// SPDX-License-Identifier: GPL-2.0
/* dplane.c - bfddp control-plane socket: framing, handlers, lifecycle.
 *
 * bfdd connects here and drives session lifecycle; we report state
 * changes back. All bfddp fields are network byte order.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <endian.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <time.h>

#include "bfd_shared.h"
#include "bfddp.h"
#include "util.h"
#include "log.h"
#include "session.h"
#include "dplane.h"
#include "ktx.h"
#include "fsm.h"

static int dp_listen = -1, dp_conn = -1;

/* Hand the loop the current pair so it can poll them instead of
 * calling accept() and recv() blind every pass. Asked for fresh each
 * time rather than cached: dp_conn is replaced on reconnect and
 * closed on drop, and a cached fd would outlive both. */
void dp_fds(int *listen_fd, int *conn_fd)
{
	*listen_fd = dp_listen;
	*conn_fd   = dp_conn;
}
static uint8_t dp_buf[4096];
static size_t dp_have;
uint64_t dp_hold_us;              /* --dp-hold: keep sessions
                                          * across bfdd restarts */
uint64_t dp_reconcile_us;         /* sweep deadline after reconnect */
#define DP_RECONCILE_US (10ull * 1000000)

/* Translate the peer's last received wire flags into the RBIT_*
 * encoding bfdd expects in bfddp_state_change.remote_flags. The two
 * use different bit positions and only Demand happens to coincide,
 * so shipping the raw wire byte mislabels the peer's bits.
 */
static uint32_t rflags_from_wire(uint8_t wire)
{
	uint32_t r = 0;

	if (wire & BFD_F_CPI)
		r |= RBIT_CPI;
	if (wire & BFD_F_DEMAND)
		r |= RBIT_DEMAND;
	if (wire & BFD_F_MP)
		r |= RBIT_MP;

	return r;
}

/* ---------- dplane socket: outbound ---------- */

static void dp_sessions_teardown(const char *why)
{
	int n = 0;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used) {
			fsm_announce_down(&sessions[i]);
			ktx_clear(&sessions[i]);
			memset(&sessions[i], 0, sizeof(sessions[i]));
			n++;
		}
	if (n)
		log_info("dplane: %s - tore down %d session(s)\n", why, n);
}

void sess_teardown_one(struct session *s, const char *why)
{
	log_info("dplane: lid=%u %s - torn down\n", s->lid, why);
	fsm_announce_down(s);
	ktx_clear(s);
	memset(s, 0, sizeof(*s));
}

/* Connection lost: with --dp-hold, keep the wire sessions alive and
 * mark them orphaned (graceful restart); otherwise the historical
 * drop-and-recreate. Reconciliation happens after reconnect. */
static void dp_sessions_orphan(const char *why)
{
	if (!dp_hold_us) {
		dp_sessions_teardown(why);
		return;
	}
	uint64_t t = now_us();
	int n = 0;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && !sessions[i].orphaned) {
			sessions[i].orphaned = 1;
			sessions[i].orphan_deadline_us = t + dp_hold_us;
			n++;
		}
	if (n)
		log_info("dplane: %s - holding %d session(s) up to %llus\n",
		       why, n, (unsigned long long)(dp_hold_us / 1000000));
}

/* Outbound queue.
 *
 * dp_conn is non-blocking, so a full socket buffer surfaces as EAGAIN.
 * That is usually transient - a counters sweep at 64 sessions arrives
 * faster than a busy bfdd reads it - so it must not tear the connection
 * down. Waiting for room is not an option either: dp_notify_state runs
 * inside the per-session tick, which paces transmit and detect timing.
 *
 * Queueing everything keeps ordering correct and handles partial writes
 * for free. Only overflow drops the connection, which means bfdd really
 * has stopped reading - the case dp_hold covers.
 *
 * 64KB is about fifteen full counter sweeps at 64 sessions.
 */
static char dp_out[65536];
static size_t dp_out_len;

/* Everything a connection carried, forgotten in one place.
 *
 * Both buffers belong to the byte stream that is going away. Input is
 * obvious; output is the half that was missed, because a message queued
 * for the old client is not a message for the new one, and after a partial
 * write what is left is the tail of a frame the new client never saw the
 * head of. It would then read a message boundary in the middle of one.
 */
static void dp_conn_reset(void)
{
	dp_have = 0;
	dp_out_len = 0;
}

static void dp_drop_conn(const char *why)
{
	close(dp_conn);
	dp_conn = -1;
	dp_conn_reset();
	dp_sessions_orphan(why);
}

void dp_flush(void)
{
	if (dp_conn < 0)
		return;

	while (dp_out_len) {
		ssize_t n = send(dp_conn, dp_out, dp_out_len, MSG_NOSIGNAL);

		if (n > 0) {
			dp_out_len -= (size_t)n;
			memmove(dp_out, dp_out + n, dp_out_len);
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return;   /* still backed up; retry next pass */
		log_err("dplane: send failed (%s), dropping connection\n",
		       n < 0 ? strerror(errno) : "zero-length write");
		dp_drop_conn("send failure");
		return;
	}
}

static void dp_send(const void *msg, size_t len)
{
	if (dp_conn < 0)
		return;
	if (len > sizeof(dp_out) - dp_out_len) {
		log_err("dplane: output queue full (%zu bytes pending), "
		       "dropping connection\n", dp_out_len);
		dp_drop_conn("output queue overflow");
		return;
	}
	memcpy(dp_out + dp_out_len, msg, len);
	dp_out_len += len;
	dp_flush();
}

void dp_notify_state(struct session *s)
{
	struct {
		struct bfddp_message_header h;
		struct bfddp_state_change   sc;
	} __attribute__((packed)) m = {0};

	m.h.version = 1;
	m.h.type    = htons(BFD_STATE_CHANGE);
	m.h.id      = 0;                      /* async */
	m.h.length  = htons(sizeof(m));
	m.sc.lid    = htonl(s->lid);
	m.sc.rid    = htonl(s->rdisc);
	m.sc.remote_flags = htonl(rflags_from_wire(s->r_flags));
	m.sc.desired_tx   = htonl(s->r_min_tx);
	m.sc.required_rx  = htonl(s->r_min_rx);
	m.sc.required_echo_rx = htonl(s->r_min_echo);
	m.sc.state  = s->state;
	m.sc.diagnostics = s->diag;
	m.sc.detection_multiplier = s->r_mult;
	dp_send(&m, sizeof(m));
}


/* ---------- dplane socket: inbound handlers ---------- */
static void dp_handle_add(const struct bfddp_message_header *h,
			  const struct bfddp_session_msg *sm, uint64_t t,
			  size_t plen)
{
	uint32_t flags = ntohl(sm->flags);
	uint32_t lid   = ntohl(sm->lid);

	struct session *s = sess_by_lid(lid);
	int fresh = 0, adopted = 0;
	if (s)
		s->orphaned = 0;   /* any bfdd message naming this lid proves
		                    * it survived the reconnect; unmark, or the
		                    * reconcile sweep tears down a live session
		                    * (bfdd can reconnect with stable lids) */
	if (!s) {
		struct session *stale = sess_by_addr_pair_local(sm);
		if (stale && dp_hold_us && stale->state == ST_UP) {
			/* Graceful restart: bfdd re-registered this addr
			 * pair under a new lid. Adopt the live session in
			 * place; wire_disc, FSM state, kernel maps and
			 * counters all survive. */
			log_info("dplane: ADD lid=%u adopts live session (old lid=%u)\n",
			       lid, stale->lid);
			s = stale;
			s->orphaned = 0;
			adopted = 1;
		} else if (stale) {
			log_info("dplane: ADD lid=%u replaces stale lid=%u\n",
			       lid, stale->lid);
			ktx_clear(stale);
			memset(stale, 0, sizeof(*stale));
		}
	}
	if (!s) {
		s = sess_alloc();
		if (!s) {
			log_err("dplane: session table full\n");
			return;
		}
		fresh = 1;
	}

	s->lid         = lid;
	if (fresh || !s->wire_disc)
		s->wire_disc = lid;   /* adopted sessions keep their wire
		                       * discriminator (RFC 5880: constant
		                       * while Up) */
	/* An UPDATE for an existing lid may move the address pair. The old
	 * pair's tx_config and bfd_sessions entries would otherwise stay
	 * behind with enable=1 and keep being answered from the fast path. */
	struct bfd_addr old_peer = s->peer, old_local = s->local;

	sm_addrs(sm, &s->local, &s->peer, &s->family);
	if (!fresh && (memcmp(&old_peer, &s->peer, sizeof(old_peer)) ||
		       memcmp(&old_local, &s->local, sizeof(old_local)))) {
		log_info("dplane: ADD lid=%u moved address pair, clearing the old\n",
		       lid);
		ktx_clear_key(&old_peer, &old_local, s->wire_disc);
		echo_peer_refresh(&old_peer, s);
		/* echo_disc mapped the discriminator to the OLD key, so let
		 * echo_tx_maybe re-insert it under the new one. */
		s->echo_disc_done = 0;
	}
	uint32_t old_tx = s->min_tx_us, old_rx = s->min_rx_us;
	s->min_tx_us   = ntohl(sm->min_tx);
	s->min_rx_us   = ntohl(sm->min_rx);
	s->detect_mult = sm->detect_mult;
	s->passive     = !!(flags & SESSION_PASSIVE);
	s->admin_down  = !!(flags & SESSION_SHUTDOWN);
	s->echo_on     = !!(flags & SESSION_ECHO);
	s->echo_tx_us  = (flags & SESSION_ECHO) ? ntohl(sm->min_echo_tx) : 0;
	s->min_echo_rx_us = (flags & SESSION_ECHO)
				    ? ntohl(sm->min_echo_rx) : 0;
	s->min_ttl     = sm->ttl ? sm->ttl : 255;
	s->is_mhop     = !!(flags & SESSION_MULTIHOP);
	s->demand      = !!(flags & SESSION_DEMAND);

	/* Authentication (RFC 5880 s6.7). bfdd sends the key itself,
	 * because a data plane that transmits is the thing that has to
	 * authenticate.
	 *
	 * A key that does not fit the digest leaves the session
	 * unauthenticated rather than half-configured: the alternative is
	 * a session that believes it is authenticating and fails every
	 * packet, which reads exactly like a mismatched key on the peer.
	 * The sequence number starts somewhere unpredictable, which
	 * s6.7.3 asks for and which costs nothing here.
	 */
	{
		int authed = !!(flags & SESSION_AUTH);

		/* The flag says whether the session authenticates at all.
		 * The keys arrive separately, so it clearing is how the
		 * control plane withdraws them: holding on to them would
		 * keep authenticating a session no longer meant to. */
		if (!authed && s->auth_present) {
			memset(s->auth_keys, 0, sizeof(s->auth_keys));
			s->auth_nkeys = 0;
		}
		if (authed != s->auth_present) {
			s->auth_present = (uint8_t)authed;
			s->auth_tx_seq = (uint32_t)random();
			s->auth_rx_seq = 0;
			s->auth_rx_seen = 0;
			s->auth_seeded = 0;
		}
		session_auth_evaluate(s, (int64_t)time(NULL));
	}

	ktx_update_mhop_flag();

	/* The fast path is attached to one interface. A single-hop session
	 * bfdd placed on a different one still works, but entirely in
	 * userspace: no RX-clocked TX, no kernel detection sweep, and none
	 * of the XDP validation. Every measured result in this project is
	 * about the fast path, so a session quietly off it invalidates any
	 * claim made about it - say so once.
	 *
	 * Multihop is exempt: a routed session can ingress anywhere, so the
	 * interface bfdd names for it does not mean what it means here.
	 */
	uint32_t sif = ntohl(sm->ifindex);

	/* Kept on the session because echo TX needs it: a raw L2 send has
	 * to name the egress interface itself, and one global taken from
	 * --kernel-tx put every session's echo on that one link. */
	if (sif != s->ifindex) {
		s->ifindex = sif;
		s->echo_mac_valid = 0;
	}

	/* Follow the sessions: bfdd places them by routing, not by where
	 * --kernel-tx pointed. Attach the same loaded program to this
	 * interface too rather than letting the session fall off the
	 * fast path. Multihop is excluded because a routed session can
	 * ingress anywhere, so its ADD ifindex does not name the one
	 * interface that would need covering. */
	if (use_ktx && !s->is_mhop && sif && !ktx_covers((int)sif)) {
		char ifn[sizeof(sm->ifname) + 1];

		/* bfddp's ifname is a fixed field and need not be
		 * terminated; the warning below uses %.*s for the same
		 * reason. */
		snprintf(ifn, sizeof(ifn), "%.*s",
			 (int)sizeof(sm->ifname), sm->ifname);
		ktx_attach_if((int)sif, ifn);
	}
	s->ktx_uncovered = (use_ktx && !s->is_mhop && sif &&
			    !ktx_covers((int)sif));
	if (s->ktx_uncovered && !s->iface_warned) {
		s->iface_warned = 1;
		log_info("dplane: lid=%u is on %.*s (ifindex %u) and could "
		       "not be attached - this session runs in userspace "
		       "only\n",
		       s->lid, (int)sizeof(sm->ifname), sm->ifname, sif);
	}
	/* echo policy: track peers of echo-active sessions so the reflector
	 * returns only their echoes, not arbitrary 3785 traffic. The map is
	 * keyed on the shared 16-byte address, so both families share it. */
	/* Not a bare update/delete on this session's say-so: the entry is
	 * shared with every other session that has the same peer. */
	echo_peer_refresh(&s->peer, NULL);
	if (!fresh && s->state == ST_UP &&
	    (s->min_tx_us != old_tx || s->min_rx_us != old_rx)) {
		/* RFC 5880 s6.8.3: parameter change while Up requires a
		 * Poll sequence. An increased min_tx must not slow actual
		 * TX until the poll terminates; a decrease applies now. */
		if (s->min_tx_us < s->applied_tx_us || !s->applied_tx_us)
			s->applied_tx_us = s->min_tx_us;
		fsm_start_poll(s, t);
	} else if (!s->polling) {
		/* Not while a Poll is outstanding. A repeated ADD carrying
		 * the values the previous one already applied compares equal
		 * here, so it lands in this branch, and assigning the new
		 * min_tx would slow transmission to a rate the peer has not
		 * accepted yet. s6.8.3 holds the old interval until the poll
		 * terminates, and it is fsm_rx and ktx_poll_map that end it
		 * on the peer's Final. */
		s->applied_tx_us = s->min_tx_us;
	}
	if (fresh) {
		s->state = s->admin_down ? ST_ADMINDOWN : ST_DOWN;
		s->diag  = 0;
		s->pushed_valid = 0;
		s->next_tx_us = t;
	}

	if (!fresh && !s->admin_down && s->state == ST_ADMINDOWN) {
		/* SHUTDOWN flag cleared on an existing session: leave
		 * AdminDown and restart the FSM. Entry into AdminDown is
		 * in fsm_tx; without this, the exit never happens. */
		state_transition(s, ST_DOWN, 0, now_us(),
				 "admin shutdown cleared");
		s->next_tx_us = now_us();
	}

	char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
	if (s->family == AF_INET6) {
		inet_ntop(AF_INET6, s->local.b, a, sizeof(a));
		inet_ntop(AF_INET6, s->peer.b, b, sizeof(b));
	} else {
		inet_ntop(AF_INET, &s->local.b[12], a, sizeof(a));
		inet_ntop(AF_INET, &s->peer.b[12], b, sizeof(b));
	}
	log_debug("dplane: %s session lid=%u %s -> %s tx=%uus rx=%uus mult=%u%s%s\n",
	       fresh ? "ADD" : "UPDATE", lid, a, b,
	       s->min_tx_us, s->min_rx_us, s->detect_mult,
	       s->passive ? " passive" : "",
	       s->admin_down ? " shutdown" : "");
	if (adopted)
		dp_notify_state(s);
	(void)h;
}

static void dp_handle_delete(const struct bfddp_session_msg *sm)
{
	struct session *s = sess_by_lid(ntohl(sm->lid));
	if (!s)
		return;
	log_info("dplane: DELETE session lid=%u\n", s->lid);
	fsm_announce_down(s);
	ktx_clear(s);
	memset(s, 0, sizeof(*s));
}

static void dp_handle_echo_req(const struct bfddp_message_header *h,
			       const struct bfddp_echo *e)
{
	struct {
		struct bfddp_message_header h;
		struct bfddp_echo           e;
	} __attribute__((packed)) m = {0};

	m.h.version = 1;
	m.h.type    = htons(ECHO_REPLY);
	m.h.id      = h->id;
	m.h.length  = htons(sizeof(m));
	m.e.bfdd_time = e->bfdd_time;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	m.e.dp_time = htobe64((uint64_t)ts.tv_sec * 1000000ull +
			      ts.tv_nsec / 1000);
	dp_send(&m, sizeof(m));
}

static void dp_handle_counters_req(const struct bfddp_message_header *h,
				   const uint32_t *lid_be)
{
	struct {
		struct bfddp_message_header h;
		struct bfddp_counters       c;
	} __attribute__((packed)) m = {0};

	uint32_t lid = ntohl(*lid_be);
	struct session *s = sess_by_lid(lid);

	m.h.version = 1;
	m.h.type    = htons(BFD_SESSION_COUNTERS);
	m.h.id      = h->id;
	m.h.length  = htons(sizeof(m));
	m.c.lid     = htonl(lid);
	if (s) {
		uint64_t krx, ktx;

		ktx_session_counters(s, &krx, &ktx);

		/* Both halves of each direction: establishment runs in
		 * userspace and the steady state in the kernel, so reporting
		 * one of them understates every session.
		 *
		 * The kernel byte count is estimated at the 24-byte minimum -
		 * session_state has no byte counter - so a peer that pads its
		 * control packets is undercounted on bytes while the packet
		 * count stays exact. Our own transmissions really are 24
		 * bytes, so the output side is exact.
		 */
		uint64_t rx = s->rx_pkts + krx;
		uint64_t rx_bytes = s->rx_bytes + krx * BFD_MIN_LEN;
		uint64_t tx = s->tx_pkts + ktx;

		m.c.control_input_bytes    = htobe64(rx_bytes);
		m.c.control_input_packets  = htobe64(rx);
		m.c.control_output_bytes   = htobe64(tx * BFD_MIN_LEN);
		m.c.control_output_packets = htobe64(tx);

		/* The originator's numbers only. Frames the kernel reflector
		 * bounces on a peer's behalf are counted globally and cannot
		 * be attributed to a session: echo_peers is keyed on the peer
		 * address alone, so the reflector never learns which session
		 * an arriving echo belongs to. A peer that echoes at us while
		 * we do not echo back reads zero here. */
		m.c.echo_input_bytes    = htobe64(s->echo_rx_pkts * BFD_MIN_LEN);
		m.c.echo_input_packets  = htobe64(s->echo_rx_pkts);
		m.c.echo_output_bytes   = htobe64(s->echo_tx_pkts * BFD_MIN_LEN);
		m.c.echo_output_packets = htobe64(s->echo_tx_pkts);
	}
	dp_send(&m, sizeof(m));
}

/* Take the session's authentication keys.
 *
 * Every key the chain holds arrives, with the periods that say when each
 * may be used, and choosing between them is this side's job. A key chain
 * rolls over on a clock, so a control plane that named the key of the
 * moment would have to keep telling us, which is the traffic that
 * delegating the session was meant to avoid.
 */
static void dp_session_auth(const struct bfddp_session_auth *sa, size_t plen)
{
	uint32_t lid = ntohl(sa->lid);
	uint16_t count = ntohs(sa->key_count);
	struct session *s = sess_by_lid(lid);
	unsigned i, kept = 0;

	if (!s)
		return;

	/* The message is only as long as the keys it carries. */
	if (count > BFDDP_AUTH_KEY_COUNT_MAX ||
	    plen < BFDDP_SESSION_AUTH_MIN + (size_t)count * sizeof(sa->keys[0])) {
		log_err("dplane: lid=%u malformed authentication message, %u keys in %zu bytes\n",
			lid, count, plen);
		return;
	}

	memset(s->auth_keys, 0, sizeof(s->auth_keys));

	for (i = 0; i < count; i++) {
		const struct bfddp_auth_key *k = &sa->keys[i];
		struct auth_key *dst = &s->auth_keys[kept];
		uint8_t kl = k->key_len;

		/* A key too long for the digest is dropped rather than
		 * truncated: a truncated key authenticates nothing and
		 * fails every packet, which reads like a mismatch on the
		 * peer. */
		if (kl == 0 || kl > sizeof(dst->kpad)) {
			log_err("dplane: lid=%u key id %u has an unusable length %u, ignored\n",
				lid, k->key_id, kl);
			continue;
		}

		dst->type = k->type;
		dst->key_id = k->key_id;
		dst->keylen = kl;
		memcpy(dst->kpad, k->key, kl);
		dst->send_start = (int64_t)be64toh((uint64_t)k->send.start);
		dst->send_end = (int64_t)be64toh((uint64_t)k->send.end);
		dst->accept_start = (int64_t)be64toh((uint64_t)k->accept.start);
		dst->accept_end = (int64_t)be64toh((uint64_t)k->accept.end);
		kept++;
	}

	s->auth_nkeys = (uint8_t)kept;
	if (session_auth_evaluate(s, (int64_t)time(NULL)))
		ktx_mirror(s);
}

static void dp_process(const uint8_t *buf, size_t len)
{
	const struct bfddp_message_header *h = (const void *)buf;
	uint16_t type = ntohs(h->type);
	const uint8_t *payload = buf + sizeof(*h);
	size_t plen = len - sizeof(*h);
	uint64_t t = now_us();

	switch (type) {
	case DP_SESSION_AUTH:
		if (plen >= BFDDP_SESSION_AUTH_MIN)
			dp_session_auth((const void *)payload, plen);
		break;
	case DP_ADD_SESSION:
		if (plen >= BFDDP_SESSION_MSG_MIN)
			dp_handle_add(h, (const void *)payload, t, plen);
		break;
	case DP_DELETE_SESSION:
		if (plen >= BFDDP_SESSION_MSG_MIN)
			dp_handle_delete((const void *)payload);
		break;
	case ECHO_REQUEST:
		if (plen >= sizeof(struct bfddp_echo))
			dp_handle_echo_req(h, (const void *)payload);
		break;
	case ECHO_REPLY:
		break;   /* our own probes, nothing to do in v0 */
	case DP_REQUEST_SESSION_COUNTERS:
		if (plen >= sizeof(uint32_t))
			dp_handle_counters_req(h, (const void *)payload);
		break;
	default:
		log_err("dplane: unhandled message type %u\n", type);
	}
}

/* The one read. A fuzz build replaces it so dp_read can be driven from a
 * buffer with no socket at all: the parser is the thing under test, and
 * owning a connection lifecycle per iteration is where a socket-based
 * harness spends its time going wrong. Production keeps recv(2). */
ssize_t (*dp_recv_hook)(int fd, void *buf, size_t len) = NULL;

/* Companion to the hook: dp_conn is static and dp_read returns at once
 * when it is negative, so a buffer-driven test needs a way past that
 * guard without a real connection. Never called in production. */
void dp_set_conn_for_test(int fd)
{
	dp_conn = fd;
	dp_have = 0;
}

void dp_read(void)
{
	if (dp_conn < 0)
		return;
	ssize_t n = dp_recv_hook
			    ? dp_recv_hook(dp_conn, dp_buf + dp_have,
					   sizeof(dp_buf) - dp_have)
			    : recv(dp_conn, dp_buf + dp_have,
				   sizeof(dp_buf) - dp_have, 0);
	if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
		log_info("dplane: bfdd disconnected\n");
		dp_drop_conn("bfdd disconnected");
		return;
	}
	if (n < 0)
		return;
	dp_have += n;

	/* Frame: header.length = total message size including header. */
	size_t off = 0;
	while (off + sizeof(struct bfddp_message_header) <= dp_have) {
		const struct bfddp_message_header *h =
			(const void *)(dp_buf + off);
		uint16_t mlen = ntohs(h->length);
		if (mlen < sizeof(*h) || mlen > sizeof(dp_buf)) {
			/* Framing lost on a byte stream: resetting the buffer
			 * but keeping the connection would resync onto arbitrary
			 * mid-stream bytes. Drop the connection instead and let
			 * bfdd reconnect from a clean boundary. With --dp-hold
			 * the sessions survive the reconnect. */
			log_err("dplane: bad frame length %u, dropping connection\n",
			       mlen);
			dp_drop_conn("bad frame length");
			return;
		}
		if (dp_have - off < mlen)
			break;
		dp_process(dp_buf + off, mlen);
		off += mlen;
		/* dp_process can reply, and a reply on a full output queue
		 * drops the connection and zeroes dp_have. Both are size_t,
		 * so dp_have - off would underflow and off would walk past
		 * the buffer. Nothing after a drop is meaningful anyway. */
		if (dp_conn < 0)
			return;
	}
	if (off) {
		memmove(dp_buf, dp_buf + off, dp_have - off);
		dp_have -= off;
	}
}

/* Which uid may drive this engine.
 *
 * -1 means "whoever runs the engine", which is the safe default: a UNIX
 * socket is then created 0600 and only that account can open it. Naming a
 * peer with --dp-peer widens it to that one account, chowns the socket and
 * opens it to the group, which is what a deployment running bfdd as `frr`
 * while the engine runs as root needs.
 *
 * root is always allowed. It can read the socket whatever the mode says,
 * so refusing it would be a check that only looks like one.
 */
static uid_t dp_peer_uid = (uid_t)-1;

void dp_set_peer_uid(uid_t uid)
{
	dp_peer_uid = uid;
}

/* Whether a freshly accepted client may replace the connection we have.
 *
 * Called before anything about the current connection is touched. The old
 * order closed dp_conn and orphaned every session first and looked at the
 * newcomer afterwards, so any local process could tear the control plane
 * down by connecting once - and with the default hold of zero that is a
 * teardown of all 64 sessions, not a pause.
 *
 * SO_PEERCRED is a UNIX socket facility. On TCP there is nothing to ask:
 * the listener is bound to loopback, so the check is that the peer really
 * is loopback and the rest is the operator's to control. That is weaker
 * and the log says so at startup.
 */
static int dp_peer_allowed(int fd)
{
	/* Zeroed, so the family this branches on is AF_UNSPEC rather than
	 * whatever was on the stack if either query below ever fails. The
	 * returns already cover that, but scan-build does not model
	 * getsockname as an initialiser and reads ss.ss_family as garbage,
	 * and this decides whether a peer may take over the control
	 * connection - not a place to answer a checker with a comment. */
	struct sockaddr_storage ss = {0};
	socklen_t sslen = sizeof(ss);

	/* Ask the socket what it is rather than inferring it from a failed
	 * getsockopt. SO_PEERCRED on a TCP socket does not fail: it returns
	 * success with uid (uid_t)-1 and pid 0, so reading the error is how
	 * you refuse every TCP client while believing you are checking a
	 * credential. */
	if (getsockname(fd, (void *)&ss, &sslen) != 0)
		return 0;

	if (ss.ss_family == AF_UNIX) {
		struct ucred cr;
		socklen_t crlen = sizeof(cr);

		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &crlen) != 0)
			return 0;
		if (cr.uid == 0)
			return 1;
		if (dp_peer_uid != (uid_t)-1)
			return cr.uid == dp_peer_uid;
		return cr.uid == geteuid();
	}

	/* TCP. The listener is bound to loopback, so this only confirms what
	 * the bind already guarantees; there is no credential to ask for. */
	sslen = sizeof(ss);
	if (getpeername(fd, (void *)&ss, &sslen) != 0)
		return 0;
	if (ss.ss_family == AF_INET) {
		const struct sockaddr_in *si = (const void *)&ss;

		return (ntohl(si->sin_addr.s_addr) >> 24) == 127;
	}

	return 0;
}

void dp_accept(void)
{
	if (dp_listen < 0)
		return;
	int c = accept(dp_listen, NULL, NULL);
	if (c < 0)
		return;
	if (!dp_peer_allowed(c)) {
		log_err("dplane: refusing a control connection from an unauthorized peer\n");
		close(c);
		return;
	}
	if (dp_conn >= 0) {
		log_info("dplane: replacing existing bfdd connection\n");
		close(dp_conn);
		dp_conn_reset();
		dp_sessions_orphan("connection replaced");
	}
	fcntl(c, F_SETFL, O_NONBLOCK);
	dp_conn = c;
	log_info("dplane: bfdd connected\n");
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].orphaned) {
			dp_reconcile_us = now_us() + DP_RECONCILE_US;
			log_info("dplane: reconcile sweep armed (%llus)\n",
			       (unsigned long long)(DP_RECONCILE_US / 1000000));
			break;
		}
}

int dp_listen_init(const char *arg)
{
	/* "<path>" = unix socket; "<port number>" = TCP on 127.0.0.1.
	 * Note: FRR <=10.5 bfdd unixc: client mode passes an oversized
	 * addrlen to connect(2), which AF_UNIX rejects (EINVAL) - use
	 * TCP with those versions. */
	if (arg[0] == '/') {
		dp_listen = socket(AF_UNIX, SOCK_STREAM, 0);
		if (dp_listen < 0) {
			perror("dplane socket (unix)");
			return -1;
		}
		struct sockaddr_un su = { .sun_family = AF_UNIX };
		strncpy(su.sun_path, arg, sizeof(su.sun_path) - 1);
		unlink(arg);
		if (bind(dp_listen, (void *)&su, sizeof(su)) ||
		    listen(dp_listen, 1)) {
			perror("dplane listen (unix)");
			return -1;
		}
		/* 0600 unless a peer was named, in which case the socket
		 * belongs to that account and its group may open it. The
		 * old 0666 let any local process connect, and dp_accept
		 * displaced the live connection before looking at who had. */
		if (dp_peer_uid != (uid_t)-1) {
			if (chown(arg, dp_peer_uid, (gid_t)-1))
				perror("dplane chown (unix)");
			chmod(arg, 0660);
		} else {
			chmod(arg, 0600);
		}
		log_info("dplane: listening on %s (bfdd: unixc:%s)\n",
		       arg, arg);
	} else {
		/* strtol, not atoi, which reports nothing: `--dplane abc`
		 * bound port 0 and announced it, and bfdd then connects to a
		 * port nobody is listening on. Every other numeric option
		 * here is range checked; this one was the exception. */
		char *end;
		long parsed = strtol(arg, &end, 10);
		int port;

		if (end == arg || *end || parsed < 1 || parsed > 65535) {
			log_err("dplane: expected a port in 1-65535 or a socket path, got '%s'\n",
				arg);
			return -1;
		}
		port = (int)parsed;
		dp_listen = socket(AF_INET, SOCK_STREAM, 0);
		if (dp_listen < 0) {
			perror("dplane socket (tcp)");
			return -1;
		}
		int one = 1;
		setsockopt(dp_listen, SOL_SOCKET, SO_REUSEADDR, &one,
			   sizeof(one));
		struct sockaddr_in si = {
			.sin_family = AF_INET,
			.sin_port = htons(port),
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		};
		if (bind(dp_listen, (void *)&si, sizeof(si)) ||
		    listen(dp_listen, 1)) {
			perror("dplane listen (tcp)");
			return -1;
		}
		log_info("dplane: listening on 127.0.0.1:%d (bfdd: ipv4c:127.0.0.1:%d)\n",
		       port, port);
		/* No peer credentials on TCP. Loopback is the whole of the
		 * access control, so any local process can drive the engine;
		 * a UNIX socket with --dp-peer is the one that authorizes. */
		log_info("dplane: TCP has no peer authorization, any local process may connect\n");
	}
	fcntl(dp_listen, F_SETFL, O_NONBLOCK);
	return 0;
}
