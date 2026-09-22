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

/* Current listener and connection fds for the poll set. Not cached, since
 * dp_conn changes on reconnect.
 */
void dp_fds(int *listen_fd, int *conn_fd)
{
	*listen_fd = dp_listen;
	*conn_fd = dp_conn;
}
static uint8_t dp_buf[4096];
static size_t dp_have;
uint64_t dp_hold_us;	  /* --dp-hold: keep sessions across bfdd restarts */
uint64_t dp_reconcile_us; /* sweep deadline after reconnect */
#define DP_RECONCILE_US (10ull * 1000000)

/* Map the peer's wire flags to the RBIT_* encoding bfdd expects in
 * remote_flags; the bit positions differ.
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

/* Connection lost: with --dp-hold, keep sessions running as orphans until bfdd
 * reconnects and reclaims them; otherwise tear them down.
 */
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
		log_info("dplane: %s - holding %d session(s) up to %llus\n", why, n,
			 (unsigned long long)(dp_hold_us / 1000000));
}

/* Outbound queue. dp_conn is non-blocking and the tick cannot wait, so writes
 * queue here and partial writes resume later. Only overflow or a send error
 * drops the connection. 64KB holds about fifteen counter sweeps at 64
 * sessions.
 */
static char dp_out[65536];
static size_t dp_out_len;

/* Forget everything the connection carried, in both directions: queued output
 * belongs to the old byte stream and may end mid-frame.
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
			return; /* still backed up; retry next pass */
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
		log_err("dplane: output queue full (%zu bytes pending), dropping connection\n",
			dp_out_len);
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
		struct bfddp_state_change sc;
	} __attribute__((packed)) m = { 0 };

	if (dp_conn < 0)
		return;

	m.h.version = 1;
	m.h.type = htons(BFD_STATE_CHANGE);
	m.h.id = 0; /* async */
	m.h.length = htons(sizeof(m));
	m.sc.lid = htonl(s->lid);
	m.sc.rid = htonl(s->rdisc);
	m.sc.remote_flags = htonl(rflags_from_wire(s->r_flags));
	m.sc.desired_tx = htonl(s->r_min_tx);
	m.sc.required_rx = htonl(s->r_min_rx);
	m.sc.required_echo_rx = htonl(s->r_min_echo);
	m.sc.state = s->state;
	m.sc.diagnostics = s->diag;
	m.sc.detection_multiplier = s->r_mult;

	/* On a full queue, defer rather than drop the connection: mark the
	 * session and re-send its current state from dp_notify_flush_pending.
	 * A flap storm collapses to one message per session.
	 */
	if (sizeof(m) > sizeof(dp_out) - dp_out_len) {
		s->notify_pending = 1;
		return;
	}
	s->notify_pending = 0;
	memcpy(dp_out + dp_out_len, &m, sizeof(m));
	dp_out_len += sizeof(m);
	dp_flush();
}

/* Re-send current state for sessions deferred while the queue was full. Called
 * after dp_flush.
 */
void dp_notify_flush_pending(void)
{
	if (dp_conn < 0)
		return;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].notify_pending)
			dp_notify_state(&sessions[i]);
}


/* ---------- dplane socket: inbound handlers ---------- */
/* Wildcard local address. bfdd sends 0.0.0.0 or :: when no local-address is
 * configured, but the fast path keys sessions on (peer, local). Resolve the
 * source the kernel would use to reach the peer; connect() on a datagram
 * socket only runs the route lookup.
 */
static int addr_unspecified(const struct bfd_addr *a, int family)
{
	if (family == AF_INET6) {
		for (int i = 0; i < 16; i++)
			if (a->b[i])
				return 0;
		return 1;
	}
	return a->b[12] == 0 && a->b[13] == 0 && a->b[14] == 0 && a->b[15] == 0;
}

static void dp_resolve_local(struct session *s)
{
	int fd = socket(s->family, SOCK_DGRAM, 0);

	if (fd < 0)
		return;
	if (s->family == AF_INET6) {
		struct sockaddr_in6 pa = { .sin6_family = AF_INET6, .sin6_port = htons(PORT_CTRL) };
		struct sockaddr_in6 la = { 0 };
		socklen_t ll = sizeof(la);

		memcpy(&pa.sin6_addr, s->peer.b, 16);
		if (!connect(fd, (void *)&pa, sizeof(pa)) && !getsockname(fd, (void *)&la, &ll))
			key_set_v6(&s->local, &la.sin6_addr);
	} else {
		struct sockaddr_in pa = { .sin_family = AF_INET, .sin_port = htons(PORT_CTRL) };
		struct sockaddr_in la = { 0 };
		socklen_t ll = sizeof(la);

		memcpy(&pa.sin_addr.s_addr, &s->peer.b[12], 4);
		if (!connect(fd, (void *)&pa, sizeof(pa)) && !getsockname(fd, (void *)&la, &ll))
			key_set_v4(&s->local, la.sin_addr.s_addr);
	}
	close(fd);
}

/* Re-resolve a wildcard session's source while it is not Up, at most once a
 * second. If the route moved, drop the old key so ktx_mirror pushes under the
 * new one.
 */
void dp_reresolve_wildcard(struct session *s, uint64_t now)
{
	struct bfd_addr old;

	if (!s->local_wildcard || s->state == ST_UP)
		return;
	if (s->last_reresolve_us && now - s->last_reresolve_us < 1000000)
		return;
	s->last_reresolve_us = now;

	old = s->local;
	dp_resolve_local(s);
	if (!addr_unspecified(&s->local, s->family) && memcmp(&old, &s->local, sizeof(old)) != 0) {
		log_info("dplane: lid=%u wildcard local moved to a new source; re-keying the fast path\n",
			 s->lid);
		ktx_clear_key(&s->peer, &old, s->wire_disc);
		echo_peer_refresh(&s->peer, s);
		s->echo_disc_done = 0;
		s->pushed_valid = 0;
	}
}

static void dp_handle_add(const struct bfddp_message_header *h, const struct bfddp_session_msg *sm,
			  uint64_t t, size_t plen)
{
	uint32_t flags = ntohl(sm->flags);
	uint32_t lid = ntohl(sm->lid);

	struct session *s = sess_by_lid(lid);
	int fresh = 0, adopted = 0;

	if (s)
		/* any bfdd message naming this lid proves it survived the
		 * reconnect; unmark, or the reconcile sweep tears down a live
		 * session (bfdd can reconnect with stable lids)
		 */
		s->orphaned = 0;
	if (!s) {
		struct session *stale = sess_by_addr_pair_local(sm);

		if (stale && dp_hold_us && stale->state == ST_UP) {
			/* Graceful restart: bfdd re-registered this addr
			 * pair under a new lid. Adopt the live session in
			 * place; wire_disc, FSM state, kernel maps and
			 * counters all survive.
			 */
			log_info("dplane: ADD lid=%u adopts live session (old lid=%u)\n", lid,
				 stale->lid);
			s = stale;
			s->orphaned = 0;
			adopted = 1;
		} else if (stale) {
			log_info("dplane: ADD lid=%u replaces stale lid=%u\n", lid, stale->lid);
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

	s->lid = lid;
	if (fresh || !s->wire_disc)
		/* adopted sessions keep their wire discriminator (RFC 5880:
		 * constant while Up)
		 */
		s->wire_disc = lid;
	/* An UPDATE may move the address pair; clear the old pair's map
	 * entries.
	 */
	struct bfd_addr old_peer = s->peer, old_local = s->local;

	sm_addrs(sm, &s->local, &s->peer, &s->family);
	s->local_wildcard = addr_unspecified(&s->local, s->family);
	if (s->local_wildcard) {
		dp_resolve_local(s);
		if (addr_unspecified(&s->local, s->family))
			log_err("dplane: lid=%u has no local address and none could be resolved to reach its peer; the fast path cannot key it\n",
				lid);
	}
	if (!fresh && (memcmp(&old_peer, &s->peer, sizeof(old_peer)) ||
		       memcmp(&old_local, &s->local, sizeof(old_local)))) {
		log_info("dplane: ADD lid=%u moved address pair, clearing the old\n", lid);
		ktx_clear_key(&old_peer, &old_local, s->wire_disc);
		echo_peer_refresh(&old_peer, s);
		/* echo_disc mapped the discriminator to the OLD key, so let
		 * echo_tx_maybe re-insert it under the new one.
		 */
		s->echo_disc_done = 0;
	}
	uint32_t old_tx = s->min_tx_us, old_rx = s->min_rx_us;

	s->min_tx_us = ntohl(sm->min_tx);
	s->min_rx_us = ntohl(sm->min_rx);
	s->detect_mult = sm->detect_mult;
	s->passive = !!(flags & SESSION_PASSIVE);
	s->admin_down = !!(flags & SESSION_SHUTDOWN);
	s->echo_on = !!(flags & SESSION_ECHO);
	s->echo_tx_us = (flags & SESSION_ECHO) ? ntohl(sm->min_echo_tx) : 0;
	s->min_echo_rx_us = (flags & SESSION_ECHO) ? ntohl(sm->min_echo_rx) : 0;
	s->min_ttl = sm->ttl ? sm->ttl : 255;
	s->is_mhop = !!(flags & SESSION_MULTIHOP);
	s->demand = !!(flags & SESSION_DEMAND);

	/* Authentication (RFC 5880 s6.7). SESSION_AUTH says whether the
	 * session authenticates; keys arrive separately in DP_SESSION_AUTH.
	 * The TX sequence starts at a random value (s6.7.3).
	 */
	{
		int authed = !!(flags & SESSION_AUTH);

		/* A cleared flag withdraws the keys. */
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

	/* Interface handling: record the ifindex for echo TX, attach the fast
	 * path to the session's interface, and warn once if it cannot be
	 * covered. Multihop sessions are exempt, since they can ingress
	 * anywhere.
	 */
	uint32_t sif = ntohl(sm->ifindex);

	/* Echo TX sends at L2, so it needs the session's own egress interface. */
	if (sif != s->ifindex) {
		s->ifindex = sif;
		s->echo_mac_valid = 0;
	}

	/* bfdd places sessions by routing, so attach the program to this
	 * interface too.
	 */
	if (use_ktx && !s->is_mhop && sif && !ktx_covers((int)sif)) {
		char ifn[sizeof(sm->ifname) + 1];

		/* bfddp's ifname need not be NUL-terminated. */
		snprintf(ifn, sizeof(ifn), "%.*s", (int)sizeof(sm->ifname), sm->ifname);
		ktx_attach_if((int)sif, ifn);
	}
	s->ktx_uncovered = (use_ktx && !s->is_mhop && sif && !ktx_covers((int)sif));
	if (s->ktx_uncovered && !s->iface_warned) {
		s->iface_warned = 1;
		log_info("dplane: lid=%u is on %.*s (ifindex %u) and could not be attached - this session runs in userspace only\n",
			 s->lid, (int)sizeof(sm->ifname), sm->ifname, sif);
	}
	/* echo_peers holds peers of echo-active sessions, so the reflector
	 * returns only their echoes. The entry is shared by every session with
	 * that peer, so recompute it rather than update it.
	 */
	echo_peer_refresh(&s->peer, NULL);
	if (!fresh && s->state == ST_UP && (s->min_tx_us != old_tx || s->min_rx_us != old_rx)) {
		/* RFC 5880 s6.8.3: parameter change while Up requires a
		 * Poll sequence. An increased min_tx must not slow actual
		 * TX until the poll terminates; a decrease applies now.
		 */
		if (s->min_tx_us < s->applied_tx_us || !s->applied_tx_us)
			s->applied_tx_us = s->min_tx_us;
		fsm_start_poll(s, t);
	} else if (!s->polling) {
		/* Not while a Poll is outstanding: s6.8.3 keeps the old
		 * interval until the peer's Final, which fsm_rx or
		 * ktx_poll_map handles.
		 */
		s->applied_tx_us = s->min_tx_us;
	}
	if (fresh) {
		s->state = s->admin_down ? ST_ADMINDOWN : ST_DOWN;
		s->diag = 0;
		s->pushed_valid = 0;
		s->next_tx_us = t;
	}

	if (!fresh && !s->admin_down && s->state == ST_ADMINDOWN) {
		/* SHUTDOWN flag cleared on an existing session: leave
		 * AdminDown and restart the FSM. Entry into AdminDown is
		 * in fsm_tx; without this, the exit never happens.
		 */
		state_transition(s, ST_DOWN, 0, now_us(), "admin shutdown cleared");
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
		  fresh ? "ADD" : "UPDATE", lid, a, b, s->min_tx_us, s->min_rx_us, s->detect_mult,
		  s->passive ? " passive" : "", s->admin_down ? " shutdown" : "");
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

static void dp_handle_echo_req(const struct bfddp_message_header *h, const struct bfddp_echo *e)
{
	struct {
		struct bfddp_message_header h;
		struct bfddp_echo e;
	} __attribute__((packed)) m = { 0 };

	m.h.version = 1;
	m.h.type = htons(ECHO_REPLY);
	m.h.id = h->id;
	m.h.length = htons(sizeof(m));
	m.e.bfdd_time = e->bfdd_time;
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	m.e.dp_time = htobe64((uint64_t)ts.tv_sec * 1000000ull + ts.tv_nsec / 1000);
	dp_send(&m, sizeof(m));
}

static void dp_handle_counters_req(const struct bfddp_message_header *h, const uint32_t *lid_be)
{
	struct {
		struct bfddp_message_header h;
		struct bfddp_counters c;
	} __attribute__((packed)) m = { 0 };

	uint32_t lid = ntohl(*lid_be);
	struct session *s = sess_by_lid(lid);

	m.h.version = 1;
	m.h.type = htons(BFD_SESSION_COUNTERS);
	m.h.id = h->id;
	m.h.length = htons(sizeof(m));
	m.c.lid = htonl(lid);
	if (s) {
		uint64_t krx, ktx;

		ktx_session_counters(s, &krx, &ktx);

		/* Sum userspace (establishment) and kernel (steady state)
		 * counts. Kernel bytes are estimated at 24 per packet, so a
		 * peer that pads is undercounted on bytes only.
		 */
		uint64_t rx = s->rx_pkts + krx;
		uint64_t rx_bytes = s->rx_bytes + krx * BFD_MIN_LEN;
		uint64_t tx = s->tx_pkts + ktx;

		m.c.control_input_bytes = htobe64(rx_bytes);
		m.c.control_input_packets = htobe64(rx);
		m.c.control_output_bytes = htobe64(tx * BFD_MIN_LEN);
		m.c.control_output_packets = htobe64(tx);

		/* Our own echoes only. Echoes the kernel reflects for a peer
		 * cannot be attributed to a session, since echo_peers is keyed
		 * on address alone.
		 */
		m.c.echo_input_bytes = htobe64(s->echo_rx_pkts * BFD_MIN_LEN);
		m.c.echo_input_packets = htobe64(s->echo_rx_pkts);
		m.c.echo_output_bytes = htobe64(s->echo_tx_pkts * BFD_MIN_LEN);
		m.c.echo_output_packets = htobe64(s->echo_tx_pkts);
	}
	dp_send(&m, sizeof(m));
}

/* Take the session's authentication keys. The whole chain arrives with its
 * send and accept periods; key selection follows the clock from here.
 */
static void dp_session_auth(const struct bfddp_session_auth *sa, size_t plen)
{
	uint32_t lid = ntohl(sa->lid);
	uint16_t count = ntohs(sa->key_count);
	struct session *s = sess_by_lid(lid);
	unsigned int i, kept = 0;

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

		/* Drop, not truncate, a key too long for the digest: a
		 * truncated key fails every packet.
		 */
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
		break; /* unsolicited: we send no ECHO_REQUEST */
	case DP_REQUEST_SESSION_COUNTERS:
		if (plen >= sizeof(uint32_t))
			dp_handle_counters_req(h, (const void *)payload);
		break;
	default:
		log_err("dplane: unhandled message type %u\n", type);
	}
}

/* Receive hook; the fuzz harness replaces it to drive dp_read from a buffer. */
ssize_t (*dp_recv_hook)(int fd, void *buf, size_t len) = NULL;

/* Test only: set dp_conn so dp_read runs without a real connection. */
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
			    ? dp_recv_hook(dp_conn, dp_buf + dp_have, sizeof(dp_buf) - dp_have)
			    : recv(dp_conn, dp_buf + dp_have, sizeof(dp_buf) - dp_have, 0);
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
		const struct bfddp_message_header *h = (const void *)(dp_buf + off);
		uint16_t mlen = ntohs(h->length);

		if (mlen < sizeof(*h) || mlen > sizeof(dp_buf)) {
			/* Framing lost: drop the connection so bfdd reconnects
			 * on a clean boundary. With --dp-hold the sessions
			 * survive.
			 */
			log_err("dplane: bad frame length %u, dropping connection\n", mlen);
			dp_drop_conn("bad frame length");
			return;
		}
		if (dp_have - off < mlen)
			break;
		dp_process(dp_buf + off, mlen);
		off += mlen;
		/* dp_process may have dropped the connection (full output
		 * queue or send error), which zeroes dp_have.
		 */
		if (dp_conn < 0)
			return;
	}
	if (off) {
		memmove(dp_buf, dp_buf + off, dp_have - off);
		dp_have -= off;
	}
}

/* uid allowed to drive the engine; -1 means the engine's own. --dp-peer names
 * bfdd's account. root is always allowed.
 */
static uid_t dp_peer_uid = (uid_t)-1;

void dp_set_peer_uid(uid_t uid)
{
	dp_peer_uid = uid;
}

/* May a freshly accepted client replace the current connection? Checked before
 * the old one is touched. UNIX sockets check SO_PEERCRED; TCP only confirms
 * the peer is loopback.
 */
static int dp_peer_allowed(int fd)
{
	/* Zeroed so scan-build sees ss_family initialised. */
	struct sockaddr_storage ss = { 0 };
	socklen_t sslen = sizeof(ss);

	/* Branch on the socket family: SO_PEERCRED succeeds on TCP too, with
	 * uid -1.
	 */
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
	 * the bind already guarantees; there is no credential to ask for.
	 */
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
	/* "<path>" is a UNIX socket, "<port>" TCP on 127.0.0.1. bfdd's unixc:
	 * mode fails with EINVAL on every release through 10.7.1 (fixed on
	 * master), so use TCP with released FRR.
	 */
	if (arg[0] == '/') {
		dp_listen = socket(AF_UNIX, SOCK_STREAM, 0);
		if (dp_listen < 0) {
			perror("dplane socket (unix)");
			return -1;
		}
		struct sockaddr_un su = { .sun_family = AF_UNIX };

		strncpy(su.sun_path, arg, sizeof(su.sun_path) - 1);
		unlink(arg);
		if (bind(dp_listen, (void *)&su, sizeof(su)) || listen(dp_listen, 1)) {
			perror("dplane listen (unix)");
			return -1;
		}
		/* 0600, or 0660 owned by the --dp-peer account. */
		if (dp_peer_uid != (uid_t)-1) {
			if (chown(arg, dp_peer_uid, (gid_t)-1))
				perror("dplane chown (unix)");
			chmod(arg, 0660);
		} else {
			chmod(arg, 0600);
		}
		log_info("dplane: listening on %s (bfdd: unixc:%s)\n", arg, arg);
	} else {
		/* strtol with a full-string check; atoi would bind port 0 for
		 * "abc".
		 */
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

		setsockopt(dp_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		struct sockaddr_in si = {
			.sin_family = AF_INET,
			.sin_port = htons(port),
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		};
		if (bind(dp_listen, (void *)&si, sizeof(si)) || listen(dp_listen, 1)) {
			perror("dplane listen (tcp)");
			return -1;
		}
		log_info("dplane: listening on 127.0.0.1:%d (bfdd: ipv4c:127.0.0.1:%d)\n", port,
			 port);
		/* TCP has no peer credentials: loopback is the only access
		 * control.
		 */
		log_info("dplane: TCP has no peer authorization, any local process may connect\n");
	}
	fcntl(dp_listen, F_SETFL, O_NONBLOCK);
	return 0;
}
