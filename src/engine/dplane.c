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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bfd_shared.h"
#include "bffdp.h"
#include "util.h"
#include "session.h"
#include "dplane.h"
#include "ktx.h"
#include "fsm.h"

static int dp_listen = -1, dp_conn = -1;
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
			ktx_clear(&sessions[i]);
			memset(&sessions[i], 0, sizeof(sessions[i]));
			n++;
		}
	if (n)
		printf("dplane: %s - tore down %d session(s)\n", why, n);
}

void sess_teardown_one(struct session *s, const char *why)
{
	printf("dplane: lid=%u %s - torn down\n", s->lid, why);
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
		printf("dplane: %s - holding %d session(s) up to %llus\n",
		       why, n, (unsigned long long)(dp_hold_us / 1000000));
}

/* Outbound queue.
 *
 * dp_conn is non-blocking (dp_accept sets O_NONBLOCK), so a full
 * socket buffer surfaces as EAGAIN rather than a block. Treating that
 * as fatal orphaned every session over what is usually transient - a
 * counters sweep at 64 sessions is a few KB arriving faster than a
 * busy bfdd reads it.
 *
 * Waiting for room is not an option either: dp_notify_state runs
 * inside the per-session tick, so even a 1ms wait per message would
 * cost tens of milliseconds in one pass, and this loop's pacing is
 * upstream of transmit and detect timing.
 *
 * Everything therefore goes through the queue, which keeps ordering
 * trivially correct and makes partial writes fall out for free. The
 * common case is still one send() per message. Tearing the connection
 * down is reserved for the queue overflowing, which means bfdd has
 * stopped reading long enough that it really is gone - the case
 * dp_hold exists to cover.
 *
 * 64KB is about fifteen full counter sweeps at 64 sessions.
 */
static char dp_out[65536];
static size_t dp_out_len;

static void dp_drop_conn(const char *why)
{
	close(dp_conn);
	dp_conn = -1;
	dp_have = 0;
	dp_out_len = 0;
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
		printf("dplane: send failed (%s), dropping connection\n",
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
		printf("dplane: output queue full (%zu bytes pending), "
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
			  const struct bfddp_session_msg *sm, uint64_t t)
{
	uint32_t flags = ntohl(sm->flags);
	uint32_t lid   = ntohl(sm->lid);

	/* Multihop is supported: bfdd sends the negotiated minimum TTL in
	 * the ADD and the XDP parser enforces it per session. Demand mode
	 * is not implemented, so it is still refused. */
	if (flags & SESSION_DEMAND) {
		printf("dplane: ADD lid=%u rejected (unsupported flags 0x%x)\n",
		       lid, flags);
		return;
	}

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
			printf("dplane: ADD lid=%u adopts live session (old lid=%u)\n",
			       lid, stale->lid);
			s = stale;
			s->orphaned = 0;
			adopted = 1;
		} else if (stale) {
			printf("dplane: ADD lid=%u replaces stale lid=%u\n",
			       lid, stale->lid);
			ktx_clear(stale);
			memset(stale, 0, sizeof(*stale));
		}
	}
	if (!s) {
		s = sess_alloc();
		if (!s) {
			printf("dplane: session table full\n");
			return;
		}
		fresh = 1;
	}

	s->lid         = lid;
	if (fresh || !s->wire_disc)
		s->wire_disc = lid;   /* adopted sessions keep their wire
		                       * discriminator (RFC 5880: constant
		                       * while Up) */
	sm_addrs(sm, &s->local, &s->peer, &s->family);
	uint32_t old_tx = s->min_tx_us, old_rx = s->min_rx_us;
	s->min_tx_us   = ntohl(sm->min_tx);
	s->min_rx_us   = ntohl(sm->min_rx);
	s->detect_mult = sm->detect_mult;
	s->passive     = !!(flags & SESSION_PASSIVE);
	s->admin_down  = !!(flags & SESSION_SHUTDOWN);
	s->echo_tx_us  = (flags & SESSION_ECHO) ? ntohl(sm->min_echo_tx) : 0;
	s->min_echo_rx_us = (flags & SESSION_ECHO)
				    ? ntohl(sm->min_echo_rx) : 0;
	s->min_ttl     = sm->ttl ? sm->ttl : 255;
	s->is_mhop     = !!(flags & SESSION_MULTIHOP);
	ktx_update_mhop_flag();
	/* echo policy: track peers of echo-active sessions so the reflector
	 * returns only their echoes, not arbitrary 3785 traffic. The map is
	 * keyed on the shared 16-byte address, so both families share it. */
	if (echo_peers_fd >= 0) {
		if (flags & SESSION_ECHO) {
			__u8 one = 1;
			bpf_map_update_elem(echo_peers_fd, &s->peer, &one, 0);
		} else {
			bpf_map_delete_elem(echo_peers_fd, &s->peer);
		}
	}
	if (!fresh && s->state == ST_UP &&
	    (s->min_tx_us != old_tx || s->min_rx_us != old_rx)) {
		/* RFC 5880 s6.8.3: parameter change while Up requires a
		 * Poll sequence. An increased min_tx must not slow actual
		 * TX until the poll terminates; a decrease applies now. */
		s->poll_seq++;
		s->polling = 1;
		if (s->min_tx_us < s->applied_tx_us || !s->applied_tx_us)
			s->applied_tx_us = s->min_tx_us;
	} else {
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
	printf("dplane: %s session lid=%u %s -> %s tx=%uus rx=%uus mult=%u%s%s\n",
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
	printf("dplane: DELETE session lid=%u\n", s->lid);
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
		uint64_t rx = 0, ktx = 0;
		if (use_ktx) {
			struct session_key k = {};
			k.peer  = s->peer;
			k.local = s->local;
			struct session_state ms;
			if (!bpf_map_lookup_elem(sess_fd, &k, &ms)) {
				rx  = ms.rx_pkts;
				ktx = ms.tx_pkts;
			}
		}
		uint64_t tx = s->tx_pkts + ktx;
		m.c.control_input_bytes    = htobe64(rx * 24);
		m.c.control_input_packets  = htobe64(rx);
		m.c.control_output_bytes   = htobe64(tx * 24);
		m.c.control_output_packets = htobe64(tx);
	}
	dp_send(&m, sizeof(m));
}

static void dp_process(const uint8_t *buf, size_t len)
{
	const struct bfddp_message_header *h = (const void *)buf;
	uint16_t type = ntohs(h->type);
	const uint8_t *payload = buf + sizeof(*h);
	size_t plen = len - sizeof(*h);
	uint64_t t = now_us();

	switch (type) {
	case DP_ADD_SESSION:
		if (plen >= sizeof(struct bfddp_session_msg))
			dp_handle_add(h, (const void *)payload, t);
		break;
	case DP_DELETE_SESSION:
		if (plen >= sizeof(struct bfddp_session_msg))
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
		printf("dplane: unhandled message type %u\n", type);
	}
}

void dp_read(void)
{
	if (dp_conn < 0)
		return;
	ssize_t n = recv(dp_conn, dp_buf + dp_have,
			 sizeof(dp_buf) - dp_have, 0);
	if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
		printf("dplane: bfdd disconnected\n");
		dp_drop_conn("bfdd disconnected");
		return;
	}
	if (n < 0)
		return;
	dp_have += n;

	/* Frame: header.length = total message size including header. */
	size_t off = 0;
	while (dp_have - off >= sizeof(struct bfddp_message_header)) {
		const struct bfddp_message_header *h =
			(const void *)(dp_buf + off);
		uint16_t mlen = ntohs(h->length);
		if (mlen < sizeof(*h) || mlen > sizeof(dp_buf)) {
			/* Framing lost on a byte stream: resetting the buffer
			 * but keeping the connection would resync onto arbitrary
			 * mid-stream bytes. Drop the connection instead and let
			 * bfdd reconnect from a clean boundary. With --dp-hold
			 * the sessions survive the reconnect. */
			printf("dplane: bad frame length %u, dropping connection\n",
			       mlen);
			dp_drop_conn("bad frame length");
			return;
		}
		if (dp_have - off < mlen)
			break;
		dp_process(dp_buf + off, mlen);
		off += mlen;
	}
	if (off) {
		memmove(dp_buf, dp_buf + off, dp_have - off);
		dp_have -= off;
	}
}

void dp_accept(void)
{
	if (dp_listen < 0)
		return;
	int c = accept(dp_listen, NULL, NULL);
	if (c < 0)
		return;
	if (dp_conn >= 0) {
		printf("dplane: replacing existing bfdd connection\n");
		close(dp_conn);
		dp_have = 0;
		dp_sessions_orphan("connection replaced");
	}
	fcntl(c, F_SETFL, O_NONBLOCK);
	dp_conn = c;
	printf("dplane: bfdd connected\n");
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].orphaned) {
			dp_reconcile_us = now_us() + DP_RECONCILE_US;
			printf("dplane: reconcile sweep armed (%llus)\n",
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
		struct sockaddr_un su = { .sun_family = AF_UNIX };
		strncpy(su.sun_path, arg, sizeof(su.sun_path) - 1);
		unlink(arg);
		if (bind(dp_listen, (void *)&su, sizeof(su)) ||
		    listen(dp_listen, 1)) {
			perror("dplane listen (unix)");
			return -1;
		}
		chmod(arg, 0666);
		printf("dplane: listening on %s (bfdd: unixc:%s)\n",
		       arg, arg);
	} else {
		int port = atoi(arg);
		dp_listen = socket(AF_INET, SOCK_STREAM, 0);
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
		printf("dplane: listening on 127.0.0.1:%d (bfdd: ipv4c:127.0.0.1:%d)\n",
		       port, port);
	}
	fcntl(dp_listen, F_SETFL, O_NONBLOCK);
	return 0;
}
