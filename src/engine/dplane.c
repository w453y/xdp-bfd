// SPDX-License-Identifier: GPL-2.0
/* dplane.c - bfddp messages and session lifecycle. Fields are network order. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <endian.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include "bfd_shared.h"
#include "bfd_auth.h"
#include "bfddp.h"
#include "util.h"
#include "log.h"
#include "session.h"
#include "dplane.h"
#include "ktx.h"
#include "fsm.h"

uint64_t dp_hold_us;	  /* --dp-hold: keep sessions across bfdd restarts */
uint64_t dp_reconcile_us; /* sweep deadline after reconnect */
#define DP_RECONCILE_US (10ull * 1000000)
/* A few replies' worth, kept free of notifications. */
#define DP_REPLY_ROOM 1024

/* bfdd's RBIT_* positions differ from the wire flags. */
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

/* Connection lost: with --dp-hold, keep sessions as orphans for bfdd to
 * reclaim; otherwise tear them down.
 */
void dp_sessions_orphan(const char *why)
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

/* bfdd is back: tear down in DP_RECONCILE_US whatever it has not re-added. */
void dp_sessions_reclaim(void)
{
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].orphaned) {
			dp_reconcile_us = now_us() + DP_RECONCILE_US;
			log_info("dplane: reconcile sweep armed (%llus)\n",
				 (unsigned long long)(DP_RECONCILE_US / 1000000));
			break;
		}
}

void dp_notify_state(struct session *s)
{
	struct {
		struct bfddp_message_header h;
		struct bfddp_state_change sc;
	} __attribute__((packed)) m = { 0 };

	/* Held for bfdd's return, which dp_notify_flush_pending serves. */
	if (!dp_connected()) {
		s->notify_pending = 1;
		return;
	}

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

	/* Queue short: defer rather than drop the connection. A flap storm
	 * collapses to one message per session. DP_REPLY_ROOM stays free for
	 * replies, which bfdd waits on and which cannot be deferred.
	 */
	if (sizeof(m) + DP_REPLY_ROOM > dp_out_room()) {
		s->notify_pending = 1;
		return;
	}
	s->notify_pending = 0;
	dp_send(&m, sizeof(m));
}

/* Called after dp_flush. */
void dp_notify_flush_pending(void)
{
	if (!dp_connected())
		return;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].notify_pending)
			dp_notify_state(&sessions[i]);
}

/* bfdd sends 0.0.0.0 or :: without a local-address, but the fast path keys on
 * (peer, local). connect() on a datagram socket finds the source the kernel
 * would use.
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

/* Once a second while not Up; if the route moved, drop the old key. */
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

/* Its own session, a live one adopted under a new lid, or a fresh one. NULL if
 * the table is full.
 */
static struct session *dp_add_find(uint32_t lid, const struct bfddp_session_msg *sm, int *fresh,
				   int *adopted)
{
	struct session *s = sess_by_lid(lid);
	struct session *stale;

	if (s) {
		/* bfdd reconnected with stable lids. It ran the session itself
		 * meanwhile, so it needs our state as well as the unmark.
		 */
		if (s->orphaned)
			*adopted = 1;
		s->orphaned = 0;
		return s;
	}
	stale = sess_by_addr_pair_local(sm);
	if (stale && dp_hold_us && stale->state == ST_UP) {
		/* Graceful restart: bfdd re-registered the pair under a new
		 * lid. Adopt the live session in place.
		 */
		log_info("dplane: ADD lid=%u adopts live session (old lid=%u)\n", lid, stale->lid);
		stale->orphaned = 0;
		*adopted = 1;
		return stale;
	}
	if (stale) {
		log_info("dplane: ADD lid=%u replaces stale lid=%u\n", lid, stale->lid);
		ktx_clear(stale);
		memset(stale, 0, sizeof(*stale));
	}
	s = sess_alloc();
	if (!s) {
		log_err("dplane: session table full\n");
		return NULL;
	}
	*fresh = 1;
	return s;
}

/* An UPDATE may move the address pair; clear the old pair's map entries. */
static void dp_add_addrs(struct session *s, const struct bfddp_session_msg *sm, int fresh)
{
	struct bfd_addr old_peer = s->peer, old_local = s->local;

	sm_addrs(sm, &s->local, &s->peer, &s->family);
	s->local_wildcard = addr_unspecified(&s->local, s->family);
	if (s->local_wildcard) {
		dp_resolve_local(s);
		if (addr_unspecified(&s->local, s->family))
			log_err("dplane: lid=%u has no local address and none could be resolved to reach its peer; the fast path cannot key it\n",
				s->lid);
	}
	if (!fresh && (memcmp(&old_peer, &s->peer, sizeof(old_peer)) ||
		       memcmp(&old_local, &s->local, sizeof(old_local)))) {
		log_info("dplane: ADD lid=%u moved address pair, clearing the old\n", s->lid);
		ktx_clear_key(&old_peer, &old_local, s->wire_disc);
		echo_peer_refresh(&old_peer, s);
		/* echo_disc still maps the old key. */
		s->echo_disc_done = 0;
	}
}

/* RFC 5880 s6.7: SESSION_AUTH says whether it authenticates; keys come in
 * DP_SESSION_AUTH. The TX sequence starts random (s6.7.3).
 */
static void dp_add_auth(struct session *s, uint32_t flags)
{
	int authed = !!(flags & SESSION_AUTH);

	if (!authed && s->auth_present) {
		memset(s->auth_keys, 0, sizeof(s->auth_keys));
		s->auth_nkeys = 0;
	}
	if (authed != s->auth_present) {
		s->auth_present = (uint8_t)authed;
		auth_seq_seed(s, (uint32_t)random());
		s->auth_rx_seq = 0;
		s->auth_rx_seen = 0;
	}
	session_auth_evaluate(s, (int64_t)time(NULL));
}

/* Multihop sessions can ingress anywhere, so they attach nowhere. */
static void dp_add_iface(struct session *s, const struct bfddp_session_msg *sm)
{
	uint32_t sif = ntohl(sm->ifindex);

	/* Echo TX sends at L2 on this interface. */
	if (sif != s->ifindex) {
		s->ifindex = sif;
		s->echo_mac_valid = 0;
	}

	if (use_ktx && !s->is_mhop && sif && !ktx_covers((int)sif)) {
		char ifn[sizeof(sm->ifname) + 1];

		/* Need not be NUL-terminated. */
		snprintf(ifn, sizeof(ifn), "%.*s", (int)sizeof(sm->ifname), sm->ifname);
		ktx_attach_if((int)sif, ifn);
	}
	s->ktx_uncovered = (use_ktx && !s->is_mhop && sif && !ktx_covers((int)sif));
	if (s->ktx_uncovered && !s->iface_warned) {
		s->iface_warned = 1;
		log_info("dplane: lid=%u is on %.*s (ifindex %u) and could not be attached - this session runs in userspace only\n",
			 s->lid, (int)sizeof(sm->ifname), sm->ifname, sif);
	}
}

static void dp_add_timers(struct session *s, uint64_t t, int fresh, uint32_t old_tx,
			  uint32_t old_rx)
{
	if (!fresh && s->state == ST_UP && (s->min_tx_us != old_tx || s->min_rx_us != old_rx)) {
		/* RFC 5880 s6.8.3: a change while Up needs a Poll. An increase
		 * waits for the Final; a decrease applies now.
		 */
		if (s->min_tx_us < s->applied_tx_us || !s->applied_tx_us)
			s->applied_tx_us = s->min_tx_us;
		fsm_start_poll(s, t);
	} else if (!s->polling) {
		/* Not mid-Poll: the old interval holds until the Final. */
		s->applied_tx_us = s->min_tx_us;
	}
	if (fresh) {
		s->state = s->admin_down ? ST_ADMINDOWN : ST_DOWN;
		s->diag = 0;
		s->pushed_valid = 0;
		s->next_tx_us = t;
	}

	if (!fresh && !s->admin_down && s->state == ST_ADMINDOWN) {
		/* SHUTDOWN cleared: leave AdminDown; nothing else does. */
		state_transition(s, ST_DOWN, 0, now_us(), "admin shutdown cleared");
		s->next_tx_us = now_us();
	}
}

static void dp_add_log(const struct session *s, int fresh)
{
	char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];

	if (s->family == AF_INET6) {
		inet_ntop(AF_INET6, s->local.b, a, sizeof(a));
		inet_ntop(AF_INET6, s->peer.b, b, sizeof(b));
	} else {
		inet_ntop(AF_INET, &s->local.b[12], a, sizeof(a));
		inet_ntop(AF_INET, &s->peer.b[12], b, sizeof(b));
	}
	log_debug("dplane: %s session lid=%u %s -> %s tx=%uus rx=%uus mult=%u%s%s\n",
		  fresh ? "ADD" : "UPDATE", s->lid, a, b, s->min_tx_us, s->min_rx_us,
		  s->detect_mult, s->passive ? " passive" : "", s->admin_down ? " shutdown" : "");
}

static void dp_handle_add(const struct bfddp_session_msg *sm, uint64_t t)
{
	uint32_t flags = ntohl(sm->flags);
	uint32_t lid = ntohl(sm->lid);
	int fresh = 0, adopted = 0;
	struct session *s = dp_add_find(lid, sm, &fresh, &adopted);
	uint32_t old_tx, old_rx;

	if (!s)
		return;

	s->lid = lid;
	if (fresh || !s->wire_disc) {
		/* RFC 5880: constant while Up, so an adopted session keeps its
		 * own, and bfdd may reissue that number as a lid later.
		 */
		uint32_t d = lid;

		while (!d || (sess_by_wire(d) && sess_by_wire(d) != s))
			d = (uint32_t)random() | 1;
		s->wire_disc = d;
	}
	dp_add_addrs(s, sm, fresh);

	old_tx = s->min_tx_us;
	old_rx = s->min_rx_us;
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

	dp_add_auth(s, flags);
	ktx_update_mhop_flag();
	dp_add_iface(s, sm);
	/* Shared by every session with this peer, so recompute rather than
	 * update.
	 */
	echo_peer_refresh(&s->peer, NULL);
	dp_add_timers(s, t, fresh, old_tx, old_rx);
	dp_add_log(s, fresh);
	if (adopted)
		dp_notify_state(s);
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

		/* Userspace plus kernel counts. Kernel bytes assume 24 per
		 * packet.
		 */
		uint64_t rx = s->rx_pkts + krx;
		uint64_t rx_bytes = s->rx_bytes + krx * BFD_MIN_LEN;
		uint64_t tx = s->tx_pkts + ktx;

		m.c.control_input_bytes = htobe64(rx_bytes);
		m.c.control_input_packets = htobe64(rx);
		m.c.control_output_bytes = htobe64(tx * BFD_MIN_LEN);
		m.c.control_output_packets = htobe64(tx);

		/* Our own echoes only: echo_peers is keyed on address alone. */
		m.c.echo_input_bytes = htobe64(s->echo_rx_pkts * BFD_MIN_LEN);
		m.c.echo_input_packets = htobe64(s->echo_rx_pkts);
		m.c.echo_output_bytes = htobe64(s->echo_tx_pkts * BFD_MIN_LEN);
		m.c.echo_output_packets = htobe64(s->echo_tx_pkts);
	}
	dp_send(&m, sizeof(m));
}

/* The whole chain arrives once; key choice follows the clock. */
static void dp_session_auth(const struct bfddp_session_auth *sa, size_t plen)
{
	uint32_t lid = ntohl(sa->lid);
	uint16_t count = ntohs(sa->key_count);
	struct session *s = sess_by_lid(lid);
	unsigned int i, kept = 0;

	if (!s)
		return;

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

		/* Drop rather than truncate: a truncated key fails every
		 * packet.
		 */
		if (kl == 0 || kl > sizeof(dst->kpad)) {
			log_err("dplane: lid=%u key id %u has an unusable length %u, ignored\n",
				lid, k->key_id, kl);
			continue;
		}
		/* Keyed MD5 and anything newer: we can neither sign nor verify. */
		if (!bfd_auth_pkt_len(k->type, kl)) {
			log_err("dplane: lid=%u key id %u has unsupported type %u, ignored\n", lid,
				k->key_id, k->type);
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

void dp_process(const uint8_t *buf, size_t len)
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
			dp_handle_add((const void *)payload, t);
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
