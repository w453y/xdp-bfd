// SPDX-License-Identifier: GPL-2.0
/* fsm.c - RFC 5880 state machine and control-packet TX. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "bfd_shared.h"
#include "bfd_auth.h"
#include "util.h"
#include "log.h"
#include "session.h"
#include "fsm.h"
#include "dplane.h"
#include "ktx.h"


int tx_sock = -1, tx6_sock = -1;

/* Send hook; tests replace it to exercise the send-failure path. */
ssize_t (*fsm_send_hook)(int fd, const void *buf, size_t len, const struct sockaddr *dst,
			 socklen_t dlen) = NULL;

static ssize_t fsm_send(int fd, const void *buf, size_t len, const struct sockaddr *dst,
			socklen_t dlen)
{
	if (fsm_send_hook)
		return fsm_send_hook(fd, buf, len, dst, dlen);
	return sendto(fd, buf, len, 0, dst, dlen);
}

/* Per-slot TX sockets bound to the session's local address, source port
 * SRC_PORT + slot. INADDR_ANY would source from the primary address and
 * break the peer's demux of your_disc=0 packets. Stored as fd+1: 0 not
 * opened, -1 bind failed.
 */
static int slot_tx[MAX_SESSIONS];
static struct bfd_addr slot_tx_ip[MAX_SESSIONS];

static int slot_sock(int slot, const struct session *s)
{
	if (slot_tx[slot] > 0 && !memcmp(&slot_tx_ip[slot], &s->local, 16))
		return slot_tx[slot] - 1;
	if (slot_tx[slot] < 0 && !memcmp(&slot_tx_ip[slot], &s->local, 16))
		return -1; /* bind failed earlier; caller uses fallback */
	if (slot_tx[slot] > 0)
		close(slot_tx[slot] - 1); /* slot reused, new local addr */
	slot_tx[slot] = 0;
	slot_tx_ip[slot] = s->local;
	int fd, rc;

	if (s->family == AF_INET6) {
		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if (fd < 0)
			/* fd exhaustion: fall back for now, slot stays 0 so a
			 * later call retries
			 */
			return -1;
		int hops = 255, on = 1;

		setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
		struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6,
					    .sin6_port = htons(SRC_PORT + slot) };
		memcpy(&sa6.sin6_addr, s->local.b, 16);
		rc = bind(fd, (void *)&sa6, sizeof(sa6));
	} else {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0)
			/* fd exhaustion: fall back for now, slot stays 0 so a
			 * later call retries
			 */
			return -1;
		int ttl = 255;

		setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
		struct sockaddr_in sa = { .sin_family = AF_INET,
					  .sin_port = htons(SRC_PORT + slot) };
		memcpy(&sa.sin_addr.s_addr, &s->local.b[12], 4);
		rc = bind(fd, (void *)&sa, sizeof(sa));
	}
	if (rc) {
		log_err("slot %d: bind port %d: %s - using fallback socket (ephemeral src port) for this session\n",
			slot, SRC_PORT + slot, strerror(errno));
		close(fd);
		slot_tx[slot] = -1;
		return -1;
	}
	slot_tx[slot] = fd + 1;
	return fd;
}

/* ---------- FSM ---------- */
/* Transition log lines per session per second before summarising. */
#define BFD_LOG_BURST 5

void state_transition(struct session *s, int newstate, int diag, uint64_t t, const char *why)
{
	if (s->state == newstate)
		return;

	/* Rate-limit the transition log per session: a forger on an
	 * unauthenticated session can flap it per packet. Log the first few
	 * each second and summarise the rest. The transition and the notify
	 * still happen.
	 */
	if (t - s->log_win_us >= 1000000ull) {
		if (s->log_suppressed)
			log_info("[%llu] lid=%u %u more transition(s) suppressed in the last second\n",
				 (unsigned long long)t, s->lid, s->log_suppressed);
		s->log_win_us = t;
		s->log_n = 0;
		s->log_suppressed = 0;
	}
	if (s->log_n < BFD_LOG_BURST) {
		log_info("[%llu] lid=%u %s -> %s (%s)\n", (unsigned long long)t, s->lid,
			 bfd_state_str(s->state), bfd_state_str(newstate), why);
		s->log_n++;
	} else {
		s->log_suppressed++;
	}
	s->state = newstate;
	s->diag = diag;
	if (newstate == ST_UP)
		s->up_events++;
	else if (newstate == ST_DOWN)
		s->down_events++;
	s->last_transition_us = t;
	if (newstate == ST_DOWN && diag == 1 && s->last_rx_us) {
		/* Account the silence here, before detect_iv_us is reset, so a
		 * Down from the sweep (on_sweep_event) is counted too.
		 */
		uint64_t silent = t - s->last_rx_us;
		uint64_t budget = (uint64_t)(s->r_mult ? s->r_mult : s->detect_mult) *
				  s->detect_iv_us;

		s->last_detect_us = (uint32_t)silent;
		s->last_overshoot_us = silent > budget ? (uint32_t)(silent - budget) : 0;
	}
	snprintf(s->last_reason, sizeof(s->last_reason), "%s", why);
	if (newstate == ST_DOWN)
		s->detect_iv_us = 0;
	if (newstate == ST_UP || newstate == ST_DOWN) {
		s->polling = 0;
		s->applied_tx_us = s->min_tx_us;
	}
	/* Each time round to Up is a fresh negotiation: the peer that
	 * comes back has not heard our D bit, whoever it is.
	 */
	s->demand_announced = 0;
	s->just_up = (newstate == ST_UP);
	s->next_tx_us = t;
	dp_notify_state(s);
}

void fsm_rx(struct session *s, const struct bfd_ctrl_pkt *p, uint64_t t)
{
	int ps = (p->flags >> 6) & 3;

	/* Accepted packets only; p->len was already validated. */
	s->rx_pkts++;
	s->rx_bytes += p->len;

	/* dp_notify_state reads the session, so decide what changed, assign,
	 * then notify. Flags-only and mult-only changes count.
	 */
	uint32_t ntx = ntohl(p->min_tx), nrx = ntohl(p->min_rx);
	uint32_t nec = ntohl(p->min_echo_rx);
	uint8_t nfl = p->flags & 0x3f;
	/* min_echo_rx counts as a change too, as in ktx_poll_map. */
	int rparams_changed = (ntx != s->r_min_tx || nrx != s->r_min_rx || nec != s->r_min_echo ||
			       nfl != s->r_flags || p->detect_mult != s->r_mult);

	s->rdisc = ntohl(p->my_disc);
	s->r_state = ps;
	s->r_min_rx = nrx;
	s->r_min_tx = ntx;
	s->r_min_echo = nec;
	s->r_mult = p->detect_mult;
	s->r_flags = nfl;

	/* Notify only in Up. Below Up the state is about to change and
	 * state_transition notifies anyway; notifying here would duplicate
	 * every bring-up. ktx_poll_map follows the same rule.
	 */
	if (s->state == ST_UP && rparams_changed)
		dp_notify_state(s);

	/* Poll-aware detect basis: decreases apply only once traffic
	 * actually paces at the new interval (RFC 5880 s6.8.3).
	 */
	{
		uint32_t cand = s->r_min_tx > s->min_rx_us ? s->r_min_tx : s->min_rx_us;

		if (!s->detect_iv_us || cand >= s->detect_iv_us ||
		    (s->last_rx_us && t - s->last_rx_us <= cand))
			s->detect_iv_us = cand;
	}

	s->last_rx_us = t;
	if (p->flags & F_P)
		s->send_final = 1;
	if ((p->flags & F_F) && s->polling) {
		s->polling = 0;
		s->applied_tx_us = s->min_tx_us;
	}

	if (s->admin_down)
		return;

	if (ps == ST_ADMINDOWN) {
		if (s->state != ST_DOWN)
			state_transition(s, ST_DOWN, 3, t, "peer AdminDown");
		return;
	}
	switch (s->state) {
	case ST_DOWN:
		if (ps == ST_DOWN)
			state_transition(s, ST_INIT, s->diag, t, "peer sent Down");
		else if (ps == ST_INIT)
			state_transition(s, ST_UP, 0, t, "peer sent Init");
		break;
	case ST_INIT:
		if (ps == ST_INIT || ps == ST_UP)
			state_transition(s, ST_UP, 0, t, "peer up");
		break;
	case ST_UP:
		if (ps == ST_DOWN)
			state_transition(s, ST_DOWN, 3, t, "peer sent Down");
		break;
	}
}

void fsm_detect(struct session *s, uint64_t t)
{
	/* RFC 5880 s6.7: clear bfd.AuthSeqKnown after twice the detection time
	 * without a packet, so a peer that restarts with a new sequence can
	 * resync. Runs before the early returns, since Down sessions need it
	 * most; clearing auth_seeded hands the cleared window to the fast path
	 * on the next Up.
	 */
	if (s->auth_type && s->auth_rx_seen && s->last_rx_us) {
		uint64_t iv = s->detect_iv_us
				      ? s->detect_iv_us
				      : (s->r_min_tx > s->min_rx_us ? s->r_min_tx : s->min_rx_us);
		uint8_t mult = s->r_mult ? s->r_mult : s->detect_mult;

		if (iv && t - s->last_rx_us > 2ull * mult * iv) {
			s->auth_rx_seen = 0;
			s->auth_rx_seq = 0;
			s->auth_seeded = 0;
		}
	}

	if (s->state == ST_DOWN || s->state == ST_ADMINDOWN || !s->last_rx_us)
		return;
	/* We asked this peer to stop transmitting, so the gap since its
	 * last packet measures our own request, not the path.
	 */
	if (demand_detect_held(s))
		return;
	uint64_t iv = s->detect_iv_us;

	if (!iv)
		iv = s->r_min_tx > s->min_rx_us ? s->r_min_tx : s->min_rx_us;
	int64_t sd = (int64_t)(t - s->last_rx_us);

	if (sd < 0)
		sd = 0;
	uint8_t mult = s->r_mult ? s->r_mult : s->detect_mult;
	uint64_t budget = (uint64_t)mult * iv;

	/* Sessions carried by the fast path are detected by the sweep. This
	 * stays as a backstop at twice the budget, in case the event ring
	 * stops delivering.
	 */
	if (use_ktx && !s->ktx_uncovered && ktx_events_fd() >= 0)
		budget *= 2;

	if ((uint64_t)sd > budget) {
		/* Debug only: the transition logs the same reason. */
		log_debug("[%llu] lid=%u DETECT TIMEOUT (silent %.1fms)\n", (unsigned long long)t,
			  s->lid, sd / 1000.0);
		s->rdisc = 0;
		state_transition(s, ST_DOWN, 1, t, "detect timeout");
	}
}

/* --demand-poll-us: longest a demanding session may go unverified; 0 disables
 * the periodic poll.
 */
uint64_t demand_poll_us = BFD_DEMAND_POLL_US_DEFAULT;

/* Begin a Poll sequence (RFC 5880 s6.8.3). */
void fsm_start_poll(struct session *s, uint64_t t)
{
	s->poll_seq++;
	s->polling = 1;

	/* Restart detection from now on a demanding session. The peer has been
	 * silent because we asked, so the stale arrival would time out at once
	 * (bfdd resets its recvtimer here too). An unanswered poll then times
	 * out on the detect budget.
	 */
	if (s->demand)
		s->last_rx_us = t;
}

/* Build and send one control packet. Separate from fsm_tx so teardown can send
 * without the pacing logic.
 */
static void tx_one(struct session *s)
{
	__u8 buf[BFD_MAX_LEN] = { 0 };
	struct bfd_ctrl_pkt o = { 0 };
	unsigned int olen = BFD_MIN_LEN;
	int announcing = 0;
	ssize_t sent;

	o.vers_diag = (1 << 5) | (s->diag & 0x1f);
	o.flags = (s->state << 6) | (s->send_final ? F_F : (s->polling ? F_P : 0));
	/* Count the announcement after the send; one that never left does not
	 * use the quota.
	 */
	if (demand_bit_out(s)) {
		o.flags |= F_D;
		announcing = s->demand_announced < DEMAND_ANNOUNCE_N;
	}
	o.detect_mult = s->detect_mult;
	o.len = 24;
	o.my_disc = htonl(s->wire_disc);
	o.your_disc = htonl(s->rdisc);
	o.min_tx = htonl(s->state == ST_UP ? s->min_tx_us : (uint32_t)SLOW_TX_US);
	o.min_rx = htonl(s->min_rx_us);
	o.min_echo_rx = htonl(s->min_echo_rx_us);

	/* RFC 5880 s6.7: the sequence advances per packet for both keyed
	 * forms. A session that cannot build its auth section sends nothing,
	 * since an unauthenticated packet is one the peer must reject.
	 */
	if (s->auth_present) {
		/* Must authenticate but has no sendable key: send nothing. */
		if (!s->auth_type) {
			if (!s->auth_gap_warned) {
				s->auth_gap_warned = 1;
				log_err("lid=%u must authenticate and has no key to send under; nothing sent until one becomes sendable\n",
					s->lid);
			}
			s->send_final = 0;
			s->just_up = 0;
			return;
		}
		o.flags |= BFD_F_AUTH;
		o.len = bfd_auth_pkt_len(s->auth_type, s->auth_keylen);
		memcpy(buf, &o, BFD_MIN_LEN);
		olen = bfd_auth_build(buf, s->auth_type, s->auth_keyid, s->auth_key,
				      s->auth_keylen, s->auth_kpad, ++s->auth_tx_seq);
		if (!olen) {
			log_err("lid=%u cannot build its authentication section; nothing sent\n",
				s->lid);
			s->send_final = 0;
			s->just_up = 0;
			return;
		}
	} else {
		memcpy(buf, &o, BFD_MIN_LEN);
	}

	int txfd = slot_sock((int)(s - sessions), s);

	if (txfd < 0)
		txfd = s->family == AF_INET6 ? tx6_sock : tx_sock;
	if (s->family == AF_INET6) {
		struct sockaddr_in6 dst = { .sin6_family = AF_INET6,
					    .sin6_port = htons(s->is_mhop ? BFD_PORT_MHOP
									  : PORT_CTRL) };
		memcpy(&dst.sin6_addr, s->peer.b, 16);
		sent = fsm_send(txfd, buf, olen, (void *)&dst, sizeof(dst));
	} else {
		struct sockaddr_in dst = { .sin_family = AF_INET,
					   .sin_port = htons(s->is_mhop ? BFD_PORT_MHOP
									: PORT_CTRL) };
		memcpy(&dst.sin_addr.s_addr, &s->peer.b[12], 4);
		sent = fsm_send(txfd, buf, olen, (void *)&dst, sizeof(dst));
	}

	/* Nothing below may run for a packet that did not leave: a failed send
	 * must not clear a pending Final, just_up or the demand quota. The
	 * next scheduled TX retries.
	 */
	if (sent != (ssize_t)olen) {
		s->tx_fail++;
		log_debug("lid=%u send failed: %s\n", s->lid, strerror(errno));
		return;
	}

	if (announcing)
		s->demand_announced++;
	s->tx_pkts++;
	s->send_final = 0;
	s->just_up = 0;
}

/* RFC 5880 s6.8.16: announce AdminDown on teardown so the peer goes down now
 * with diag 3 instead of waiting out detection. Three packets, since nothing
 * retransmits once the slot is freed. Not used for dp_hold orphans.
 */
void fsm_announce_down(struct session *s)
{
	if (!s->used || !s->wire_disc || s->state == ST_ADMINDOWN)
		return;

	/* Set directly, not via state_transition: bfdd asked for the teardown
	 * and needs no notification.
	 */
	s->state = ST_ADMINDOWN;
	s->diag = 7; /* Administratively Down */
	s->send_final = 0;
	s->polling = 0;

	for (int i = 0; i < 3; i++)
		tx_one(s);
}

/* Advance next_tx_us by one jittered interval. Also used by the holds below,
 * so the schedule keeps rolling while nothing is sent.
 */
static void tx_reschedule(struct session *s, uint64_t t)
{
	uint64_t iv, span;

	if (s->state == ST_UP)
		iv = s->applied_tx_us > s->r_min_rx ? s->applied_tx_us : s->r_min_rx;
	else
		iv = SLOW_TX_US;

	/* RFC 5880 s6.8.7 jitter: 75-100% of the interval, 75-90% if
	 * detect_mult is 1. The 1s slow rate is jittered too, so a mesh coming
	 * up together does not synchronise. The 1s floor of s6.8.7 applies to
	 * bfd.DesiredMinTxInterval, not to the jittered gap.
	 */
	span = s->detect_mult == 1 ? iv * 3 / 20 : iv / 4;
	iv = iv * 3 / 4 + (random() % (span + 1));

	s->next_tx_us = t + iv;
}

void fsm_tx(struct session *s, uint64_t t)
{
	if (s->admin_down && s->state != ST_ADMINDOWN)
		state_transition(s, ST_ADMINDOWN, 7, t, "admin shutdown");

	/* RFC 5880 s6.8.7: a passive session must not transmit while
	 * bfd.RemoteDiscr is zero. The schedule keeps rolling so the first
	 * packet after the peer appears is on time.
	 */
	if (s->passive && !s->rdisc) {
		if (t >= s->next_tx_us)
			tx_reschedule(s, t);
		return;
	}

	/* Periodic Poll to verify a demand-mode path (RFC 5880 s6.6).
	 *
	 * Detection is held while demanding, so nothing would take a dead path
	 * down. Poll once per demand_poll_us, never faster than the detect
	 * budget; the poll re-arms detection. Measured from last_rx_us, which
	 * any packet or Final refreshes. Not while the D bit is still being
	 * announced, nor before any packet has arrived.
	 */
	if (demand_poll_us && demand_detect_held(s) && s->last_rx_us && !demand_announce_due(s)) {
		uint64_t iv = s->detect_iv_us;
		uint8_t mult = s->r_mult ? s->r_mult : s->detect_mult;
		uint64_t every;

		if (!iv)
			iv = s->r_min_tx > s->min_rx_us ? s->r_min_tx : s->min_rx_us;
		every = (uint64_t)mult * iv;
		if (every < demand_poll_us)
			every = demand_poll_us;
		if (t - s->last_rx_us >= every) {
			log_debug("[%llu] lid=%u demand poll (unverified %.1fms)\n",
				  (unsigned long long)t, s->lid, (t - s->last_rx_us) / 1000.0);
			s->demand_polls++;
			fsm_start_poll(s, t);
		}
	}

	/* RFC 5880 s6.8.7: the peer is demanding, so stop periodic TX but keep
	 * the schedule rolling. bfdd does the same in ptm_bfd_xmt_TO.
	 */
	if (demand_tx_held(s) || zero_rx_tx_held(s)) {
		if (t >= s->next_tx_us)
			tx_reschedule(s, t);
		return;
	}

	if (s->last_rx_us) {
		uint64_t cur = (s->state == ST_UP)
				       ? (s->applied_tx_us > s->r_min_rx ? s->applied_tx_us
									 : s->r_min_rx)
				       : SLOW_TX_US;
		if (s->next_tx_us > t + cur)
			s->next_tx_us = t + cur;
	}

	int due = (t >= s->next_tx_us) || s->send_final;

	if (use_ktx && !s->ktx_uncovered && ktx_answers(s) && !s->send_final && !s->just_up &&
	    !demand_announce_due(s)) {
		/* The fast path only replies at the peer's pace. If that is
		 * slower than our required rate, transmit from here.
		 * last_ktx_us is when the fast path last replied; it is zero
		 * until the first reply, so userspace transmits until the
		 * kernel has.
		 */
		uint64_t pace = s->applied_tx_us > s->r_min_rx ? s->applied_tx_us : s->r_min_rx;

		if (t - s->last_ktx_us < pace)
			due = 0;
	}
	if (!due)
		return;

	tx_one(s);

	if (t >= s->next_tx_us)
		tx_reschedule(s, t);
}
