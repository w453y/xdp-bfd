// SPDX-License-Identifier: GPL-2.0
/* fsm.c - RFC 5880 state machine and control-packet TX.
 *
 * Per-slot TX sockets bind source port SRC_PORT + slot to the
 * session's local address: INADDR_ANY would let routing source every
 * packet from the primary address, breaking the peer's address-based
 * demux for your_disc=0 packets.
 */
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
#include "util.h"
#include "session.h"
#include "fsm.h"
#include "dplane.h"
#include "ktx.h"

static const char *stname[] = { "AdminDown", "Down", "Init", "Up" };

int tx_sock = -1, tx6_sock = -1;

/* Per-slot TX sockets: source port = SRC_PORT + slot, bound to the
 * session's local address (INADDR_ANY would let routing source every
 * packet from the primary address, which breaks the peer's
 * address-based demux for your_disc=0 packets). Opened lazily and
 * kept; a reused slot with a different local address rebinds.
 * Stored as fd+1; 0 = not opened; -1 = bind failed. */
static int slot_tx[MAX_SESSIONS];
static struct bfd_addr slot_tx_ip[MAX_SESSIONS];

static int slot_sock(int slot, const struct session *s)
{
	if (slot_tx[slot] > 0 && !memcmp(&slot_tx_ip[slot], &s->local, 16))
		return slot_tx[slot] - 1;
	if (slot_tx[slot] < 0 && !memcmp(&slot_tx_ip[slot], &s->local, 16))
		return -1;   /* bind failed earlier; caller uses fallback */
	if (slot_tx[slot] > 0)
		close(slot_tx[slot] - 1);   /* slot reused, new local addr */
	slot_tx[slot] = 0;
	slot_tx_ip[slot] = s->local;
	int fd, rc;
	if (s->family == AF_INET6) {
		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		int hops = 255, on = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
		struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6,
			.sin6_port = htons(SRC_PORT + slot) };
		memcpy(&sa6.sin6_addr, s->local.b, 16);
		rc = bind(fd, (void *)&sa6, sizeof(sa6));
	} else {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		int ttl = 255;
		setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
		struct sockaddr_in sa = { .sin_family = AF_INET,
			.sin_port = htons(SRC_PORT + slot) };
		memcpy(&sa.sin_addr.s_addr, &s->local.b[12], 4);
		rc = bind(fd, (void *)&sa, sizeof(sa));
	}
	if (rc) {
		fprintf(stderr,
			"slot %d: bind port %d: %s - using fallback socket "
			"(ephemeral src port) for this session\n",
			slot, SRC_PORT + slot, strerror(errno));
		close(fd);
		slot_tx[slot] = -1;
		return -1;
	}
	slot_tx[slot] = fd + 1;
	return fd;
}

/* ---------- FSM ---------- */
void state_transition(struct session *s, int newstate, int diag,
			     uint64_t t, const char *why)
{
	if (s->state == newstate)
		return;
	printf("[%llu] lid=%u %s -> %s (%s)\n", (unsigned long long)t,
	       s->lid, stname[s->state], stname[newstate], why);
	s->state = newstate;
	s->diag  = diag;
	if (newstate == ST_DOWN)
		s->detect_iv_us = 0;
	if (newstate == ST_UP || newstate == ST_DOWN) {
		s->polling = 0;
		s->applied_tx_us = s->min_tx_us;
	}
	s->just_up = (newstate == ST_UP);
	s->next_tx_us = t;
	dp_notify_state(s);
}

void fsm_rx(struct session *s, const struct bfdpkt *p, uint64_t t)
{
	int ps = (p->flags >> 6) & 3;

	{
		uint32_t ntx = ntohl(p->min_tx), nrx = ntohl(p->min_rx);
		if (s->state == ST_UP &&
		    (ntx != s->r_min_tx || nrx != s->r_min_rx)) {
			s->r_min_tx = ntx;
			s->r_min_rx = nrx;
			dp_notify_state(s);   /* refresh remote timers */
		}
	}
	s->rdisc    = ntohl(p->my_disc);
	s->r_state  = ps;
	s->r_min_rx = ntohl(p->min_rx);
	s->r_min_tx = ntohl(p->min_tx);
	s->r_min_echo = ntohl(p->min_echo);
	s->r_mult   = p->mult;
	s->r_flags  = p->flags & 0x3f;

	/* Poll-aware detect basis: decreases apply only once traffic
	 * actually paces at the new interval (RFC 5880 s6.8.3). */
	{
		uint32_t cand = s->r_min_tx > s->min_rx_us ?
				s->r_min_tx : s->min_rx_us;
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
		if (ps == ST_DOWN && !s->passive)
			state_transition(s, ST_INIT, s->diag, t,
					 "peer sent Down");
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
	if (s->state == ST_DOWN || s->state == ST_ADMINDOWN || !s->last_rx_us)
		return;
	uint64_t iv = s->detect_iv_us;
	if (!iv)
		iv = s->r_min_tx > s->min_rx_us ? s->r_min_tx : s->min_rx_us;
	int64_t sd = (int64_t)(t - s->last_rx_us);
	if (sd < 0)
		sd = 0;
	uint8_t mult = s->r_mult ? s->r_mult : s->detect_mult;
	if ((uint64_t)sd > (uint64_t)mult * iv) {
		printf("[%llu] lid=%u DETECT TIMEOUT (silent %.1fms)\n",
		       (unsigned long long)t, s->lid, sd / 1000.0);
		s->rdisc = 0;
		state_transition(s, ST_DOWN, 1, t, "detect timeout");
	}
}

void fsm_tx(struct session *s, uint64_t t)
{
	if (s->admin_down && s->state != ST_ADMINDOWN)
		state_transition(s, ST_ADMINDOWN, 7, t, "admin shutdown");

	if (s->last_rx_us) {
		uint64_t cur = (s->state == ST_UP)
			? (s->applied_tx_us > s->r_min_rx ? s->applied_tx_us
							  : s->r_min_rx)
			: SLOW_TX_US;
		if (s->next_tx_us > t + cur)
			s->next_tx_us = t + cur;
	}

	int due = (t >= s->next_tx_us) || s->send_final;
	if (use_ktx && s->state == ST_UP && !s->send_final && !s->just_up) {
		/* Kernel echo covers TX only at the peer's pace. If the
		 * peer paces slower than our required rate (its detect
		 * budget for us), transmit from here at the required
		 * pace; otherwise stay silent as before. last_rx_us is
		 * synced from the map, so it tracks kernel echo times. */
		uint64_t pace = s->applied_tx_us > s->r_min_rx ?
				s->applied_tx_us : s->r_min_rx;
		if (t - s->last_rx_us < pace)
			due = 0;
	}
	if (!due)
		return;

	struct bfdpkt o = {0};
	o.vers_diag = (1 << 5) | (s->diag & 0x1f);
	o.flags     = (s->state << 6) |
		      (s->send_final ? F_F : (s->polling ? F_P : 0));
	o.mult      = s->detect_mult;
	o.len       = 24;
	o.my_disc   = htonl(s->wire_disc);
	o.your_disc = htonl(s->rdisc);
	o.min_tx    = htonl(s->state == ST_UP ? s->min_tx_us
					      : (uint32_t)SLOW_TX_US);
	o.min_rx    = htonl(s->min_rx_us);
	o.min_echo  = htonl(s->min_echo_rx_us);

	int txfd = slot_sock((int)(s - sessions), s);
	if (txfd < 0)
		txfd = s->family == AF_INET6 ? tx6_sock : tx_sock;
	if (s->family == AF_INET6) {
		struct sockaddr_in6 dst = { .sin6_family = AF_INET6,
			.sin6_port = htons(s->is_mhop ? BFD_PORT_MHOP : PORT_CTRL) };
		memcpy(&dst.sin6_addr, s->peer.b, 16);
		sendto(txfd, &o, 24, 0, (void *)&dst, sizeof(dst));
	} else {
		struct sockaddr_in dst = { .sin_family = AF_INET,
			.sin_port = htons(s->is_mhop ? BFD_PORT_MHOP : PORT_CTRL) };
		memcpy(&dst.sin_addr.s_addr, &s->peer.b[12], 4);
		sendto(txfd, &o, 24, 0, (void *)&dst, sizeof(dst));
	}
	s->tx_pkts++;
	s->send_final = 0;
	s->just_up = 0;

	if (t >= s->next_tx_us) {
		uint64_t iv;
		if (s->state == ST_UP) {
			iv = s->applied_tx_us > s->r_min_rx ? s->applied_tx_us
							    : s->r_min_rx;
			/* RFC 5880 s6.8.7: jitter the interval to 75-100%,
			 * but only 75-90% when detect_mult is 1. */
			uint64_t span = s->detect_mult == 1 ? iv * 3 / 20
							    : iv / 4;
			iv = iv * 3 / 4 + (random() % (span + 1));
		} else {
			iv = SLOW_TX_US;
		}
		s->next_tx_us = t + iv;
	}
}
