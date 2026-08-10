// SPDX-License-Identifier: GPL-2.0
/* echo_tx.c - m8b echo originator.
 *
 * Self-addressed UDP/3785 to the neighbour's MAC at TTL 255, sent on
 * a raw L2 socket: a self-addressed packet through a normal socket is
 * routed to loopback and never reaches the wire. Detection keys off
 * the outstanding nonce, so a stall means no echo outstanding and no
 * timeout can fire.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bfd_shared.h"
#include "util.h"
#include "session.h"
#include "echo_tx.h"
#include "ktx.h"

int echo_sock = -1, echo_ifindex = 0;
uint8_t echo_src_mac[6];
static uint32_t echo_nonce_ctr;

/* ---- m8b: echo originator ---- */
static uint16_t ip_csum(const void *data, size_t len)
{
	const uint16_t *w = data;
	uint32_t sum = 0;
	while (len > 1) { sum += *w++; len -= 2; }
	if (len) sum += *(const uint8_t *)w;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* Self-addressed UDP/3785 to the neighbour's MAC, TTL 255. The trailing
 * payload word carries a nonce; the return is matched on it for RTT.
 * Detection keys off the outstanding nonce, so if this stalls there is
 * simply no echo outstanding and no timeout can fire. */
void echo_tx_maybe(struct session *s, uint64_t t)
{
	if (echo_sock < 0 || !s->echo_tx_us || s->state != ST_UP)
		return;
	if (!s->mac_valid || s->family != AF_INET)
		return;
	if (t < s->next_echo_tx_us)
		return;
	if (s->echo_last_send_us) {
		uint64_t gap = t - s->echo_last_send_us;
		if (gap > s->echo_gap_max_us)
			s->echo_gap_max_us = gap;
	}
	s->echo_last_send_us = t;
	s->next_echo_tx_us = t + s->echo_tx_us;

	/* Previous echo never came back before this one is due. */
	if (s->echo_sent_us) {
		s->echo_lost++;
		s->echo_sent_us = 0;
	}

	if (!s->echo_disc_done && echo_disc_fd >= 0 && s->wire_disc) {
		struct session_key dk = {};
		dk.peer  = s->peer;
		dk.local = s->local;
		if (!bpf_map_update_elem(echo_disc_fd, &s->wire_disc, &dk, 0))
			s->echo_disc_done = 1;
	}

	uint8_t frame[66];
	memset(frame, 0, sizeof(frame));

	memcpy(frame + 0, s->peer_mac, 6);
	memcpy(frame + 6, echo_src_mac, 6);
	frame[12] = 0x08;
	frame[13] = 0x00;

	uint8_t *ip = frame + 14;
	uint16_t tot = 20 + 8 + 24;
	ip[0] = 0x45;
	ip[1] = 0xc0;
	ip[2] = tot >> 8;
	ip[3] = tot & 0xff;
	ip[8] = 255;
	ip[9] = 17;
	memcpy(ip + 12, s->local.b + 12, 4);
	memcpy(ip + 16, s->local.b + 12, 4);
	uint16_t ipc = ip_csum(ip, 20);
	memcpy(ip + 10, &ipc, 2);

	uint8_t *udp = frame + 34;
	uint16_t ulen = 8 + 24;
	udp[0] = 3785 >> 8; udp[1] = 3785 & 0xff;
	udp[2] = 3785 >> 8; udp[3] = 3785 & 0xff;
	udp[4] = ulen >> 8; udp[5] = ulen & 0xff;

	uint8_t *b = frame + 42;
	uint32_t v, nonce = ++echo_nonce_ctr;
	b[0] = (1 << 5);
	b[1] = (ST_UP & 0x3) << 6;
	b[2] = s->detect_mult;
	b[3] = 24;
	v = htonl(s->wire_disc); memcpy(b + 4,  &v, 4);
	v = 0;                   memcpy(b + 8,  &v, 4);
	v = htonl(s->min_tx_us); memcpy(b + 12, &v, 4);
	v = htonl(s->min_rx_us); memcpy(b + 16, &v, 4);
	v = htonl(nonce);        memcpy(b + 20, &v, 4);

	uint8_t ps[12 + 8 + 24];
	memcpy(ps + 0, ip + 12, 4);
	memcpy(ps + 4, ip + 16, 4);
	ps[8]  = 0;
	ps[9]  = 17;
	ps[10] = ulen >> 8;
	ps[11] = ulen & 0xff;
	memcpy(ps + 12, udp, 8);
	memcpy(ps + 20, b, 24);
	uint16_t uc = ip_csum(ps, sizeof(ps));
	if (!uc)
		uc = 0xffff;
	memcpy(udp + 6, &uc, 2);

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family  = AF_PACKET;
	sll.sll_ifindex = echo_ifindex;
	sll.sll_halen   = 6;
	memcpy(sll.sll_addr, s->peer_mac, 6);

	if (sendto(echo_sock, frame, sizeof(frame), 0,
		   (struct sockaddr *)&sll, sizeof(sll)) < 0)
		return;

	s->echo_nonce   = nonce;
	s->echo_sent_us = t;
	s->echo_tx_pkts++;

	if (s->echo_tx_pkts % 100 == 0) {
		const uint8_t *lo = s->local.b + 12, *pe = s->peer.b + 12;
		uint64_t avg = s->echo_rtt_n ? s->echo_rtt_sum_us / s->echo_rtt_n : 0;
		printf("echo %u.%u.%u.%u->%u.%u.%u.%u tx=%llu rx=%llu lost=%llu "
		       "rtt last/min/avg/max %llu/%llu/%llu/%llu us win-max %llu gap-max %lluus echo-alive=%d\n",
		       lo[0], lo[1], lo[2], lo[3], pe[0], pe[1], pe[2], pe[3],
		       (unsigned long long)s->echo_tx_pkts,
		       (unsigned long long)s->echo_rx_pkts,
		       (unsigned long long)s->echo_lost,
		       (unsigned long long)s->echo_rtt_last_us,
		       (unsigned long long)s->echo_rtt_min_us,
		       (unsigned long long)avg,
		       (unsigned long long)s->echo_rtt_max_us,
		       (unsigned long long)s->echo_rtt_max_win_us,
		       (unsigned long long)s->echo_gap_max_us,
		       s->echo_alive_k);
		s->echo_gap_max_us = 0;
		s->echo_rtt_max_win_us = 0;
		fflush(stdout);
	}
}
