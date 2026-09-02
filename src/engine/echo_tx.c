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
#include "addrstr.h"
#include "util.h"
#include "log.h"
#include "session.h"
#include <net/if.h>
#include <sys/ioctl.h>
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

void echo_tx_init(const char *ifname)
{
        	/* Echo TX needs a raw L2 socket: a self-addressed UDP packet sent
        	 * through a normal socket is routed to loopback and never reaches
        	 * the wire. */
        	echo_ifindex = if_nametoindex(ifname);
        	struct ifreq ifr;
        	memset(&ifr, 0, sizeof(ifr));
        	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        	int mfd = socket(AF_INET, SOCK_DGRAM, 0);
        	if (mfd >= 0) {
        		if (!ioctl(mfd, SIOCGIFHWADDR, &ifr))
        			memcpy(echo_src_mac, ifr.ifr_hwaddr.sa_data, 6);
        		close(mfd);
        	}
        	/* Protocol 0, not ETH_P_ALL: this socket only ever sends.
        	 * ETH_P_ALL subscribes the process to every inbound frame on
        	 * every interface, so packet_rcv runs for all host traffic and
        	 * queues it on a socket nothing reads. TX behaviour is
        	 * identical either way. */
        	echo_sock = socket(AF_PACKET, SOCK_RAW, 0);
        	if (echo_sock < 0)
        		perror("echo raw socket");
        	log_info("echo-tx: ifindex %d src-mac %02x:%02x:%02x:%02x:%02x:%02x sock %d\n",
        	       echo_ifindex, echo_src_mac[0], echo_src_mac[1], echo_src_mac[2],
        	       echo_src_mac[3], echo_src_mac[4], echo_src_mac[5], echo_sock);
}

/* The 24-byte payload, identical on both families. My Disc names the
 * session when the frame comes back; Your Disc is zero because a classic
 * echo never loops it; and the nonce rides in the Required Min Echo RX
 * field, which is the word the kernel return demux reads back into
 * session_state.echo_last_nonce. */
static void echo_payload(struct session *s, uint8_t *b, uint32_t nonce)
{
	uint32_t v;

	b[0] = (1 << 5);
	b[1] = (ST_UP & 0x3) << 6;
	b[2] = s->detect_mult;
	b[3] = 24;
	v = htonl(s->wire_disc); memcpy(b + 4,  &v, 4);
	v = 0;                   memcpy(b + 8,  &v, 4);
	v = htonl(s->min_tx_us); memcpy(b + 12, &v, 4);
	v = htonl(s->min_rx_us); memcpy(b + 16, &v, 4);
	v = htonl(nonce);        memcpy(b + 20, &v, 4);
}

/* v4: self-addressed, TTL 255, IP checksum plus a UDP checksum over the
 * 12-byte pseudo-header. Returns the frame length. */
static unsigned echo_build_v4(struct session *s, uint8_t *frame,
			      uint32_t nonce)
{
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
	echo_payload(s, b, nonce);

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

	return 14 + 20 + 8 + 24;
}

/* v6: no IP checksum to compute, but the UDP one is mandatory rather than
 * optional and its pseudo-header is 40 bytes instead of 12 - the two
 * addresses, a 32-bit upper-layer length, three zero bytes and the next
 * header. Self-addressed at hop limit 255, which the neighbour's
 * forwarding plane returns at 254 exactly as it does for v4. */
static unsigned echo_build_v6(struct session *s, uint8_t *frame,
			      uint32_t nonce)
{
	memcpy(frame + 0, s->peer_mac, 6);
	memcpy(frame + 6, echo_src_mac, 6);
	frame[12] = 0x86;
	frame[13] = 0xdd;

	uint8_t *ip = frame + 14;
	uint16_t plen = 8 + 24;
	ip[0] = 0x6c;          /* version 6, traffic class 0xc0 */
	ip[4] = plen >> 8;
	ip[5] = plen & 0xff;
	ip[6] = 17;            /* next header: UDP */
	ip[7] = 255;           /* hop limit */
	memcpy(ip + 8,  s->local.b, 16);
	memcpy(ip + 24, s->local.b, 16);

	uint8_t *udp = frame + 54;
	udp[0] = 3785 >> 8; udp[1] = 3785 & 0xff;
	udp[2] = 3785 >> 8; udp[3] = 3785 & 0xff;
	udp[4] = plen >> 8; udp[5] = plen & 0xff;

	uint8_t *b = frame + 62;
	echo_payload(s, b, nonce);

	uint8_t ps[40 + 8 + 24];
	memset(ps, 0, sizeof(ps));
	memcpy(ps + 0,  s->local.b, 16);
	memcpy(ps + 16, s->local.b, 16);
	ps[34] = plen >> 8;
	ps[35] = plen & 0xff;
	ps[39] = 17;
	memcpy(ps + 40, udp, 8);
	memcpy(ps + 48, b, 24);
	uint16_t uc = ip_csum(ps, sizeof(ps));
	if (!uc)
		uc = 0xffff;
	memcpy(udp + 6, &uc, 2);

	return 14 + 40 + 8 + 24;
}

/* Self-addressed UDP/3785 to the neighbour's MAC, TTL 255. The trailing
 * payload word carries a nonce; the return is matched on it for RTT.
 * Detection keys off the outstanding nonce, so if this stalls there is
 * simply no echo outstanding and no timeout can fire. */
void echo_tx_maybe(struct session *s, uint64_t t)
{
	if (echo_sock < 0 || !s->echo_tx_us || s->state != ST_UP)
		return;
	if (!s->mac_valid)
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

	uint8_t frame[86];
	uint32_t nonce = ++echo_nonce_ctr;
	unsigned flen;

	memset(frame, 0, sizeof(frame));

	if (s->family == AF_INET6)
		flen = echo_build_v6(s, frame, nonce);
	else
		flen = echo_build_v4(s, frame, nonce);

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family  = AF_PACKET;
	sll.sll_ifindex = echo_ifindex;
	sll.sll_halen   = 6;
	memcpy(sll.sll_addr, s->peer_mac, 6);

	if (sendto(echo_sock, frame, flen, 0,
		   (struct sockaddr *)&sll, sizeof(sll)) < 0)
		return;

	s->echo_nonce   = nonce;
	s->echo_sent_us = t;
	s->echo_tx_pkts++;

	if (s->echo_tx_pkts % 100 == 0) {
		char lb[INET6_ADDRSTRLEN], pb[INET6_ADDRSTRLEN];
		uint64_t avg = s->echo_rtt_n ? s->echo_rtt_sum_us / s->echo_rtt_n : 0;
		log_debug("echo %s->%s tx=%llu rx=%llu lost=%llu "
		       "rtt last/min/avg/max %llu/%llu/%llu/%llu us win-max %llu gap-max %lluus echo-alive=%d\n",
		       bfd_addr_str(&s->local, lb, sizeof(lb)),
		       bfd_addr_str(&s->peer, pb, sizeof(pb)),
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
