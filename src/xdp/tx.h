// SPDX-License-Identifier: GPL-2.0
/* tx.h - RX-clocked TX: rewrite the received frame into our control packet and
 * bounce it with XDP_TX. The v6 checksum fold must run before
 * bpf_xdp_adjust_tail, which invalidates its pointers.
 */
#ifndef BFD_XDP_TX_H
#define BFD_XDP_TX_H

#include "bfd_shared.h"
#include "tunables.h"
#include "auth.h"

static __always_inline int rx_clocked_tx(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph,
					 struct ipv6hdr *ip6, struct udphdr *udp,
					 struct bfd_ctrl_pkt *bfd, struct tx_cfg *cfg,
					 struct session_state *st, struct auth_scratch *sc,
					 void *data, void *data_end)
{
	__u8 send_final = (bfd->flags & BFD_F_POLL) ? BFD_F_FINAL : 0;
	__u32 auth_sum = 0;

	__u8 tmp[6];

	__builtin_memcpy(tmp, eth->h_dest, 6);
	__builtin_memcpy(eth->h_dest, eth->h_source, 6);
	__builtin_memcpy(eth->h_source, tmp, 6);

	/* Swapping halves leaves the checksum alone. */
	if (iph) {
		__be32 tip = iph->saddr;

		iph->saddr = iph->daddr;
		iph->daddr = tip;
	} else if (ip6) {
		struct in6_addr t6 = ip6->saddr;

		ip6->saddr = ip6->daddr;
		ip6->daddr = t6;
	}

	/* RFC 5883: send at 255, not at the TTL this arrived with. */
	if (iph && iph->ttl != 255) {
		/* The v4 checksum is recomputed below. */
		iph->ttl = 255;
	} else if (ip6 && ip6->hop_limit != 255) {
		ip6->hop_limit = 255; /* no checksum in v6 */
	}

	__be16 in_dport = udp->dest;

	/* Back to the arrival port, so multihop replies reach 4784. No UDP
	 * checksum, legal in v4.
	 */
	udp->source = cfg->src_port ? bpf_htons(cfg->src_port) : bpf_htons(BFD_SRC_PORT);
	udp->dest = in_dport;
	udp->check = 0;

	/* P while our Poll is active, F answering the peer's P; never both. */
	bfd->vers_diag = (1 << 5) | (cfg->diag & 0x1f);
	bfd->flags = ((cfg->state & 0x3) << 6) | send_final;
	if (!send_final && cfg->poll && st->final_seq != cfg->poll_seq)
		bfd->flags |= BFD_F_POLL;
	/* D may go with P or F (s6.5); the engine checked both ends are Up. */
	if (cfg->demand)
		bfd->flags |= BFD_F_DEMAND;
	bfd->detect_mult = cfg->mult;
	bfd->len = BFD_MIN_LEN;
	if (cfg->auth_type) {
		__u32 alen = xdp_auth_len(cfg);

		if (!alen)
			return XDP_DROP;
		bfd->flags |= BFD_F_AUTH;
		bfd->len = (__u8)alen;
	}
	bfd->my_disc = bpf_htonl(cfg->my_disc);
	bfd->your_disc = bpf_htonl(cfg->your_disc);
	bfd->min_tx = bpf_htonl(cfg->min_tx_us);
	bfd->min_rx = bpf_htonl(cfg->min_rx_us);
	bfd->min_echo_rx = bpf_htonl(cfg->min_echo_rx_us);

	/* Sign before checksumming and trimming; without a digest send nothing. */
	if (cfg->auth_type && (!sc || !xdp_auth_build(ctx, iph ? BFD_OFF_V4 : BFD_OFF_V6, bfd, cfg,
						      st, sc, &auth_sum)))
		return XDP_DROP;

	/* On adjust_tail failure drop: the frame is half-rewritten. */
	int want = (int)(sizeof(*eth) + (iph ? sizeof(*iph) : sizeof(*ip6)) + sizeof(*udp) +
			 bfd->len);
	int excess = (int)((long)data_end - (long)data) - want;

	/* The received envelope may not describe the frame. */
	udp->len = bpf_htons(sizeof(*udp) + bfd->len);
	if (iph) {
		iph->tot_len = bpf_htons(sizeof(*iph) + sizeof(*udp) + bfd->len);
		iph->check = 0;
		__u32 csum = 0;
		__u16 *w = (__u16 *)iph;

		for (int i = 0; i < 10; i++)
			csum += w[i];
		csum = (csum & 0xffff) + (csum >> 16);
		csum = (csum & 0xffff) + (csum >> 16);
		iph->check = ~csum & 0xffff;
	} else if (ip6) {
		ip6->payload_len = bpf_htons(sizeof(*udp) + bfd->len);
	}

	/* v6: the UDP checksum is mandatory. The fold reads nothing the trim removes. */
	if (ip6) {
		__u32 csum = 0;
		__u16 *w = (__u16 *)&ip6->saddr;

		for (int i = 0; i < 16; i++) /* saddr + daddr */
			csum += w[i];
		csum += udp->len; /* pseudo length */
		csum += bpf_htons(IPPROTO_UDP);
		w = (__u16 *)udp; /* UDP hdr, check == 0 */
		for (int i = 0; i < 4; i++)
			csum += w[i];
		/* With auth the payload length varies; xdp_auth_build returns its sum. */
		if (cfg->auth_type) {
			csum += auth_sum;
		} else {
			w = (__u16 *)bfd;
			for (int i = 0; i < BFD_MIN_LEN / 2; i++)
				csum += w[i];
		}
		csum = (csum & 0xffff) + (csum >> 16);
		csum = (csum & 0xffff) + (csum >> 16);
		__u16 c = ~csum & 0xffff;

		udp->check = c ? c : 0xffff; /* RFC 768: 0 -> 0xffff */
	}

	if (excess > 0 && bpf_xdp_adjust_tail(ctx, -excess))
		return XDP_DROP;

	st->tx_pkts++;
	return XDP_TX;
}

#endif /* BFD_XDP_TX_H */
