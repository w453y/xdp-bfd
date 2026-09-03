// SPDX-License-Identifier: GPL-2.0
/* tx.h - RX-clocked TX: rewrite the received frame into our control
 * packet and bounce it with XDP_TX. The peer's transmit clock becomes
 * ours, executed in softirq.
 *
 * Ordering constraint: the v6 UDP checksum fold runs BEFORE
 * bpf_xdp_adjust_tail, which invalidates the pointers it reads.
 */
#ifndef BFD_XDP_TX_H
#define BFD_XDP_TX_H

#include "bfd_shared.h"
#include "tunables.h"
#include "csum.h"

static __always_inline int rx_clocked_tx(struct xdp_md *ctx,
                struct ethhdr *eth, struct iphdr *iph,
                struct ipv6hdr *ip6, struct udphdr *udp,
                struct bfd_ctrl_pkt *bfd, struct tx_cfg *cfg,
                struct session_state *st, void *data, void *data_end)
{
        	__u8 send_final = (bfd->flags & BFD_F_POLL) ? BFD_F_FINAL : 0;

        	/* L2 swap */
        	__u8 tmp[6];
        	__builtin_memcpy(tmp, eth->h_dest, 6);
        	__builtin_memcpy(eth->h_dest, eth->h_source, 6);
        	__builtin_memcpy(eth->h_source, tmp, 6);

        	/* L3 swap (checksum unaffected by swapping halves) */
        	if (iph) {
        		__be32 tip = iph->saddr;
        		iph->saddr = iph->daddr;
        		iph->daddr = tip;
        	} else if (ip6) {
        		struct in6_addr t6 = ip6->saddr;
        		ip6->saddr = ip6->daddr;
        		ip6->daddr = t6;
        	}

        	/* Multihop: this frame arrived below 255 and is being reused as
        	 * our reply, so it would leave already decremented and lose more
        	 * on the return path - the peer would then measure it against
        	 * its own minimum and reject us while we accept it, giving a
        	 * session that comes up one way only. RFC 5883 wants multihop
        	 * sent at 255 so the receiver can count hops, which is what the
        	 * userspace path already does. Single-hop frames arrive at 255
        	 * and skip this entirely. */
        	if (iph && iph->ttl != 255) {
        		__u16 ow = *(__u16 *)&iph->ttl;
	
        		iph->ttl = 255;
        		csum_replace2(&iph->check, ow, *(__u16 *)&iph->ttl);
        	} else if (ip6 && ip6->hop_limit != 255) {
        		ip6->hop_limit = 255;   /* no checksum in v6 */
        	}

        	__be16 in_dport = udp->dest;

        	/* L4: our source port, and back to the port this frame
        	 * arrived on so multihop replies reach 4784. No UDP
        	 * checksum (legal in v4). */
        	udp->source = cfg->src_port ? bpf_htons(cfg->src_port)
        				    : bpf_htons(BFD_SRC_PORT);
        	udp->dest   = in_dport;
        	udp->check  = 0;

        	/* BFD payload from config. P while a Poll sequence is
        	 * active, F when answering the peer's P; never both. */
        	bfd->vers_diag   = (1 << 5) | (cfg->diag & 0x1f);
        	bfd->flags       = ((cfg->state & 0x3) << 6) | send_final;
        	if (!send_final && cfg->poll &&
            st->final_seq != cfg->poll_seq)
        		bfd->flags |= BFD_F_POLL;
        	/* D rides alongside P or F rather than excluding them: only
        	 * P and F are mutually exclusive (s6.5). The engine has
        	 * already checked both ends are Up, which is the whole of
        	 * s6.8.6's condition. */
        	if (cfg->demand)
        		bfd->flags |= BFD_F_DEMAND;
        	bfd->detect_mult = cfg->mult;
        	bfd->len         = 24;
        	bfd->my_disc     = bpf_htonl(cfg->my_disc);
        	bfd->your_disc   = bpf_htonl(cfg->your_disc);
        	bfd->min_tx      = bpf_htonl(cfg->min_tx_us);
        	bfd->min_rx      = bpf_htonl(cfg->min_rx_us);
        	bfd->min_echo_rx = bpf_htonl(cfg->min_echo_rx_us);

        	/* Echo exactly a 24-byte control packet: a longer peer
        	 * frame (auth section, trailer) must not go back out with
        	 * trailing bytes. tot_len changes, so recompute the IP
        	 * checksum; UDP csum is already 0. On adjust_tail failure
        	 * drop: the frame is half-rewritten by now, and liveness
        	 * was already refreshed above. */
        	int want = (int)(sizeof(*eth) +
        	                 (iph ? sizeof(*iph) : sizeof(*ip6)) +
        	                 sizeof(*udp) + BFD_MIN_LEN);
        	int excess = (int)((long)data_end - (long)data) - want;
        	if (excess > 0) {
        		udp->len = bpf_htons(sizeof(*udp) + BFD_MIN_LEN);
        		if (iph) {
        			iph->tot_len = bpf_htons(sizeof(*iph) +
        			                         sizeof(*udp) + BFD_MIN_LEN);
        			iph->check = 0;
        			__u32 csum = 0;
        			__u16 *w = (__u16 *)iph;
        			for (int i = 0; i < 10; i++)
        				csum += w[i];
        			csum = (csum & 0xffff) + (csum >> 16);
        			csum = (csum & 0xffff) + (csum >> 16);
        			iph->check = ~csum & 0xffff;
        		} else if (ip6) {
        			ip6->payload_len = bpf_htons(sizeof(*udp) +
        			                             BFD_MIN_LEN);
        		}
        	}

        	/* v6: mandatory UDP checksum over pseudo-header + UDP header
        	 * + the 24-byte payload. Swaps are csum-neutral but the
        	 * payload rewrite is not, so recompute in full. Fixed 34-word
        	 * fold, pointers bounds-proven above. Runs before adjust_tail
        	 * (which invalidates pointers); the fold never reads past
        	 * payload byte 24, which survives the trim. */
        	if (ip6) {
        		__u32 csum = 0;
        		__u16 *w = (__u16 *)&ip6->saddr;
        		for (int i = 0; i < 16; i++)   /* saddr + daddr */
        			csum += w[i];
        		csum += udp->len;              /* pseudo length */
        		csum += bpf_htons(IPPROTO_UDP);
        		w = (__u16 *)udp;              /* UDP hdr, check == 0 */
        		for (int i = 0; i < 4; i++)
        			csum += w[i];
        		w = (__u16 *)bfd;              /* 24-byte payload */
        		for (int i = 0; i < 12; i++)
        			csum += w[i];
        		csum = (csum & 0xffff) + (csum >> 16);
        		csum = (csum & 0xffff) + (csum >> 16);
        		__u16 c = ~csum & 0xffff;
        		udp->check = c ? c : 0xffff;   /* RFC 768: 0 -> 0xffff */
        	}

        	if (excess > 0 && bpf_xdp_adjust_tail(ctx, -excess))
        		return XDP_DROP;

        	st->tx_pkts++;
        	return XDP_TX;
}

#endif /* BFD_XDP_TX_H */
