// SPDX-License-Identifier: GPL-2.0
/* bfd_xdp.c v2 - observer + kernel-side detection sweep. */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "bfd_shared.h"

/* Split out of this file; maps.h must come first (see src/xdp). */
#include "wire.h"
#include "maps.h"
#include "stats.h"
#include "sweep.h"
#include "csum.h"
#include "echo.h"
#include "tx.h"

SEC("xdp")
int bfd_observer(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	count(0);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	__u16 proto = eth->h_proto;

	struct udphdr *udp;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6 = NULL;
	struct session_key key = {};

	if (proto == bpf_htons(ETH_P_IP)) {
		iph = (void *)(eth + 1);
		if ((void *)(iph + 1) > data_end)
			return XDP_PASS;
		if (iph->protocol != IPPROTO_UDP)
			return XDP_PASS;
		/* IP options (ihl != 5) on a UDP packet: a single-hop BFD
		 * control packet never carries them. Passing would skip the
		 * GTSM/your_disc checks below (UDP header sits at a variable
		 * offset with options) and leak the packet to the userspace
		 * socket unvalidated - the same bypass class as an XDP_PASS
		 * reject. Drop it. */
		if (iph->ihl != 5) {
			count(3);
			return XDP_DROP;
		}
		udp = (void *)(iph + 1);
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		/* GTSM (RFC 5881 s5): single-hop control packets MUST arrive
		 * with TTL 255. Anything else is off-link or spoofed. The one
		 * exception is our own echo coming back: the neighbour's
		 * forwarding plane decremented it to 254, and the frame is
		 * still self-addressed to us on the echo port. Kept narrow so
		 * it cannot become a general TTL bypass. */
		if (iph->ttl != 255 &&
		    !(udp->dest == bpf_htons(BFD_ECHO_PORT) &&
		      iph->ttl == 254 && iph->saddr == iph->daddr)) {
			/* Not single-hop and not our own echo returning. If no
			 * multihop session exists on this box the packet is
			 * off-link or spoofed, so drop it here as before - that
			 * keeps the cheap early filter for the common case. With
			 * multihop configured the verdict needs the session's own
			 * minimum, which is only known after the config lookup. */
			__u32 mz = 0;
			__u32 *mf = bpf_map_lookup_elem(&prog_flags, &mz);
			if (!mf || !(*mf & 2)) {
				count(3);
				return XDP_DROP;
			}
		}
		key_set_v4(&key.peer,  iph->saddr);
		key_set_v4(&key.local, iph->daddr);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;
		/* Non-UDP first header: ICMPv6 (ND/MLD/RA), or UDP hidden
		 * behind extension headers we deliberately don't walk. PASS to
		 * the stack either way - this mirrors the v4 non-UDP PASS.
		 * DROPping here kills v6 neighbour discovery. A UDP-behind-
		 * extheaders packet to the BFD port is left to userspace GTSM
		 * (IPV6_MINHOPCOUNT) and demux; single-hop BFD never sends one. */
		if (ip6->nexthdr != IPPROTO_UDP)
			return XDP_PASS;
		/* GTSM: hop_limit is the v6 TTL. */
		if (ip6->hop_limit != 255) {
			__u32 mz = 0;
			__u32 *mf = bpf_map_lookup_elem(&prog_flags, &mz);
			if (!mf || !(*mf & 2)) {
				count(3);
				return XDP_DROP;
			}
		}
		udp = (void *)(ip6 + 1);
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		key_set_v6(&key.peer,  &ip6->saddr);
		key_set_v6(&key.local, &ip6->daddr);
	} else {
		return XDP_PASS;
	}

	/* Echo reflection (RFC 5880 s6.4): a self-addressed UDP/3785
	 * packet from a neighbor whose forwarding plane is us. Return it
	 * to the originator from the driver: swap MAC, decrement TTL
	 * 255->254 (the originator's GTSM requires 254 inbound), leave
	 * IP/UDP/BFD untouched (already addressed to the originator).
	 * No session lookup, no map, no adjust_tail. */
	if (udp->dest == bpf_htons(BFD_ECHO_PORT)) {
		if (ip6)
			return echo_reflect_v6(eth, ip6);
		if (!iph)
			return XDP_PASS;
	        return echo_reflect_v4(eth, iph, udp, data_end);
	}

	/* Single-hop (3784) and multihop (4784, RFC 5883) both land here.
	 * The reply below goes back to whichever port it arrived on. */
	if (udp->dest != bpf_htons(BFD_PORT_1HOP) &&
	    udp->dest != bpf_htons(BFD_PORT_MHOP))
		return XDP_PASS;

	struct bfdhdr *bfd = (void *)(udp + 1);
	if ((void *)(bfd + 1) > data_end) {
		count(2);
		return XDP_PASS;
	}
	if (BFD_VERS(bfd) != BFD_VERSION || bfd->len < BFD_MIN_LEN ||
	    bfd->detect_mult == 0 || bfd->my_disc == 0) {
		count(2);
		return XDP_PASS;
	}
	__u16 udp_len = bpf_ntohs(udp->len);
	if (udp_len < sizeof(*udp) + BFD_MIN_LEN ||
	    bfd->len > udp_len - sizeof(*udp)) {
		count(2);
		return XDP_PASS;
	}

	count(1);

	/* Only track sessions the control plane configured, unless the
	 * standalone loader asked for promiscuous observation. Stops
	 * unsolicited packets from filling the session map. */
	struct tx_cfg *cfg = bpf_map_lookup_elem(&tx_config, &key);
	if (!cfg) {
		__u32 zero = 0;
		__u32 *fl = bpf_map_lookup_elem(&prog_flags, &zero);
		if (!fl || !(*fl & 1))
			return XDP_PASS;
	}

	/* Deferred GTSM. A control packet that did not arrive at 255 is
	 * acceptable only if it names a configured session whose minimum
	 * admits it. An unconfigured pair must still drop: the
	 * promiscuous PASS above exists for observation, not to relax
	 * GTSM. Single-hop sessions carry min_ttl 255, so nothing below
	 * 255 reaches them and their behaviour is unchanged. */
	{
		__u8 pttl = iph ? iph->ttl : (ip6 ? ip6->hop_limit : 0);
	
		if (pttl != 255) {
			__u32 mt = (cfg && cfg->min_ttl) ? cfg->min_ttl : 255;
	
			if (!cfg || pttl < mt) {
				count(3);
				return XDP_DROP;
			}
		}
	}

	/* Demux validation (RFC 5880 s6.8.6): your_disc must name our
	 * session, or be 0 with the peer in Down/AdminDown (peer lost
	 * state / restarting). A packet failing this must not refresh
	 * liveness or be echoed - that is how spoofed traffic keeps a
	 * dead session up. */
	__u8 rstate = BFD_STATE(bfd);
	if (cfg && cfg->my_disc) {
		__u32 ydisc = bpf_ntohl(bfd->your_disc);
		if (ydisc != cfg->my_disc &&
		    !(ydisc == 0 && rstate <= 1)) {
			count(3);
			return XDP_DROP;
		}
	}

	ensure_sweeper();

	struct session_state *st = bpf_map_lookup_elem(&bfd_sessions, &key);
	if (!st) {
		struct session_state init = {};
		bpf_map_update_elem(&bfd_sessions, &key, &init, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&bfd_sessions, &key);
		if (!st)
			return XDP_PASS;
	}

	__u64 now = bpf_ktime_get_ns();

	/* Poll-aware detect basis (RFC 5880 s6.8.3): a peer that lowers
	 * its advertised min_tx keeps transmitting at the old rate until
	 * its Poll sequence terminates. Shrinking our detect budget on
	 * the advertisement alone guarantees a false timeout, so:
	 * increases apply immediately (always safe, larger budget);
	 * decreases apply only once the observed inter-arrival gap fits
	 * the new interval, i.e. the peer is actually pacing at it. */
	{
		__u32 local_rx = LOCAL_MIN_RX_US;
		if (cfg && cfg->min_rx_us)
			local_rx = cfg->min_rx_us;
		__u32 cand = bpf_ntohl(bfd->min_tx);
		if (cand < local_rx)
			cand = local_rx;
		if (!st->alive || !st->detect_iv_us ||
		    cand >= st->detect_iv_us)
			st->detect_iv_us = cand;
		else if (now - st->last_seen_ns <= (__u64)cand * 1000ull)
			st->detect_iv_us = cand;
	}

	st->last_seen_ns = now;
	st->rx_pkts++;
	__builtin_memcpy(st->peer_mac, eth->h_source, 6);
	st->mac_valid = 1;
	st->remote_disc  = bpf_ntohl(bfd->my_disc);
	st->local_disc   = bpf_ntohl(bfd->your_disc);
	st->min_tx_us    = bpf_ntohl(bfd->min_tx);
	st->min_rx_us    = bpf_ntohl(bfd->min_rx);
	st->remote_min_echo_us = bpf_ntohl(bfd->min_echo_rx);
	st->remote_state = BFD_STATE(bfd);
	st->remote_diag  = BFD_DIAG(bfd);
	st->detect_mult  = bfd->detect_mult;

	/* Poll termination (RFC 5880 s6.8.4): peer answered our P with
	 * F. tx_cfg is userspace-owned, so ack via kernel-owned
	 * final_seq instead of clearing cfg->poll in place (a racing
	 * userspace mirror push could resurrect the finished poll). */
	if (cfg && cfg->poll && (bfd->flags & BFD_F_FINAL))
		st->final_seq = cfg->poll_seq;

	if (__sync_val_compare_and_swap(&st->alive, 0, 1) == 0)
		emit(&key, st, now, 1);

	/* RX-clocked TX: rewrite this very frame into our control packet
	 * and bounce it. Peer's clock becomes our clock; runs in softirq.
	 * Never echo Up at a peer that just said Down/AdminDown; let
	 * userspace run the transition. */
	if (cfg && cfg->enable && rstate >= 2) {
	        return rx_clocked_tx(ctx, eth, iph, ip6, udp,
	                             bfd, cfg, st, data, data_end);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
