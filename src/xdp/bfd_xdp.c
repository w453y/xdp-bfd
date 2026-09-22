// SPDX-License-Identifier: GPL-2.0
/* bfd_xdp.c - packet parse, RX-clocked TX, echo reflection, and the
 * kernel-side detection sweep. */

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
#include "tunables.h"
#include "maps.h"
#include "stats.h"
#include "parse.h"
#include "validate.h"
#include "auth.h"
#include "sweep.h"
#include "csum.h"
#include "echo.h"
#include "tx.h"

SEC("xdp")
int bfd_observer(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	count(BFD_STAT_SEEN);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;


	struct l3ctx c = {};
	int pv = parse_l3(eth, data_end, &c);
	if (pv >= 0)
		return pv;
	struct iphdr *iph = c.iph;
	struct ipv6hdr *ip6 = c.ip6;
	struct udphdr *udp = c.udp;

	/* Echo reflection (RFC 5880 s6.4): return a self-addressed UDP/3785
	 * packet to its originator. Swap MACs and decrement TTL 255->254,
	 * which the originator's GTSM expects; nothing else changes. */
	if (udp->dest == bpf_htons(BFD_ECHO_PORT)) {
		if (ip6)
			return echo_reflect_v6(eth, ip6, udp, data_end);
		if (!iph)
			return XDP_PASS;
	        return echo_reflect_v4(eth, iph, udp, data_end);
	}

	/* Single-hop (3784) and multihop (4784, RFC 5883) both land here.
	 * The reply below goes back to whichever port it arrived on. */
	if (udp->dest != bpf_htons(BFD_PORT_1HOP) &&
	    udp->dest != bpf_htons(BFD_PORT_MHOP))
		return XDP_PASS;

	struct bfd_ctrl_pkt *bfd = (void *)(udp + 1);
	if ((void *)(bfd + 1) > data_end) {
		count(BFD_STAT_MALFORMED);
		return XDP_DROP;
	}
	/* The UDP length must match the frame received, or a short frame could
	 * claim a longer packet. Dropped as malformed: nothing but our socket
	 * consumes the BFD ports. */
	{
		__u32 have = (__u32)((long)data_end - (long)udp);
		__u16 ulen = bpf_ntohs(udp->len);

		if (ulen < sizeof(*udp) || (__u32)ulen > have) {
			count(BFD_STAT_MALFORMED);
			return XDP_DROP;
		}
		if (iph) {
			__u32 ihave = (__u32)((long)data_end - (long)iph);
			__u16 tot = bpf_ntohs(iph->tot_len);

			if (tot < sizeof(*iph) + sizeof(*udp) ||
			    (__u32)tot > ihave) {
				count(BFD_STAT_MALFORMED);
				return XDP_DROP;
			}
		} else if (ip6) {
			__u32 phave = (__u32)((long)data_end - (long)(ip6 + 1));
			__u16 plen = bpf_ntohs(ip6->payload_len);

			if (plen < sizeof(*udp) || (__u32)plen > phave) {
				count(BFD_STAT_MALFORMED);
				return XDP_DROP;
			}
		}
	}

	/* Only sessions the control plane configured are tracked, unless the
	 * loader asked for promiscuous mode. Looked up before header
	 * validation because whether the A bit is allowed depends on the
	 * session; the key comes from addresses already parsed. */
	struct tx_cfg *cfg = bpf_map_lookup_elem(&tx_config, &c.key);

	int hv = bfd_hdr_verdict(bfd, udp, cfg ? cfg->auth_present : 0);
	if (hv >= 0)
		return hv;

	count(BFD_STAT_WELL_FORMED);

	/* Deferred GTSM: a packet below TTL 255 is accepted only for a
	 * configured session whose minimum admits it. Before the promiscuous
	 * PASS, which is for observation and must not relax GTSM. */
	{
		__u8 pttl = iph ? iph->ttl : (ip6 ? ip6->hop_limit : 0);

		if (pttl != 255) {
			__u32 mt = (cfg && cfg->min_ttl) ? cfg->min_ttl : 255;

			if (!cfg || pttl < mt) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
		}
	}

	if (!cfg) {
		__u32 zero = 0;
		__u32 *fl = bpf_map_lookup_elem(&prog_flags, &zero);
		/* A valid control packet for an unconfigured address pair:
		 * drop it, so a flood cannot fill the socket queue ahead of
		 * sessions coming up. The promiscuous flag keeps XDP_PASS for
		 * bfd_loader, a debugging tool. */
		if (!fl || !(*fl & 1)) {
			count(BFD_STAT_UNKNOWN_SESSION);
			return XDP_DROP;
		}
	}

	/* Demux (RFC 5880 s6.8.6): your_disc names our session, or is 0 with
	 * the peer in Down/AdminDown. A failing packet must not refresh
	 * liveness or be answered. */
	__u8 rstate = BFD_STATE(bfd);
	if (cfg && cfg->my_disc) {
		__u32 ydisc = bpf_ntohl(bfd->your_disc);
		if (ydisc != cfg->my_disc &&
		    !(ydisc == 0 && rstate <= 1)) {
			count(BFD_STAT_REJECTED);
			return XDP_DROP;
		}
	}

	ensure_sweeper();

	struct session_state *st = bpf_map_lookup_elem(&bfd_sessions, &c.key);
	if (!st) {
		struct session_state init = {};
		bpf_map_update_elem(&bfd_sessions, &c.key, &init, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&bfd_sessions, &c.key);
		if (!st)
			return XDP_PASS;
	}

	/* Authentication (RFC 5880 s6.7), after demux and before anything in
	 * the packet is believed. */
	struct auth_scratch *asc = NULL;

	/* auth_present, not auth_type: verification uses the accept set, so it
	 * runs even with no send key. */
	if (cfg && cfg->auth_present) {
		__u32 azero = 0;
		__u64 anow = bpf_ktime_get_ns();
		__u64 awin = (__u64)(st->detect_iv_us ? st->detect_iv_us
						      : cfg->min_rx_us) * 1000;

		/* Bound the HMACs a forger can force: after BFD_AUTH_FAIL_MAX
		 * digest failures in a detect interval, drop further A-bit
		 * packets for this session before hashing. A flood can take
		 * this one session down; the bucket is per session, so the
		 * others are untouched. */
		if (anow - st->auth_fail_ts > awin) {
			st->auth_fail_ts = anow;
			st->auth_fail_n = 0;
		}
		if (st->auth_fail_n >= BFD_AUTH_FAIL_MAX) {
			count(BFD_STAT_AUTH_RATELIMITED);
			return XDP_DROP;
		}

		asc = bpf_map_lookup_elem(&auth_scratch, &azero);
		/* The capability check belongs to the send key, because it
		 * decides what we could BUILD. With no send key there is
		 * nothing to build and the accept set still verifies. */
		if (!asc || (cfg->auth_type && !xdp_auth_fast(cfg)) ||
		    !xdp_auth_verify(ctx, iph ? BFD_OFF_V4 : BFD_OFF_V6,
				     bfd, cfg, st, asc)) {
			st->auth_fail_n++;
			count(BFD_STAT_AUTH_BAD);
			return XDP_DROP;
		}
	}

	__u64 now = bpf_ktime_get_ns();

	/* Poll-aware detect basis (RFC 5880 s6.8.3): increases apply at once,
	 * decreases only once the observed gap fits the new interval. */
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

	/* Not atomic: RSS keeps one session on one CPU. Generic XDP with RPS
	 * could break that, at worst accepting one replayed packet. */
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
	st->remote_flags = bfd->flags & 0x3f;
	st->detect_mult  = bfd->detect_mult;

	/* Poll termination (RFC 5880 s6.8.4): ack via the kernel-owned
	 * final_seq, since tx_cfg belongs to userspace. The F carries no
	 * sequence, so it ends whichever Poll is current. */
	if (cfg && cfg->poll && (bfd->flags & BFD_F_FINAL))
		st->final_seq = cfg->poll_seq;

	if (__sync_val_compare_and_swap(&st->alive, 0, 1) == 0)
		emit(&c.key, st, now, 1);

	/* RX-clocked TX: rewrite this frame into our reply and bounce it, in
	 * softirq. Not while the peer says Down or AdminDown, and not for a
	 * session that must authenticate but has no sendable key. */
	if (cfg && cfg->enable && rstate >= 2 &&
	    !(cfg->auth_present && !xdp_auth_fast(cfg))) {
	        /* Dead-man gate: stop answering once the engine stops beating,
	         * so a wedged engine cannot hold sessions Up. The peer's own
	         * detection then decides. */
	        if (deadman_tripped(now)) {
	                count(BFD_STAT_DEADMAN_HOLD);
	                return XDP_PASS;
	        }
	        return rx_clocked_tx(ctx, eth, iph, ip6, udp,
	                             bfd, cfg, st, asc, data, data_end);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
