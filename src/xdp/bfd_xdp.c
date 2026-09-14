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

	/* Echo reflection (RFC 5880 s6.4): a self-addressed UDP/3785
	 * packet from a neighbor whose forwarding plane is us. Return it
	 * to the originator from the driver: swap MAC, decrement TTL
	 * 255->254 (the originator's GTSM requires 254 inbound), leave
	 * IP/UDP/BFD untouched (already addressed to the originator).
	 * No session lookup, no map, no adjust_tail. */
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
		return XDP_PASS;
	}
	/* The envelope has to describe the frame that arrived.
	 *
	 * bfd_ctrl_check derives the payload length from udp->len, which is
	 * whatever the sender wrote, and nothing had compared it against
	 * what was actually received. A frame carrying 24 bytes while
	 * claiming 200 was accepted: no overread, since every field read
	 * here is inside the header already bounds-checked above, but it
	 * refreshed liveness and could acknowledge a Poll on a packet that
	 * is not what it says it is.
	 *
	 * MALFORMED and PASS, like a broken BFD header: a length that does
	 * not match the frame is not evidence of an attack, and the stack
	 * applies the same rule and will reject it too.
	 */
	{
		__u32 have = (__u32)((long)data_end - (long)udp);
		__u16 ulen = bpf_ntohs(udp->len);

		if (ulen < sizeof(*udp) || (__u32)ulen > have) {
			count(BFD_STAT_MALFORMED);
			return XDP_PASS;
		}
		if (iph) {
			__u32 ihave = (__u32)((long)data_end - (long)iph);
			__u16 tot = bpf_ntohs(iph->tot_len);

			if (tot < sizeof(*iph) + sizeof(*udp) ||
			    (__u32)tot > ihave) {
				count(BFD_STAT_MALFORMED);
				return XDP_PASS;
			}
		} else if (ip6) {
			__u32 phave = (__u32)((long)data_end - (long)(ip6 + 1));
			__u16 plen = bpf_ntohs(ip6->payload_len);

			if (plen < sizeof(*udp) || (__u32)plen > phave) {
				count(BFD_STAT_MALFORMED);
				return XDP_PASS;
			}
		}
	}

	/* Only track sessions the control plane configured, unless the
	 * standalone loader asked for promiscuous observation. Stops
	 * unsolicited packets from filling the session map.
	 *
	 * Looked up before the header is validated because one of the
	 * acceptance rules is not a property of the packet: whether the A
	 * bit belongs there depends on whether this session has a key. The
	 * lookup keys on addresses that parse_l3 has already read, so
	 * nothing in the BFD header is trusted to do it. */
	struct tx_cfg *cfg = bpf_map_lookup_elem(&tx_config, &c.key);

	int hv = bfd_hdr_verdict(bfd, udp, cfg ? cfg->auth_present : 0);
	if (hv >= 0)
		return hv;

	count(BFD_STAT_WELL_FORMED);

	/* Deferred GTSM. A control packet that did not arrive at 255 is
	 * acceptable only if it names a configured session whose minimum
	 * admits it. This runs BEFORE the promiscuous PASS below: with a
	 * multihop session configured, prog_flags bit 2 tells parse_l3 to
	 * defer the TTL verdict, and an off-link packet naming an address
	 * pair we do not have would otherwise reach the stack. The
	 * promiscuous PASS exists for observation, not to relax GTSM.
	 * Single-hop sessions carry min_ttl 255 and are unaffected. */
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
		if (!fl || !(*fl & 1))
			return XDP_PASS;
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

	/* RFC 5880 s6.7, before anything about this packet is believed: an
	 * unverified packet must not refresh liveness, must not update the
	 * peer's parameters, and must not be answered. Checked after the
	 * demux above so a forged discriminator cannot reach the digest,
	 * and before the state below so a failure leaves no trace of the
	 * packet having arrived. */
	struct auth_scratch *asc = NULL;

	/* auth_present, not auth_type. Verification does not need a key we
	 * may send under: xdp_auth_verify reads the type and key id the
	 * PACKET names and matches them against auth_accept, which is the
	 * set the engine left for exactly this. Gating on the send key meant
	 * that a session in a rollover gap, with nothing to transmit under
	 * and a perfectly good accept set, skipped verification entirely and
	 * took the packet on trust. */
	if (cfg && cfg->auth_present) {
		__u32 azero = 0;

		asc = bpf_map_lookup_elem(&auth_scratch, &azero);
		/* The capability check belongs to the send key, because it
		 * decides what we could BUILD. With no send key there is
		 * nothing to build and the accept set still verifies. */
		if (!asc || (cfg->auth_type && !xdp_auth_fast(cfg)) ||
		    !xdp_auth_verify(ctx, iph ? BFD_OFF_V4 : BFD_OFF_V6,
				     bfd, cfg, st, asc)) {
			count(BFD_STAT_AUTH_BAD);
			return XDP_DROP;
		}
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
	st->remote_flags = bfd->flags & 0x3f;
	st->detect_mult  = bfd->detect_mult;

	/* Poll termination (RFC 5880 s6.8.4): peer answered our P with
	 * F. tx_cfg is userspace-owned, so ack via kernel-owned
	 * final_seq instead of clearing cfg->poll in place (a racing
	 * userspace mirror push could resurrect the finished poll). */
	if (cfg && cfg->poll && (bfd->flags & BFD_F_FINAL))
		st->final_seq = cfg->poll_seq;

	if (__sync_val_compare_and_swap(&st->alive, 0, 1) == 0)
		emit(&c.key, st, now, 1);

	/* RX-clocked TX: rewrite this very frame into our control packet
	 * and bounce it. Peer's clock becomes our clock; runs in softirq.
	 * Never echo Up at a peer that just said Down/AdminDown; let
	 * userspace run the transition. */
	/* An authenticated session with no key to sign with cannot be
	 * answered from here: the reply is built from auth_type, so it would
	 * go out bare on a session whose peer must reject it. Userspace
	 * declines to send in the same state (auth_fast_capable), and this
	 * is the program's half of that agreement rather than a trust in
	 * the mirror having set enable correctly. */
	if (cfg && cfg->enable && rstate >= 2 &&
	    !(cfg->auth_present && !xdp_auth_fast(cfg))) {
	        /* Unless the engine has stopped saying it is there.
	         *
	         * Answering from softirq is what makes detection independent
	         * of the loop, and it is also what lets a wedged engine lie:
	         * the program keeps replying on the peer's clock whether or
	         * not anything upstairs is still running, so a control plane
	         * that is alive but making no progress presents Up sessions
	         * to the whole network indefinitely. Measured, not supposed -
	         * with the engine held in T state for twenty seconds, 57 of
	         * 64 sessions stayed Up with the peer receiving at full rate.
	         * That is exactly the lie BFD exists to prevent, arriving by
	         * way of the optimisation.
	         *
	         * So the fast path answers on the engine's behalf only while
	         * the engine is there to be answered for. Withholding the
	         * reply does not take the session down here; it lets the peer
	         * reach its own conclusion by its own detection timer, which
	         * is the peer's decision to make and needs no new protocol.
	         */
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
