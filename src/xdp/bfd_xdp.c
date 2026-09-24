// SPDX-License-Identifier: GPL-2.0
/* bfd_xdp.c - parse, RX-clocked TX, echo reflection and the detection sweep. */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "bfd_shared.h"

/* maps.h first: the rest reference maps. */
#include "tunables.h"
#include "maps.h"
#include "stats.h"
#include "parse.h"
#include "validate.h"
#include "auth.h"
#include "sweep.h"
#include "echo.h"
#include "tx.h"

#define TX_CFG_HEAD  __builtin_offsetof(struct tx_cfg, key)
#define TX_CFG_WORDS ((__builtin_offsetof(struct tx_cfg, auth_accept) - TX_CFG_HEAD) / 4)
#define TX_KEY_WORDS (sizeof(struct xdp_auth_key) / 4)

/* NULL if the key has no entry, or its entry was freed and reused meanwhile.
 * Copies only the accept keys in use: all sixteen double a reply's cost.
 */
static __always_inline struct tx_cfg *tx_cfg_get(const struct session_key *k)
{
	struct tx_cfg *live = bpf_map_lookup_elem(&tx_config, k);
	__u32 zero = 0;
	struct tx_cfg *c;

	if (!live)
		return NULL;
	c = bpf_map_lookup_elem(&tx_snap, &zero);
	if (!c)
		return NULL;

	__u32 *dst = (__u32 *)((__u8 *)c + TX_CFG_HEAD);
	const __u32 *src = (const __u32 *)((const __u8 *)live + TX_CFG_HEAD);
	__u32 *kdst = (__u32 *)c->auth_accept;
	const __u32 *ksrc = (const __u32 *)live->auth_accept;
	__u32 n;

	bpf_spin_lock(&live->lock);
#pragma unroll
	for (int i = 0; i < (int)TX_CFG_WORDS; i++)
		dst[i] = src[i];
	n = c->auth_nkeys;
	if (n > BFD_AUTH_ACCEPT_MAX)
		n = BFD_AUTH_ACCEPT_MAX;
	/* The second bound is for the verifier. */
	for (__u32 i = 0; i < n * TX_KEY_WORDS && i < BFD_AUTH_ACCEPT_MAX * TX_KEY_WORDS; i++)
		kdst[i] = ksrc[i];
	bpf_spin_unlock(&live->lock);

	const __u32 *a = (const __u32 *)&c->key, *b = (const __u32 *)k;
	__u32 diff = 0;

#pragma unroll
	for (int i = 0; i < (int)(sizeof(*k) / 4); i++)
		diff |= a[i] ^ b[i];
	return diff ? NULL : c;
}

SEC("xdp")
int bfd_observer(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
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

	/* RFC 5880 s6.4: return a self-addressed echo to its originator at TTL
	 * 254, which its GTSM expects; and a v6 one sent to us, as bfdd does.
	 */
	if (udp->dest == bpf_htons(BFD_ECHO_PORT)) {
		if (ip6)
			return echo_reflect_v6(eth, ip6, udp, data_end);
		if (!iph)
			return XDP_PASS;
		return echo_reflect_v4(eth, iph, udp, data_end);
	}

	/* Single-hop 3784 and multihop 4784 (RFC 5883); the reply uses the arrival port. */
	if (udp->dest != bpf_htons(BFD_PORT_1HOP) && udp->dest != bpf_htons(BFD_PORT_MHOP))
		return XDP_PASS;

	struct bfd_ctrl_pkt *bfd = (void *)(udp + 1);

	if ((void *)(bfd + 1) > data_end) {
		count(BFD_STAT_MALFORMED);
		return XDP_DROP;
	}
	/* The lengths must fit the frame, or a short frame could claim a longer
	 * packet. Nothing else consumes the BFD ports, so drop.
	 */
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

			if (tot < sizeof(*iph) + sizeof(*udp) || (__u32)tot > ihave) {
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

	/* Before header validation: whether the A bit is allowed depends on the session. */
	struct tx_cfg *cfg = tx_cfg_get(&c.key);

	int hv = bfd_hdr_verdict(bfd, udp, cfg ? cfg->auth_present : 0);

	if (hv >= 0)
		return hv;

	count(BFD_STAT_WELL_FORMED);

	/* RFC 5880 s6.3: a nonzero Your Discriminator alone selects the session,
	 * so when the address pair misses, userspace demuxes on it, within a
	 * per-CPU budget: a forger who has seen a discriminator must not be
	 * able to flood the socket.
	 */
	if (!cfg && bfd->your_disc) {
		__u32 yd = bpf_ntohl(bfd->your_disc), zero = 0;

		if (bpf_map_lookup_elem(&our_discs, &yd)) {
			struct moved_budget *mb = bpf_map_lookup_elem(&moved_budget, &zero);
			__u64 now = bpf_ktime_get_ns();

			if (!mb)
				return XDP_DROP;
			if (now - mb->win_ns > MOVED_WIN_NS) {
				mb->win_ns = now;
				mb->n = 0;
			}
			if (mb->n < MOVED_MAX) {
				mb->n++;
				return XDP_PASS;
			}
			count(BFD_STAT_MOVED_RATELIMITED);
			return XDP_DROP;
		}
	}

	/* Deferred GTSM: below 255 only for a configured session whose minimum
	 * admits it. Before the promiscuous PASS, which must not relax it.
	 */
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

	/* The port names the session type: 3784 single-hop, 4784 multihop. */
	if (cfg && (udp->dest == bpf_htons(BFD_PORT_MHOP)) != !!cfg->mhop) {
		count(BFD_STAT_REJECTED);
		return XDP_DROP;
	}

	if (!cfg) {
		__u32 zero = 0;
		__u32 *fl = bpf_map_lookup_elem(&prog_flags, &zero);
		/* Drop, so a flood cannot fill the socket queue ahead of
		 * sessions coming up. bfd_loader sets the promiscuous flag.
		 */
		if (!fl || !(*fl & 1)) {
			count(BFD_STAT_UNKNOWN_SESSION);
			return XDP_DROP;
		}
	}

	/* RFC 5880 s6.8.6: your_disc names us, or is 0 with the peer Down or AdminDown. */
	__u8 rstate = BFD_STATE(bfd);

	if (cfg && cfg->my_disc) {
		__u32 ydisc = bpf_ntohl(bfd->your_disc);

		if (ydisc != cfg->my_disc && !(ydisc == 0 && rstate <= 1)) {
			count(BFD_STAT_REJECTED);
			return XDP_DROP;
		}
	}

	ensure_sweeper();

	struct session_state *st = bpf_map_lookup_elem(&bfd_sessions, &c.key);

	if (!st) {
		__u32 z = 0;
		struct session_state *init = bpf_map_lookup_elem(&state_zero, &z);

		if (!init)
			return XDP_PASS;
		bpf_map_update_elem(&bfd_sessions, &c.key, init, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&bfd_sessions, &c.key);
		if (!st)
			return XDP_PASS;
	}

	/* RFC 5880 s6.7, after demux and before anything in the packet is believed. */
	struct auth_scratch *asc = NULL;

	/* The accept set verifies even with no send key. */
	if (cfg && cfg->auth_present) {
		__u32 azero = 0;
		__u64 anow = bpf_ktime_get_ns();
		__u64 awin = (__u64)(st->detect_iv_us ? st->detect_iv_us : cfg->min_rx_us) * 1000;

		/* After BFD_AUTH_FAIL_MAX digest failures in a detect interval,
		 * drop A-bit packets for this session before hashing. A flood
		 * can take this one session down, no other.
		 */
		if (anow - st->auth_fail_ts > awin) {
			st->auth_fail_ts = anow;
			st->auth_fail_n = 0;
		}
		if (st->auth_fail_n >= BFD_AUTH_FAIL_MAX) {
			count(BFD_STAT_AUTH_RATELIMITED);
			return XDP_DROP;
		}

		asc = bpf_map_lookup_elem(&auth_scratch, &azero);
		/* Only a send key needs the capability check; the accept set
		 * verifies without one.
		 */
		if (!asc || (cfg->auth_type && !xdp_auth_fast(cfg)) ||
		    !xdp_auth_verify(ctx, iph ? BFD_OFF_V4 : BFD_OFF_V6, bfd, cfg, st, asc)) {
			st->auth_fail_n++;
			count(BFD_STAT_AUTH_BAD);
			return XDP_DROP;
		}
	}

	__u64 now = bpf_ktime_get_ns();

	/* RFC 5880 s6.8.3: increases apply at once, decreases once the gap fits. */
	{
		__u32 local_rx = LOCAL_MIN_RX_US;

		if (cfg && cfg->min_rx_us)
			local_rx = cfg->min_rx_us;
		__u32 cand = bpf_ntohl(bfd->min_tx);

		if (cand < local_rx)
			cand = local_rx;
		if (!st->alive || !st->detect_iv_us || cand >= st->detect_iv_us)
			st->detect_iv_us = cand;
		else if (now - st->last_seen_ns <= (__u64)cand * 1000ull)
			st->detect_iv_us = cand;
	}

	/* What the engine mirrors and would otherwise have to poll for. */
	int changed = !st->last_seen_ns || st->remote_state != BFD_STATE(bfd) ||
		      st->remote_flags != (bfd->flags & 0x3f) ||
		      st->detect_mult != bfd->detect_mult ||
		      st->min_tx_us != bpf_ntohl(bfd->min_tx) ||
		      st->min_rx_us != bpf_ntohl(bfd->min_rx) ||
		      st->remote_min_echo_us != bpf_ntohl(bfd->min_echo_rx) ||
		      st->remote_disc != bpf_ntohl(bfd->my_disc);

	/* Not atomic: RSS keeps a session on one CPU. Generic XDP with RPS
	 * could accept one replayed packet.
	 */
	st->last_seen_ns = now;
	st->rx_pkts++;
	__builtin_memcpy(st->peer_mac, eth->h_source, 6);
	st->mac_valid = 1;
	st->remote_disc = bpf_ntohl(bfd->my_disc);
	st->local_disc = bpf_ntohl(bfd->your_disc);
	st->min_tx_us = bpf_ntohl(bfd->min_tx);
	st->min_rx_us = bpf_ntohl(bfd->min_rx);
	st->remote_min_echo_us = bpf_ntohl(bfd->min_echo_rx);
	st->remote_state = BFD_STATE(bfd);
	st->remote_diag = BFD_DIAG(bfd);
	st->remote_flags = bfd->flags & 0x3f;
	st->detect_mult = bfd->detect_mult;

	/* RFC 5880 s6.8.4: ack through the kernel-owned final_seq; tx_cfg belongs to userspace. */
	if (cfg && cfg->poll && (bfd->flags & BFD_F_FINAL) && st->final_seq != cfg->poll_seq) {
		st->final_seq = cfg->poll_seq;
		changed = 1;
	}
	if (changed)
		st->chg_pending = 1;
	if (st->chg_pending && now - st->chg_emit_ns >= CHANGE_MIN_NS) {
		st->chg_pending = 0;
		st->chg_emit_ns = now;
		emit_change(&c.key, now);
	}

	if (__sync_val_compare_and_swap(&st->alive, 0, 1) == 0)
		emit(&c.key, st, now, BFD_EV_ALIVE);

	/* RFC 5880 s6.8.7: the peer sends no faster than our Required Min RX,
	 * jitter included, so twice that is a forger. The packet has counted
	 * above; it is neither answered nor passed up, so a flood can fill
	 * neither the transmit ring nor the socket. Poll and Final are exempt,
	 * within a budget of their own.
	 */
	if (cfg) {
		if (bfd->flags & (BFD_F_POLL | BFD_F_FINAL)) {
			if (now - st->pf_win_ns > PF_WIN_NS) {
				st->pf_win_ns = now;
				st->pf_n = 0;
			}
			if (st->pf_n >= PF_MAX) {
				count(BFD_STAT_TOO_FAST);
				return XDP_DROP;
			}
			st->pf_n++;
		} else if (now - st->last_act_ns < (__u64)cfg->min_rx_us * 500ull) {
			count(BFD_STAT_TOO_FAST);
			return XDP_DROP;
		}
		st->last_act_ns = now;
	}

	/* Rewrite this frame into our reply and bounce it. Not while the peer
	 * is Down or AdminDown, nor without a sendable key.
	 */
	if (cfg && cfg->enable && rstate >= 2 && !(cfg->auth_present && !xdp_auth_fast(cfg))) {
		/* A wedged engine must not hold sessions Up. */
		if (deadman_tripped(now)) {
			count(BFD_STAT_DEADMAN_HOLD);
			return XDP_PASS;
		}
		return rx_clocked_tx(ctx, eth, iph, ip6, udp, bfd, cfg, st, asc, data, data_end);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
