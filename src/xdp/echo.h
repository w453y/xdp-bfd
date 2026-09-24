// SPDX-License-Identifier: GPL-2.0
/* echo.h - echo reflectors. Include after maps.h. */
#ifndef BFD_XDP_ECHO_H
#define BFD_XDP_ECHO_H

#include "parse.h"

/* Reflect a v4 echo, or consume our own coming back. */
/* Racy across CPUs, which at worst lets a few more through. */
static __always_inline int echo_budget(struct echo_peer *ep)
{
	__u64 now = bpf_ktime_get_ns();

	if (now - ep->win_ns > BFD_ECHO_WIN_US * 1000ull) {
		ep->win_ns = now;
		ep->n = 0;
	}
	if (ep->n >= ep->max)
		return 0;
	ep->n++;
	return 1;
}

static __always_inline int echo_reflect_v4(struct ethhdr *eth, struct iphdr *iph,
					   struct udphdr *udp, void *data_end)
{
	if (iph->ttl == 254 && iph->saddr == iph->daddr) {
		struct bfd_ctrl_pkt *eb = (void *)(udp + 1);

		if ((void *)(eb + 1) > data_end)
			return XDP_PASS;
		__u32 ed = bpf_ntohl(eb->my_disc);
		struct session_key *ek = bpf_map_lookup_elem(&echo_disc, &ed);

		if (!ek)
			return XDP_PASS;
		struct session_state *es = bpf_map_lookup_elem(&bfd_sessions, ek);

		if (!es)
			return XDP_PASS;
		es->echo_last_seen_ns = bpf_ktime_get_ns();
		es->echo_last_nonce = bpf_ntohl(eb->min_echo_rx);
		es->echo_rx_pkts++;
		count(BFD_STAT_ECHO_RETURNS);
		return XDP_DROP;
	}
	/* Single-hop only. */
	if (iph->ttl != 255) {
		count(BFD_STAT_ECHO_TTL);
		return XDP_PASS;
	}
	if (iph->saddr != iph->daddr) {
		count(BFD_STAT_NOT_SELF);
		return XDP_PASS;
	}
	/* Only for peers of echo-active sessions: otherwise an amplifier. */
	struct bfd_addr esrc;

	key_set_v4(&esrc, iph->saddr);
	struct echo_peer *ep = bpf_map_lookup_elem(&echo_peers, &esrc);

	if (!ep) {
		count(BFD_STAT_DECLINED);
		return XDP_PASS;
	}
	if (!echo_budget(ep)) {
		count(BFD_STAT_ECHO_RATELIMITED);
		return XDP_DROP;
	}

	__u8 tmp[6];

	__builtin_memcpy(tmp, eth->h_dest, 6);
	__builtin_memcpy(eth->h_dest, eth->h_source, 6);
	__builtin_memcpy(eth->h_source, tmp, 6);

	iph->ttl--;
	iph->check = 0;
	__u32 csum = 0;
	__u16 *w = (__u16 *)iph;

	for (int i = 0; i < 10; i++)
		csum += w[i];
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	iph->check = ~csum & 0xffff;

	count(BFD_STAT_REFLECTED);
	return XDP_TX;
}

/* No IP checksum, and the UDP checksum covers nothing a reflection changes. */
static __always_inline int echo_reflect_v6(struct ethhdr *eth, struct ipv6hdr *ip6,
					   struct udphdr *udp, void *data_end)
{
	struct session_key sk; /* .peer is also the echo_peers key */
	__u8 tmp[6];

	/* Our own at 254. Every miss inside returns, so 254 never reaches the GTSM check. */
	if (ip6->hop_limit == 254 && v6_self_addressed(ip6)) {
		struct bfd_ctrl_pkt *eb = (void *)(udp + 1);

		if ((void *)(eb + 1) > data_end)
			return XDP_PASS;
		__u32 ed = bpf_ntohl(eb->my_disc);
		struct session_key *ek = bpf_map_lookup_elem(&echo_disc, &ed);

		if (!ek)
			return XDP_PASS;
		struct session_state *es = bpf_map_lookup_elem(&bfd_sessions, ek);

		if (!es)
			return XDP_PASS;
		es->echo_last_seen_ns = bpf_ktime_get_ns();
		es->echo_last_nonce = bpf_ntohl(eb->min_echo_rx);
		es->echo_rx_pkts++;
		count(BFD_STAT_ECHO_RETURNS);
		return XDP_DROP;
	}

	/* Single-hop only. */
	if (ip6->hop_limit != 255) {
		count(BFD_STAT_ECHO_TTL);
		return XDP_PASS;
	}

	/* bfdd sends a v6 echo to its peer's address and returns one sent to
	 * it for a session it holds. Do the same, so an FRR peer's echo works.
	 */
	int to_us = !v6_self_addressed(ip6);

	key_set_v6(&sk.peer, &ip6->saddr);
	if (to_us) {
		key_set_v6(&sk.local, &ip6->daddr);
		if (!bpf_map_lookup_elem(&tx_config, &sk)) {
			count(BFD_STAT_NOT_SELF);
			return XDP_PASS;
		}
	}

	/* Only for peers of echo-active sessions: otherwise an amplifier. */
	struct echo_peer *ep = bpf_map_lookup_elem(&echo_peers, &sk.peer);

	if (!ep) {
		count(BFD_STAT_DECLINED);
		return XDP_PASS;
	}
	if (!echo_budget(ep)) {
		count(BFD_STAT_ECHO_RATELIMITED);
		return XDP_DROP;
	}

	__builtin_memcpy(tmp, eth->h_dest, 6);
	__builtin_memcpy(eth->h_dest, eth->h_source, 6);
	__builtin_memcpy(eth->h_source, tmp, 6);

	if (to_us) {
		__u32 *sa = (__u32 *)&ip6->saddr, *da = (__u32 *)&ip6->daddr;

		for (int i = 0; i < 4; i++) {
			__u32 w = sa[i];

			sa[i] = da[i];
			da[i] = w;
		}
	}
	ip6->hop_limit--;

	count(BFD_STAT_REFLECTED);
	return XDP_TX;
}

#endif /* BFD_XDP_ECHO_H */
