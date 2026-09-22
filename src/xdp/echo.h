// SPDX-License-Identifier: GPL-2.0
/* echo.h - echo reflectors, IPv4 and IPv6.
 *
 * Include after maps.h.
 */
#ifndef BFD_XDP_ECHO_H
#define BFD_XDP_ECHO_H

#include "parse.h"

/* Reflect a v4 echo, or consume our own coming back. The caller has checked
 * UDP/3785 and iph.
 */
static __always_inline int echo_reflect_v4(struct ethhdr *eth, struct iphdr *iph,
					   struct udphdr *udp, void *data_end)
{
	/* Our own echo returning at TTL 254, still self-addressed:
	 * consume it.
	 */
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
	/* GTSM: single-hop echoes only. */
	if (iph->ttl != 255) {
		count(BFD_STAT_ECHO_TTL);
		return XDP_PASS;
	}
	/* A classic echo is self-addressed to the originator. */
	if (iph->saddr != iph->daddr) {
		count(BFD_STAT_NOT_SELF);
		return XDP_PASS;
	}
	/* Reflect only for a peer of an echo-active session; otherwise
	 * this is an arbitrary 3785 packet (amplification vector).
	 */
	struct bfd_addr esrc;

	key_set_v4(&esrc, iph->saddr);
	if (!bpf_map_lookup_elem(&echo_peers, &esrc)) {
		count(BFD_STAT_DECLINED);
		return XDP_PASS;
	}

	/* L2 swap: return to the originating MAC. */
	__u8 tmp[6];

	__builtin_memcpy(tmp, eth->h_dest, 6);
	__builtin_memcpy(eth->h_dest, eth->h_source, 6);
	__builtin_memcpy(eth->h_source, tmp, 6);

	/* Decrement TTL and recompute the IP checksum in full. */
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

/* Reflect a v6 echo. No IP checksum, and the UDP checksum covers nothing a
 * reflection changes, so only the MACs and hop limit are touched.
 */
static __always_inline int echo_reflect_v6(struct ethhdr *eth, struct ipv6hdr *ip6,
					   struct udphdr *udp, void *data_end)
{
	struct bfd_addr esrc;
	__u8 tmp[6];

	/* Our own echo returning at hop limit 254: consume it. Every miss
	 * inside returns, so a 254 frame never reaches the GTSM check.
	 */
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

	/* GTSM: single-hop echoes only. */
	if (ip6->hop_limit != 255) {
		count(BFD_STAT_ECHO_TTL);
		return XDP_PASS;
	}

	/* A classic echo is self-addressed to the originator. */
	if (!v6_self_addressed(ip6)) {
		count(BFD_STAT_NOT_SELF);
		return XDP_PASS;
	}

	/* Reflect only for a peer of an echo-active session; anything else
	 * would be an amplification vector.
	 */
	key_set_v6(&esrc, &ip6->saddr);
	if (!bpf_map_lookup_elem(&echo_peers, &esrc)) {
		count(BFD_STAT_DECLINED);
		return XDP_PASS;
	}

	/* L2 swap: return to the originating MAC. */
	__builtin_memcpy(tmp, eth->h_dest, 6);
	__builtin_memcpy(eth->h_dest, eth->h_source, 6);
	__builtin_memcpy(eth->h_source, tmp, 6);

	ip6->hop_limit--;

	count(BFD_STAT_REFLECTED);
	return XDP_TX;
}

#endif /* BFD_XDP_ECHO_H */
