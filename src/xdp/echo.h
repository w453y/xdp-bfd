// SPDX-License-Identifier: GPL-2.0
/* echo.h - IPv6 echo reflector.
 *
 * Split out of bfd_xdp.c. Include order matters: maps.h must precede
 * any header whose helpers reference a map by symbol.
 */
#ifndef BFD_XDP_ECHO_H
#define BFD_XDP_ECHO_H

/* Reflect a v6 echo.
 *
 * Simpler than the v4 path: v6 has no IP checksum, and the mandatory UDP
 * checksum covers the pseudo-header and the payload, neither of which a
 * self-addressed reflection changes. Only the MAC and the hop limit are
 * touched, so nothing needs recomputing.
 *
 * The m8b originator is v4 only, so there is no v6 equivalent of the
 * hop_limit-254 return demux: a v6 echo arriving here is always a
 * neighbour's, never our own coming back.
 */
static __always_inline int echo_reflect_v6(struct ethhdr *eth,
					   struct ipv6hdr *ip6)
{
	const __u32 *sa = (const __u32 *)&ip6->saddr;
	const __u32 *da = (const __u32 *)&ip6->daddr;
	struct bfd_addr esrc;
	__u8 tmp[6];

	/* GTSM: single-hop echoes only. */
	if (ip6->hop_limit != 255) {
		count(8);          /* echo-ttl */
		return XDP_PASS;
	}

	/* A classic echo is self-addressed to the originator. */
	if (sa[0] != da[0] || sa[1] != da[1] ||
	    sa[2] != da[2] || sa[3] != da[3]) {
		count(7);          /* echo-not-self */
		return XDP_PASS;
	}

	/* Reflect only for a peer of an echo-active session; otherwise this
	 * is an arbitrary 3785 packet and returning it is an amplification
	 * vector. */
	key_set_v6(&esrc, &ip6->saddr);
	if (!bpf_map_lookup_elem(&echo_peers, &esrc)) {
		count(6);          /* echo-declined */
		return XDP_PASS;
	}

	/* L2 swap: return to the originating MAC. */
	__builtin_memcpy(tmp, eth->h_dest, 6);
	__builtin_memcpy(eth->h_dest, eth->h_source, 6);
	__builtin_memcpy(eth->h_source, tmp, 6);

	ip6->hop_limit--;

	count(4);          /* echo-reflected */
	return XDP_TX;
}

#endif /* BFD_XDP_ECHO_H */
