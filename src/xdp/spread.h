// SPDX-License-Identifier: GPL-2.0
/* spread.h - hand traffic that is not ours to other CPUs (--spread-pass), so
 * the stack's work on a flood runs in cpumap threads, which the RX softirq
 * preempts, instead of holding up the ring BFD arrives on. A flow keeps its
 * CPU. Include after maps.h and parse.h.
 */
#ifndef BFD_XDP_SPREAD_H
#define BFD_XDP_SPREAD_H

/* Addresses and, for an unfragmented TCP or UDP packet, ports. 0 for a
 * packet to a BFD port, which stays on this CPU.
 */
static __always_inline int flow_hash(void *data, void *data_end, __u32 *h)
{
	struct ethhdr *eth = data;
	__u32 x = 0;
	__u8 proto = 0;
	void *l4 = NULL;

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (void *)(eth + 1);

		if ((void *)(iph + 1) > data_end)
			return -1;
		x = iph->saddr ^ iph->daddr;
		proto = iph->protocol;
		/* Not a later fragment, and no options to skip. */
		if (iph->ihl == 5 && !(iph->frag_off & bpf_htons(0x1fff)))
			l4 = iph + 1;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		const __u32 *s, *d;

		if ((void *)(ip6 + 1) > data_end)
			return -1;
		s = (const __u32 *)&ip6->saddr;
		d = (const __u32 *)&ip6->daddr;
		x = s[0] ^ s[1] ^ s[2] ^ s[3] ^ d[0] ^ d[1] ^ d[2] ^ d[3];
		proto = ip6->nexthdr;
		l4 = ip6 + 1;
	} else {
		return -1;
	}
	if (l4 && (proto == IPPROTO_UDP || proto == IPPROTO_TCP)) {
		struct udphdr *uh = l4; /* ports in the same place for TCP */

		if ((void *)(uh + 1) > data_end)
			return -1;
		if (proto == IPPROTO_UDP && bfd_dport(uh->dest))
			return -1;
		x ^= ((__u32)uh->source << 16) | uh->dest;
	}
	x *= 0x9e3779b1;
	*h = x ^ (x >> 16);
	return 0;
}

static __always_inline int pass_up(void *data, void *data_end)
{
	__u32 k = BFD_TUNE_SPREAD_CPUS, h;
	__u64 *n = bpf_map_lookup_elem(&tunables, &k);

	if (!n || !*n || flow_hash(data, data_end, &h))
		return XDP_PASS;
	/* A CPU not in the map falls back to passing here. */
	return bpf_redirect_map(&pass_cpus, h % (__u32)*n, XDP_PASS);
}

#endif /* BFD_XDP_SPREAD_H */
