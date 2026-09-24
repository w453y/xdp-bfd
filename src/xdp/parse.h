// SPDX-License-Identifier: GPL-2.0
/* parse.h - L2/L3 parse, front GTSM, session key. */
#ifndef BFD_XDP_PARSE_H
#define BFD_XDP_PARSE_H

#include "bfd_shared.h"
#include "tunables.h"
#include "maps.h"
#include "stats.h"

/* Shared with the parser's GTSM exception. */
static __always_inline int v6_self_addressed(const struct ipv6hdr *ip6)
{
	const __u32 *sa = (const __u32 *)&ip6->saddr;
	const __u32 *da = (const __u32 *)&ip6->daddr;

	return sa[0] == da[0] && sa[1] == da[1] && sa[2] == da[2] && sa[3] == da[3];
}

/* Every BFD rule below is gated on this; other traffic passes untouched. */
static __always_inline int bfd_dport(__be16 dest)
{
	return dest == bpf_htons(BFD_PORT_1HOP) || dest == bpf_htons(BFD_PORT_MHOP) ||
	       dest == bpf_htons(BFD_ECHO_PORT);
}

struct l3ctx {
	struct iphdr *iph;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	struct session_key key;
};

/* An XDP verdict, or -1 to carry on. */
static __always_inline int parse_l3(struct ethhdr *eth, void *data_end, struct l3ctx *c)
{
	__u16 proto = eth->h_proto;

	if (proto == bpf_htons(ETH_P_IP)) {
		c->iph = (void *)(eth + 1);
		if ((void *)(c->iph + 1) > data_end)
			return XDP_PASS;
		if (c->iph->protocol != IPPROTO_UDP)
			return XDP_PASS;
		/* IP options move the UDP header and BFD never sends them. Drop
		 * if the declared port is a BFD port, since passing would
		 * bypass validation.
		 */
		if (c->iph->ihl != 5) {
			__u32 ihl = c->iph->ihl;
			struct udphdr *ou;

			/* Malformed; leave it to the stack. */
			if (ihl < 5)
				return XDP_PASS;

			ou = (void *)c->iph + ihl * 4;
			if ((void *)(ou + 1) > data_end)
				return XDP_PASS;
			if (!bfd_dport(ou->dest))
				return XDP_PASS;

			count(BFD_STAT_IP_OPTIONS);
			return XDP_DROP;
		}
		c->udp = (void *)(c->iph + 1);
		if ((void *)(c->udp + 1) > data_end)
			return XDP_PASS;
		/* BFD never fragments: drop a first fragment to a BFD port
		 * rather than bounce it with MF set. IPv6 fragments fall out at
		 * the nexthdr check.
		 */
		if (c->iph->frag_off & bpf_htons(0x3fff)) {
			if (!(c->iph->frag_off & bpf_htons(0x1fff)) && bfd_dport(c->udp->dest)) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
			return XDP_PASS;
		}
		if (!bfd_dport(c->udp->dest))
			return XDP_PASS;
		/* RFC 5881 s5: TTL 255, except our own echo returning at 254. */
		if (c->iph->ttl != 255 && !(c->udp->dest == bpf_htons(BFD_ECHO_PORT) &&
					    c->iph->ttl == 254 && c->iph->saddr == c->iph->daddr)) {
			/* Off-link or spoofed, unless multihop is configured;
			 * then the session's minimum decides after lookup.
			 */
			__u32 mz = 0;
			__u32 *mf = bpf_map_lookup_elem(&prog_flags, &mz);

			if (!mf || !(*mf & 2)) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
		}
		key_set_v4(&c->key.peer, c->iph->saddr);
		key_set_v4(&c->key.local, c->iph->daddr);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		c->ip6 = (void *)(eth + 1);
		if ((void *)(c->ip6 + 1) > data_end)
			return XDP_PASS;
		/* ICMPv6 and unresolved chains pass, so ND is untouched. UDP to
		 * a BFD port behind one extension header is dropped.
		 */
		if (c->ip6->nexthdr != IPPROTO_UDP) {
			__u8 nh = c->ip6->nexthdr;
			struct exthdr2 {
				__u8 nexthdr;
				__u8 hdrlen;
			} *eh;
			struct udphdr *ou;
			__u32 ehlen;

			if (nh != IPPROTO_HOPOPTS && nh != IPPROTO_ROUTING &&
			    nh != IPPROTO_DSTOPTS && nh != IPPROTO_FRAGMENT)
				return XDP_PASS;

			eh = (void *)(c->ip6 + 1);
			if ((void *)(eh + 1) > data_end)
				return XDP_PASS;
			if (eh->nexthdr != IPPROTO_UDP)
				return XDP_PASS;

			/* Bounded so the variable offset stays provable. */
			ehlen = nh == IPPROTO_FRAGMENT ? 8u : (((__u32)eh->hdrlen + 1u) * 8u);
			if (ehlen > 64u)
				return XDP_PASS;

			ou = (void *)eh + ehlen;
			if ((void *)(ou + 1) > data_end)
				return XDP_PASS;
			if (!bfd_dport(ou->dest))
				return XDP_PASS;

			count(BFD_STAT_V6_EXTHDR);
			return XDP_DROP;
		}
		c->udp = (void *)(c->ip6 + 1);
		if ((void *)(c->udp + 1) > data_end)
			return XDP_PASS;
		if (!bfd_dport(c->udp->dest))
			return XDP_PASS;
		/* As v4. */
		if (c->ip6->hop_limit != 255 &&
		    !(c->udp->dest == bpf_htons(BFD_ECHO_PORT) && c->ip6->hop_limit == 254 &&
		      v6_self_addressed(c->ip6))) {
			__u32 mz = 0;
			__u32 *mf = bpf_map_lookup_elem(&prog_flags, &mz);

			if (!mf || !(*mf & 2)) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
		}
		key_set_v6(&c->key.peer, &c->ip6->saddr);
		key_set_v6(&c->key.local, &c->ip6->daddr);
	} else {
		return XDP_PASS;
	}

	return -1;
}

#endif /* BFD_XDP_PARSE_H */
