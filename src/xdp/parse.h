// SPDX-License-Identifier: GPL-2.0
/* parse.h - L2/L3 parse, front GTSM, session key construction. */
#ifndef BFD_XDP_PARSE_H
#define BFD_XDP_PARSE_H

#include "bfd_shared.h"
#include "tunables.h"
#include "maps.h"
#include "stats.h"

/* Self-addressed IPv6, as a classic echo is. Four word compares; shared with
 * the parser's GTSM exception. */
static __always_inline int v6_self_addressed(const struct ipv6hdr *ip6)
{
	const __u32 *sa = (const __u32 *)&ip6->saddr;
	const __u32 *da = (const __u32 *)&ip6->daddr;

	return sa[0] == da[0] && sa[1] == da[1] &&
	       sa[2] == da[2] && sa[3] == da[3];
}

/* Destination is a BFD port. Every BFD-specific rule below (GTSM, options and
 * fragment drops) is gated on this, so other traffic passes untouched. */
static __always_inline int bfd_dport(__be16 dest)
{
	return dest == bpf_htons(BFD_PORT_1HOP) ||
	       dest == bpf_htons(BFD_PORT_MHOP) ||
	       dest == bpf_htons(BFD_ECHO_PORT);
}

struct l3ctx {
	struct iphdr   *iph;
	struct ipv6hdr *ip6;
	struct udphdr  *udp;
	struct session_key key;
};

/* Parse L2/L3, apply the front GTSM filter and fill the session key. Returns
 * an XDP verdict, or -1 to carry on. */
static __always_inline int parse_l3(struct ethhdr *eth, void *data_end,
				    struct l3ctx *c)
{
	__u16 proto = eth->h_proto;

	if (proto == bpf_htons(ETH_P_IP)) {
		c->iph = (void *)(eth + 1);
		if ((void *)(c->iph + 1) > data_end)
			return XDP_PASS;
		if (c->iph->protocol != IPPROTO_UDP)
			return XDP_PASS;
		/* IP options: BFD never sends them, and they move the UDP
		 * header. Read the port at the declared offset; drop if it is
		 * a BFD port, since passing would bypass validation, otherwise
		 * pass. Counted separately from REJECTED. */
		if (c->iph->ihl != 5) {
			__u32 ihl = c->iph->ihl;
			struct udphdr *ou;

			/* Below five the header is malformed and the length
			 * is not usable as an offset; leave it to the stack. */
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
		/* Fragments. BFD never fragments, so a first fragment aimed at
		 * a BFD port is dropped rather than bounced with MF set.
		 * Non-first fragments have no UDP header and pass. IPv6
		 * fragments fall out at the nexthdr check. */
		if (c->iph->frag_off & bpf_htons(0x3fff)) {
			if (!(c->iph->frag_off & bpf_htons(0x1fff)) &&
			    bfd_dport(c->udp->dest)) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
			return XDP_PASS;
		}
		/* Not a BFD port: pass untouched. */
		if (!bfd_dport(c->udp->dest))
			return XDP_PASS;
		/* GTSM (RFC 5881 s5): single-hop control packets arrive with
		 * TTL 255. The only exception is our own echo returning at
		 * 254, self-addressed on the echo port. */
		if (c->iph->ttl != 255 &&
		    !(c->udp->dest == bpf_htons(BFD_ECHO_PORT) &&
		      c->iph->ttl == 254 && c->iph->saddr == c->iph->daddr)) {
			/* Below 255: without multihop sessions it is off-link
			 * or spoofed, so drop it. With multihop configured,
			 * defer to the session's minimum after lookup. */
			__u32 mz = 0;
			__u32 *mf = bpf_map_lookup_elem(&prog_flags, &mz);
			if (!mf || !(*mf & 2)) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
		}
		key_set_v4(&c->key.peer,  c->iph->saddr);
		key_set_v4(&c->key.local, c->iph->daddr);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		c->ip6 = (void *)(eth + 1);
		if ((void *)(c->ip6 + 1) > data_end)
			return XDP_PASS;
		/* First header is not UDP. ICMPv6 and unresolved chains pass,
		 * so ND is untouched. UDP to a BFD port behind one extension
		 * header is dropped, since BFD never sends that; deeper or
		 * malformed chains pass to the stack. */
		if (c->ip6->nexthdr != IPPROTO_UDP) {
			__u8 nh = c->ip6->nexthdr;
			struct exthdr2 { __u8 nexthdr; __u8 hdrlen; } *eh;
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

			/* Fragment header is a fixed eight bytes; the others
			 * count length in 8-octet units past the first eight.
			 * Bounded so the variable offset stays provable. */
			ehlen = nh == IPPROTO_FRAGMENT
				? 8u : (((__u32)eh->hdrlen + 1u) * 8u);
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
		/* Not aimed at us; see the v4 branch. */
		if (!bfd_dport(c->udp->dest))
			return XDP_PASS;
		/* GTSM on hop_limit, with the same exception for our own echo
		 * returning at 254. */
		if (c->ip6->hop_limit != 255 &&
		    !(c->udp->dest == bpf_htons(BFD_ECHO_PORT) &&
		      c->ip6->hop_limit == 254 &&
		      v6_self_addressed(c->ip6))) {
			__u32 mz = 0;
			__u32 *mf = bpf_map_lookup_elem(&prog_flags, &mz);
			if (!mf || !(*mf & 2)) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
		}
		key_set_v6(&c->key.peer,  &c->ip6->saddr);
		key_set_v6(&c->key.local, &c->ip6->daddr);
	} else {
		return XDP_PASS;
	}

	return -1;
}

#endif /* BFD_XDP_PARSE_H */
