// SPDX-License-Identifier: GPL-2.0
/* parse.h - L2/L3 parse, front GTSM, session key construction. */
#ifndef BFD_XDP_PARSE_H
#define BFD_XDP_PARSE_H

#include "bfd_shared.h"
#include "tunables.h"
#include "maps.h"
#include "stats.h"

/* Self-addressed: a classic echo is sent to the originator's own address.
 * Four word compares rather than a memcmp; the program uses none. Lives
 * here rather than in echo.h because the parser's GTSM exception needs it
 * too, and two copies of one address comparison is how they drift. */
static __always_inline int v6_self_addressed(const struct ipv6hdr *ip6)
{
	const __u32 *sa = (const __u32 *)&ip6->saddr;
	const __u32 *da = (const __u32 *)&ip6->daddr;

	return sa[0] == da[0] && sa[1] == da[1] &&
	       sa[2] == da[2] && sa[3] == da[3];
}

/* One of the three ports this program is about.
 *
 * Every BFD-specific rejection below is gated on this. The rules that
 * follow - GTSM, the options drop, the fragment drop - are all statements
 * about BFD, and applying them to a packet that is not BFD drops traffic
 * this program has no business touching. A DNS reply arrives at whatever
 * TTL the path left it with.
 */
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

/* Parse L2/L3, apply the front GTSM filter, and fill the session key.
 *
 * Returns an XDP verdict to bail with, or -1 to mean carry on. The
 * sentinel matters: every early exit here is a real verdict, and
 * only falling off the end of the family branch continues.
 */
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
		/* IP options (ihl != 5) on a UDP packet. A BFD control packet
		 * never carries them, and with them the UDP header sits at a
		 * variable offset, so every fixed-offset read below would be
		 * looking at the wrong bytes.
		 *
		 * Locate the header once, at the offset the packet declares,
		 * purely to read the port. Aimed at a BFD port it is dropped:
		 * passing would skip GTSM and demux and leak it to the
		 * userspace socket unvalidated, which is the bypass class an
		 * XDP_PASS reject belongs to. Anything else is not ours and
		 * goes to the stack with its options intact.
		 *
		 * Its own counter slot rather than REJECTED, because an
		 * optioned packet is refused for what its header is, not for
		 * anything about the BFD inside it. */
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
		/* Fragmented UDP. At any offset but 0 there is no UDP header,
		 * so c->udp points at payload and every port test reads
		 * garbage. At offset 0 with MF set the header is there, so
		 * the packet can pass every check below and be bounced with
		 * MF still set - a nonsense fragment on the wire while the
		 * stack reassembles the datagram for the socket.
		 *
		 * A BFD control packet is 66 bytes and never fragments, so
		 * dropping one aimed at a BFD port costs nothing. Everything
		 * else passes to the stack.
		 *
		 * IPv6 needs no equivalent: a fragment header makes
		 * nexthdr != IPPROTO_UDP and falls out of the dispatch. */
		if (c->iph->frag_off & bpf_htons(0x3fff)) {
			if (!(c->iph->frag_off & bpf_htons(0x1fff)) &&
			    bfd_dport(c->udp->dest)) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
			return XDP_PASS;
		}
		/* Not aimed at us. No BFD rule applies to it, GTSM least of
		 * all, so it reaches the stack exactly as it arrived. */
		if (!bfd_dport(c->udp->dest))
			return XDP_PASS;
		/* GTSM (RFC 5881 s5): single-hop control packets MUST arrive
		 * with TTL 255. Anything else is off-link or spoofed. The one
		 * exception is our own echo coming back: the neighbour's
		 * forwarding plane decremented it to 254, and the frame is
		 * still self-addressed to us on the echo port. Kept narrow so
		 * it cannot become a general TTL bypass. */
		if (c->iph->ttl != 255 &&
		    !(c->udp->dest == bpf_htons(BFD_ECHO_PORT) &&
		      c->iph->ttl == 254 && c->iph->saddr == c->iph->daddr)) {
			/* Not single-hop and not our own echo returning. If no
			 * multihop session exists on this box the packet is
			 * off-link or spoofed, so drop it here as before - that
			 * keeps the cheap early filter for the common case. With
			 * multihop configured the verdict needs the session's own
			 * minimum, which is only known after the config lookup. */
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
		/* First header is not UDP: ICMPv6 (ND/MLD/RA), or UDP hidden
		 * behind extension headers. ICMPv6 and any chain we do not
		 * resolve to UDP still PASS to the stack, so v6 neighbour
		 * discovery is untouched. But UDP behind one extension header
		 * aimed at a BFD port is not something single-hop BFD ever
		 * sends, and passing it is the same flood path to our socket
		 * the unknown-session drop closed for plain UDP. Walk
		 * exactly one extension header - hop-by-hop, routing,
		 * dest-opts or fragment - and if UDP to a BFD port sits behind
		 * it, drop and count. Deeper chains, and any header whose
		 * length runs past the frame, still PASS: they are malformed
		 * and the stack rejects them anyway. */
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
		/* GTSM: hop_limit is the v6 TTL. Same narrow exception as the v4
		 * branch for our own echo coming back: the neighbour's forwarding
		 * plane decremented it to 254 and the frame is still
		 * self-addressed on the echo port. Without it echo_reflect_v6's
		 * return branch is unreachable and v6 echo RTT never updates.
		 * The udp assignment moved above this check so the port is
		 * readable here; nothing between the two reads it. Kept narrow so
		 * it cannot become a general hop-limit bypass. */
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
