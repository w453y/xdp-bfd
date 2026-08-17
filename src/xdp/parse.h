// SPDX-License-Identifier: GPL-2.0
/* parse.h - L2/L3 parse, front GTSM, session key construction. */
#ifndef BFD_XDP_PARSE_H
#define BFD_XDP_PARSE_H

#include "bfd_shared.h"
#include "tunables.h"
#include "maps.h"
#include "stats.h"

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
		/* IP options (ihl != 5) on a UDP packet: a single-hop BFD
		 * control packet never carries them. Passing would skip the
		 * GTSM/your_disc checks below (UDP header sits at a variable
		 * offset with options) and leak the packet to the userspace
		 * socket unvalidated - the same bypass class as an XDP_PASS
		 * reject. Drop it. */
		if (c->iph->ihl != 5) {
			count(BFD_STAT_REJECTED);
			return XDP_DROP;
		}
		c->udp = (void *)(c->iph + 1);
		if ((void *)(c->udp + 1) > data_end)
			return XDP_PASS;
		/* Fragmented UDP. Nothing below this point is safe on a
		 * fragment: at any offset but 0 there is no UDP header at
		 * all, so c->udp points at payload and every port test
		 * reads garbage. At offset 0 with MF set the header IS
		 * there, so the packet can satisfy every check below and
		 * then be bounced with MF still set - a nonsense fragment
		 * emitted onto the wire while the stack separately
		 * reassembles the datagram for the socket.
		 *
		 * A BFD control packet is 66 bytes and never fragments, so
		 * dropping a fragment aimed at a BFD port costs nothing and
		 * closes the same bypass class as the ihl != 5 rule above.
		 * Everything else PASSes to the stack as before.
		 *
		 * IPv6 needs no equivalent: a fragment header makes
		 * nexthdr != IPPROTO_UDP and falls out of the dispatch. */
		if (c->iph->frag_off & bpf_htons(0x3fff)) {
			if (!(c->iph->frag_off & bpf_htons(0x1fff)) &&
			    (c->udp->dest == bpf_htons(BFD_PORT_1HOP) ||
			     c->udp->dest == bpf_htons(BFD_PORT_MHOP) ||
			     c->udp->dest == bpf_htons(BFD_ECHO_PORT))) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
			return XDP_PASS;
		}
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
		/* Non-UDP first header: ICMPv6 (ND/MLD/RA), or UDP hidden
		 * behind extension headers we deliberately don't walk. PASS to
		 * the stack either way - this mirrors the v4 non-UDP PASS.
		 * DROPping here kills v6 neighbour discovery. A UDP-behind-
		 * extheaders packet to the BFD port is left to userspace GTSM
		 * (IPV6_MINHOPCOUNT) and demux; single-hop BFD never sends one. */
		if (c->ip6->nexthdr != IPPROTO_UDP)
			return XDP_PASS;
		/* GTSM: hop_limit is the v6 TTL. */
		if (c->ip6->hop_limit != 255) {
			__u32 mz = 0;
			__u32 *mf = bpf_map_lookup_elem(&prog_flags, &mz);
			if (!mf || !(*mf & 2)) {
				count(BFD_STAT_REJECTED);
				return XDP_DROP;
			}
		}
		c->udp = (void *)(c->ip6 + 1);
		if ((void *)(c->udp + 1) > data_end)
			return XDP_PASS;
		key_set_v6(&c->key.peer,  &c->ip6->saddr);
		key_set_v6(&c->key.local, &c->ip6->daddr);
	} else {
		return XDP_PASS;
	}

	return -1;
}

#endif /* BFD_XDP_PARSE_H */
