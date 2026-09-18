// SPDX-License-Identifier: GPL-2.0
/* validate.h - BFD control-packet header validation. */
#ifndef BFD_XDP_VALIDATE_H
#define BFD_XDP_VALIDATE_H

#include "bfd_shared.h"
#include "tunables.h"
#include "stats.h"

/* Control-packet validation (RFC 5880 s6.8.6 and the overread guard).
 * Returns an XDP verdict to bail with, or -1 to mean carry on - the same
 * sentinel idiom parse_l3 uses.
 *
 * Every disposition here drops. Under the threat model (HARDENING_PLAN
 * G2) the BFD ports have no consumer on this host but our own socket, so
 * a header the fast path will not honour has nowhere useful to go:
 * passing it only costs a syscall and, at a flood, evicts datagrams for
 * real sessions from the shared socket queue. A MALFORMED header is
 * counted to slot 2 and dropped; a well-formed header we cannot honour is
 * dropped for the same reason and counted to its own slot.
 *
 * Every check bails before any session lookup or state write.
 *
 * my_disc goes in without a byte swap on purpose: the shared predicate
 * only tests it against zero, which reads the same either way.
 *
 * The bfd + 1 bounds check stays in the caller: the verifier must see it
 * before bfd is dereferenced here or after this returns.
 */
static __always_inline int bfd_hdr_verdict(const struct bfd_ctrl_pkt *bfd,
					   const struct udphdr *udp,
					   __u8 auth_expected)
{
	__u16 udp_len = bpf_ntohs(udp->len);
	__u32 payload = udp_len >= sizeof(*udp) ? udp_len - sizeof(*udp) : 0;

	/* Guarded before the subtraction because udp_len is attacker-set:
	 * an under-8 value would wrap and hand bfd_ctrl_check a payload
	 * length of nearly 4G, which every length test would then pass. */
	switch (bfd_ctrl_check(bfd->vers_diag, bfd->flags, bfd->detect_mult,
			       bfd->len, bfd->my_disc, payload, auth_expected)) {
	case BFD_CTRL_MALFORMED:
		count(BFD_STAT_MALFORMED);
		return XDP_DROP;
	case BFD_CTRL_UNSUPPORTED:
		/* RFC 5880 s6.8.6: the M bit is discarded, multipoint being
		 * a different protocol. */
		count(BFD_STAT_UNSUPPORTED_FLAGS);
		return XDP_DROP;
	case BFD_CTRL_AUTH_MISMATCH:
		/* The A bit and the session disagree, in either direction.
		 * Dropped rather than passed: a packet claiming
		 * authentication we cannot check, or omitting the
		 * authentication we require, is not something the stack
		 * should get a second opinion on. */
		count(BFD_STAT_AUTH_MISMATCH);
		return XDP_DROP;
	}

	return -1;
}

#endif /* BFD_XDP_VALIDATE_H */
