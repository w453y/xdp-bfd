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
 * Two dispositions, deliberately different. A MALFORMED header is counted
 * to slot 2 and PASSED to the stack: a broken header is not evidence of
 * an attack, and the stack may have a use for it. A well-formed header we
 * cannot honour is DROPPED, because PASSing it hands it to a userspace
 * path that would accept it as something it is not.
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
					   const struct udphdr *udp)
{
	__u16 udp_len = bpf_ntohs(udp->len);
	__u32 payload = udp_len >= sizeof(*udp) ? udp_len - sizeof(*udp) : 0;

	/* Guarded before the subtraction because udp_len is attacker-set:
	 * an under-8 value would wrap and hand bfd_ctrl_check a payload
	 * length of nearly 4G, which every length test would then pass. */
	switch (bfd_ctrl_check(bfd->vers_diag, bfd->flags, bfd->detect_mult,
			       bfd->len, bfd->my_disc, payload)) {
	case BFD_CTRL_MALFORMED:
		count(2);
		return XDP_PASS;
	case BFD_CTRL_UNSUPPORTED:
		/* RFC 5880 s6.8.6: the M bit MUST be discarded (multipoint
		 * is not this protocol), and the A bit MUST be discarded
		 * when no authentication is configured. s6.7 is
		 * unimplemented here, so that is every session - an
		 * authenticated peer's packets were being accepted as
		 * though they carried no auth section at all.
		 *
		 * If auth is ever implemented this becomes "PASS to
		 * userspace when the session has auth configured, DROP
		 * otherwise". Keyed digests do not belong in the verifier.
		 */
		count(9);
		return XDP_DROP;
	}

	return -1;
}

#endif /* BFD_XDP_VALIDATE_H */
