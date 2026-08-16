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
 * The bfd + 1 bounds check stays in the caller: the verifier must see it
 * before bfd is dereferenced here or after this returns.
 */
static __always_inline int bfd_hdr_verdict(const struct bfd_ctrl_pkt *bfd,
					   const struct udphdr *udp)
{
	if (BFD_VERS(bfd) != BFD_VERSION || bfd->len < BFD_MIN_LEN ||
	    bfd->detect_mult == 0 || bfd->my_disc == 0) {
		count(2);
		return XDP_PASS;
	}
	__u16 udp_len = bpf_ntohs(udp->len);
	if (udp_len < sizeof(*udp) + BFD_MIN_LEN ||
	    bfd->len > udp_len - sizeof(*udp)) {
		count(2);
		return XDP_PASS;
	}

	/* RFC 5880 s6.8.6: a packet with the M bit set MUST be discarded
	 * (multipoint is not this protocol), and one with the A bit set
	 * MUST be discarded when no authentication is configured. s6.7 is
	 * unimplemented here, so that is every session - an authenticated
	 * peer's packets were being accepted as though they carried no
	 * auth section at all.
	 *
	 * If auth is ever implemented this becomes "PASS to userspace when
	 * the session has auth configured, DROP otherwise". Keyed digests
	 * do not belong in the verifier.
	 */
	if (bfd->flags & (BFD_F_AUTH | BFD_F_MP)) {
		count(9);
		return XDP_DROP;
	}

	return -1;
}

#endif /* BFD_XDP_VALIDATE_H */
