// SPDX-License-Identifier: GPL-2.0
/* validate.h - BFD control-packet header validation. */
#ifndef BFD_XDP_VALIDATE_H
#define BFD_XDP_VALIDATE_H

#include "bfd_shared.h"
#include "tunables.h"
#include "stats.h"

/* Control-packet validation (RFC 5880 s6.8.6 and the overread guard).
 * Malformed frames are counted to slot 2 and PASSED to the stack, never
 * dropped: a broken header is not evidence of an attack. Every check
 * bails before any session lookup or state write.
 *
 * The bfd + 1 bounds check stays in the caller: the verifier must see it
 * before bfd is dereferenced here or after this returns.
 */
static __always_inline int bfd_hdr_valid(const struct bfd_ctrl_pkt *bfd,
					 const struct udphdr *udp)
{
	if (BFD_VERS(bfd) != BFD_VERSION || bfd->len < BFD_MIN_LEN ||
	    bfd->detect_mult == 0 || bfd->my_disc == 0) {
		count(2);
		return 0;
	}
	__u16 udp_len = bpf_ntohs(udp->len);
	if (udp_len < sizeof(*udp) + BFD_MIN_LEN ||
	    bfd->len > udp_len - sizeof(*udp)) {
		count(2);
		return 0;
	}

	return 1;
}

#endif /* BFD_XDP_VALIDATE_H */
