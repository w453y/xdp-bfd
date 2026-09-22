// SPDX-License-Identifier: GPL-2.0
/* validate.h - BFD control-packet header validation. */
#ifndef BFD_XDP_VALIDATE_H
#define BFD_XDP_VALIDATE_H

#include "bfd_shared.h"
#include "tunables.h"
#include "stats.h"

/* Control-packet validation (RFC 5880 s6.8.6). Returns an XDP verdict, or -1
 * to carry on.
 *
 * Everything refused is dropped, since nothing but our socket consumes the BFD
 * ports. Runs before any session lookup or state write. my_disc is only tested
 * against zero, so it needs no byte swap. The caller does the bfd + 1 bounds
 * check.
 */
static __always_inline int bfd_hdr_verdict(const struct bfd_ctrl_pkt *bfd,
					   const struct udphdr *udp, __u8 auth_expected)
{
	__u16 udp_len = bpf_ntohs(udp->len);
	__u32 payload = udp_len >= sizeof(*udp) ? udp_len - sizeof(*udp) : 0;

	/* payload is guarded above: udp_len is attacker-set, and under 8 it
	 * would wrap to nearly 4G.
	 */
	switch (bfd_ctrl_check(bfd->vers_diag, bfd->flags, bfd->detect_mult, bfd->len,
			       bfd->my_disc, payload, auth_expected)) {
	case BFD_CTRL_MALFORMED:
		count(BFD_STAT_MALFORMED);
		return XDP_DROP;
	case BFD_CTRL_UNSUPPORTED:
		/* RFC 5880 s6.8.6: the M bit is discarded, multipoint being
		 * a different protocol.
		 */
		count(BFD_STAT_UNSUPPORTED_FLAGS);
		return XDP_DROP;
	case BFD_CTRL_AUTH_MISMATCH:
		/* The A bit and the session disagree, either way. */
		count(BFD_STAT_AUTH_MISMATCH);
		return XDP_DROP;
	}

	return -1;
}

#endif /* BFD_XDP_VALIDATE_H */
