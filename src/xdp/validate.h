// SPDX-License-Identifier: GPL-2.0
/* validate.h - BFD control-packet header validation. */
#ifndef BFD_XDP_VALIDATE_H
#define BFD_XDP_VALIDATE_H

#include "bfd_shared.h"
#include "tunables.h"
#include "stats.h"

/* RFC 5880 s6.8.6. An XDP verdict, or -1 to carry on. Refused packets are
 * dropped: nothing else consumes the BFD ports. The caller bounds bfd + 1.
 */
static __always_inline int bfd_hdr_verdict(const struct bfd_ctrl_pkt *bfd,
					   const struct udphdr *udp, __u8 auth_expected)
{
	__u16 udp_len = bpf_ntohs(udp->len);
	__u32 payload = udp_len >= sizeof(*udp) ? udp_len - sizeof(*udp) : 0;

	/* udp_len is attacker-set; under 8 it would wrap. */
	switch (bfd_ctrl_check(bfd->vers_diag, bfd->flags, bfd->detect_mult, bfd->len,
			       bfd->my_disc, payload, auth_expected)) {
	case BFD_CTRL_MALFORMED:
		count(BFD_STAT_MALFORMED);
		return XDP_DROP;
	case BFD_CTRL_UNSUPPORTED:
		/* RFC 5880 s6.8.6: multipoint is another protocol. */
		count(BFD_STAT_UNSUPPORTED_FLAGS);
		return XDP_DROP;
	case BFD_CTRL_AUTH_MISMATCH:
		count(BFD_STAT_AUTH_MISMATCH);
		return XDP_DROP;
	}

	return -1;
}

#endif /* BFD_XDP_VALIDATE_H */
