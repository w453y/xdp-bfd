// SPDX-License-Identifier: GPL-2.0
/* csum.h - checksum helpers.
 *
 * Split out of bfd_xdp.c. Include order matters: maps.h must precede
 * any header whose helpers reference a map by symbol.
 */
#ifndef BFD_XDP_CSUM_H
#define BFD_XDP_CSUM_H

/* Ones-complement incremental checksum update for a single 16-bit
 * word (RFC 1624). Endian-agnostic: the fold is symmetric, so the
 * words may be passed in network order. */
static __always_inline void csum_replace2(__u16 *check, __u16 old,
					  __u16 new)
{
	__u32 csum = (~(*check) & 0xffff) + (~old & 0xffff) + new;

	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	*check = (__u16)~csum;
}

#endif /* BFD_XDP_CSUM_H */
