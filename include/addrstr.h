// SPDX-License-Identifier: GPL-2.0
/* addrstr.h - render a shared 16-byte session address.
 *
 * The key always holds the 16-byte form with v4 stored v4-mapped
 * (::ffff:a.b.c.d), so anything printing one has to decide which family it
 * is looking at. The loader grew this first; the stats dump needs the same
 * thing, and two copies of a byte-comparison is exactly how the v6 render
 * bug got into the loader in the first place.
 *
 * Userspace only - inet_ntop does not exist on the BPF side.
 */
#ifndef BFD_ADDRSTR_H
#define BFD_ADDRSTR_H

#include <arpa/inet.h>
#include <string.h>

#include "bfd_shared.h"

static inline const char *bfd_addr_str(const struct bfd_addr *a, char *buf,
				       size_t n)
{
	static const __u8 v4map[12] = { 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0xff, 0xff };

	if (!memcmp(a->b, v4map, sizeof(v4map)))
		return inet_ntop(AF_INET, &a->b[12], buf, n);
	return inet_ntop(AF_INET6, a->b, buf, n);
}

#endif /* BFD_ADDRSTR_H */
