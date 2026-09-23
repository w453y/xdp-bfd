// SPDX-License-Identifier: GPL-2.0
/* rx.h - the receive decision for each control packet; rx_run.c tests it directly. */
#ifndef BFD_ENGINE_RX_H
#define BFD_ENGINE_RX_H

#include <stddef.h>

#include "session.h"

/* In the order the checks run. */
enum rx_verdict {
	RX_ACCEPT = 0,
	RX_MALFORMED, /* bfd_ctrl_check refused the header */
	/* GTSM, or the cmsg never arrived */
	RX_TTL,
	RX_NO_SESSION, /* demux named no session of ours */
	RX_AUTH,       /* the A bit or the digest did not satisfy it */
};

/* RFC 5880 s6.7. */
int rx_auth_ok(struct session *s, const __u8 *buf, __u8 len);

/* The session to hand to fsm_rx, or NULL with *why set. pkt is zeroed past n.
 * ttl is -1 if the cmsg was missing, which is refused.
 */
struct session *rx_accept(const __u8 *pkt, size_t n, int ttl, const struct bfd_addr *from,
			  const struct bfd_addr *to, int mhop, enum rx_verdict *why);

#endif /* BFD_ENGINE_RX_H */
