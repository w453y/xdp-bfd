// SPDX-License-Identifier: GPL-2.0
/* rx.h - the per-packet receive decision made for every packet rx_drain reads.
 * Pure apart from the session table, so tests/unit/rx_run.c drives it
 * directly.
 */
#ifndef BFD_ENGINE_RX_H
#define BFD_ENGINE_RX_H

#include <stddef.h>

#include "session.h"

/* Why a packet was not accepted. Ordered by where it fell out, so a test
 * can assert the reason and not merely the refusal.
 */
enum rx_verdict {
	RX_ACCEPT = 0,
	RX_MALFORMED, /* bfd_ctrl_check refused the header */
	/* GTSM: not 255 single-hop, or under the session's minimum multihop,
	 * or the cmsg never arrived
	 */
	RX_TTL,
	RX_NO_SESSION, /* demux named no session of ours */
	RX_AUTH,       /* the A bit or the digest did not satisfy it */
};

/* Whether this packet authenticates for this session (RFC 5880 s6.7). */
int rx_auth_ok(struct session *s, const __u8 *buf, __u8 len);

/* The session to hand to fsm_rx, or NULL with *why set.
 *
 * `pkt` is the caller's zeroed BFD_MAX_LEN buffer and `n` the datagram length.
 * `ttl` is the received TTL or hop limit, -1 if the cmsg was missing, which is
 * refused. `mhop` selects GTSM: 255 before demux for single-hop, the session's
 * minimum after demux for multihop.
 */
struct session *rx_accept(const __u8 *pkt, size_t n, int ttl, const struct bfd_addr *from,
			  const struct bfd_addr *to, int mhop, enum rx_verdict *why);

#endif /* BFD_ENGINE_RX_H */
