// SPDX-License-Identifier: GPL-2.0
/* rx.h - the per-packet receive decision, shared by the four drains.
 *
 * The four receive drains in main.c (v4/v6 x single-hop/multihop) differ
 * only in which socket they read and how the source and destination
 * addresses come out of the cmsgs. The decision they make about a packet
 * once it is in hand - does the header parse, does the TTL satisfy GTSM,
 * which session does it name, does it authenticate - was written out four
 * times, and both authentication findings of the last review round sat on
 * that boundary with no host test able to reach it.
 *
 * Here it is one pure-ish function of the packet and the session table,
 * so the drains keep only the socket plumbing and the decision can be
 * driven directly from a harness (tests/unit/rx_run.c).
 */
#ifndef BFD_ENGINE_RX_H
#define BFD_ENGINE_RX_H

#include <stddef.h>

#include "session.h"

/* Why a packet was not accepted. Ordered by where it fell out, so a test
 * can assert the reason and not merely the refusal. */
enum rx_verdict {
	RX_ACCEPT = 0,
	RX_MALFORMED,    /* bfd_ctrl_check refused the header */
	RX_TTL,          /* GTSM: not 255 single-hop, or under the session's
	                  * minimum multihop, or the cmsg never arrived */
	RX_NO_SESSION,   /* demux named no session of ours */
	RX_AUTH,         /* the A bit or the digest did not satisfy it */
};

/* Whether this packet authenticates for this session (RFC 5880 s6.7).
 * Exposed because the drains once had it and the harness asserts it
 * directly; rx_accept applies it last. */
int rx_auth_ok(struct session *s, const __u8 *buf, __u8 len);

/* The session to hand to fsm_rx, or NULL with *why set.
 *
 * `pkt` is the receive buffer, which is BFD_MAX_LEN and zeroed by the
 * caller, so the header is readable whatever the datagram length; `n` is
 * what recvmsg returned and is what the length field is checked against.
 * `ttl` is the arriving TTL or hop limit, -1 when the cmsg was absent,
 * which is a refusal rather than a pass: a missing cmsg means the
 * setsockopt did not take, and accepting anything then is worse.
 * `mhop` selects the GTSM rule: single-hop wants exactly 255 before the
 * demux, multihop wants the session's own minimum after it, because that
 * is when the minimum is known.
 */
struct session *rx_accept(const __u8 *pkt, size_t n, int ttl,
			  const struct bfd_addr *from,
			  const struct bfd_addr *to,
			  int mhop, enum rx_verdict *why);

#endif /* BFD_ENGINE_RX_H */
