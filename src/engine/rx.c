// SPDX-License-Identifier: GPL-2.0
/* rx.c - the per-packet receive decision. \see rx.h */
#define _GNU_SOURCE
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "bfd_shared.h"
#include "bfd_auth.h"
#include "log.h"
#include "rx.h"

int rx_auth_ok(struct session *s, const __u8 *buf, __u8 len)
{
	const struct bfd_ctrl_pkt *h = (const struct bfd_ctrl_pkt *)buf;
	const struct auth_key *k;
	int v;

	/* Authentication is a property of the session, not of which key is
	 * usable now. */
	if (!!(h->flags & BFD_F_AUTH) != !!s->auth_present)
		return 0;
	if (!s->auth_present)
		return 1;

	if (len < BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR)
		return 0;

	/* Accept any key inside its accept period, not only the one we send
	 * with, so a rollover does not refuse the peer. */
	k = session_auth_key_for(s, buf[BFD_MIN_LEN + 2], (int64_t)time(NULL));
	if (!k) {
		log_debug("lid=%u no key %u is currently accepted\n", s->lid,
			  buf[BFD_MIN_LEN + 2]);
		return 0;
	}

	v = bfd_auth_check(buf, len, k->type, k->key_id,
			   k->kpad, k->keylen, k->kpad,
			   &s->auth_rx_seq, &s->auth_rx_seen,
			   h->detect_mult);
	if (v != BFD_AUTH_OK) {
		log_debug("lid=%u authentication rejected a packet (%d)\n",
			  s->lid, v);
		return 0;
	}
	return 1;
}

struct session *rx_accept(const __u8 *pkt, size_t n, int ttl,
			  const struct bfd_addr *from,
			  const struct bfd_addr *to,
			  int mhop, enum rx_verdict *why)
{
	struct bfd_ctrl_pkt h;
	struct session *s;
	__u32 ydisc;

	/* From the caller's zeroed buffer, so a short datagram reads as zeros;
	 * bfd_ctrl_check checks the length. */
	memcpy(&h, pkt, sizeof(h));

	/* The same predicate the XDP path uses, so the two planes cannot
	 * disagree about what is acceptable. */
	if (bfd_ctrl_check(h.vers_diag, h.flags, h.detect_mult, h.len,
			   h.my_disc, (__u32)n,
			   !!(h.flags & BFD_F_AUTH)) != BFD_CTRL_ACCEPT) {
		*why = RX_MALFORMED;
		return NULL;
	}

	/* Single-hop GTSM (RFC 5881): exactly 255, and before the demux,
	 * because the rule does not depend on which session it names. */
	if (!mhop && ttl != 255) {
		*why = RX_TTL;
		return NULL;
	}

	/* Demux (RFC 5880 s6.8.6), as XDP does it: your_disc names our
	 * session, or is zero with the peer in Down or AdminDown. */
	ydisc = ntohl(h.your_disc);
	s = sess_by_wire(ydisc);
	if (!s && ydisc == 0 && BFD_STATE(&h) <= ST_DOWN)
		s = sess_by_addr(from, to);
	if (!s) {
		*why = RX_NO_SESSION;
		return NULL;
	}

	/* Multihop GTSM (RFC 5883) against this session's own minimum, the
	 * same rule the kernel applies against cfg->min_ttl. After the
	 * demux because that is when the minimum is known. */
	if (mhop && (ttl < 0 || ttl < (int)s->min_ttl)) {
		*why = RX_TTL;
		return NULL;
	}

	if (!rx_auth_ok(s, pkt, h.len)) {
		*why = RX_AUTH;
		return NULL;
	}

	*why = RX_ACCEPT;
	return s;
}
