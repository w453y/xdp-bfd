// SPDX-License-Identifier: GPL-2.0
/* auth.h - authentication on the fast path (RFC 5880 s6.7).
 *
 * Keyed SHA1 only, in its plain and meticulous forms. That is not the
 * easier half by accident: a keyed-SHA1 packet is always 52 bytes, so
 * every copy here has a constant bound. A simple-password packet is
 * 24 + 3 + however long the key is, and copying it means a loop bounded
 * by a runtime length, which the verifier walks one iteration at a time
 * until it gives up. Those sessions stay in userspace, where the
 * password is checked against the same shared code.
 *
 * Include after maps.h.
 */
#ifndef BFD_XDP_AUTH_H
#define BFD_XDP_AUTH_H

#include "bfd_shared.h"
#include "bfd_auth.h"

/* Is this a session the program can authenticate for? Must agree with
 * the engine's ktx_answers: if the two disagree the fast path either
 * answers without a section, or stays quiet while userspace waits for
 * it to answer. */
static __always_inline int xdp_auth_fast(const struct tx_cfg *cfg)
{
	return cfg->auth_type == BFD_AUTH_KEYED_SHA1 ||
	       cfg->auth_type == BFD_AUTH_METICULOUS_SHA1;
}

/* Check the section on a received packet, and advance the replay window
 * on success.
 *
 * The digest covers the packet with its own digest field zeroed, so the
 * whole thing is copied into a scratch block first - which the hash
 * wants in that shape anyway.
 *
 * The window is kernel-owned while the fast path is answering. Two
 * writers would let a stale userspace copy hand the peer a sequence
 * that goes backwards, and a meticulous peer rejects everything after
 * that until the session resets.
 */
static __always_inline int xdp_auth_verify(const struct bfd_ctrl_pkt *bfd,
					   const struct tx_cfg *cfg,
					   struct session_state *st,
					   struct auth_scratch *sc,
					   void *data_end)
{
	const __u8 *p = (const __u8 *)bfd;
	__u8 *blk = sc->blk;
	__u8 *dig = sc->dig;
	__u32 seq = 0;
	__u8 diff = 0;
	int i;

	/* Exactly the shape this handles, checked before anything is read:
	 * the length the peer claims, and the bytes actually present. */
	if (bfd->len != BFD_MIN_LEN + BFD_AUTH_SHA1_LEN)
		return 0;
	if ((void *)(p + BFD_MIN_LEN + BFD_AUTH_SHA1_LEN) > data_end)
		return 0;

	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		blk[i] = (i < BFD_MIN_LEN + BFD_AUTH_SHA1_LEN) ? p[i] : 0;

	if (blk[BFD_MIN_LEN] != cfg->auth_type ||
	    blk[BFD_MIN_LEN + 1] != BFD_AUTH_SHA1_LEN ||
	    blk[BFD_MIN_LEN + 2] != cfg->auth_keyid)
		return 0;

	for (i = 0; i < 4; i++)
		seq = (seq << 8) | blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + i];

	/* RFC 5880 s6.7.3. Meticulous demands strictly increasing; the
	 * plain form tolerates a repeat, which is what lets a peer answer
	 * a Poll without burning a sequence. The first packet has nothing
	 * to be judged against and sets the window instead. */
	if (st->auth_rx_seen) {
		if (cfg->auth_type == BFD_AUTH_METICULOUS_SHA1) {
			if (seq <= st->auth_rx_seq)
				return 0;
		} else if (seq < st->auth_rx_seq) {
			return 0;
		}
	}

	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = 0;
	if (!hmac_sha1_blocks(cfg->auth_kpad, blk,
			      BFD_MIN_LEN + BFD_AUTH_SHA1_LEN, dig))
		return 0;

	/* Compared in full rather than bailing on the first difference: an
	 * early return times out proportionally to how much of the digest
	 * was right. */
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		diff |= (__u8)(dig[i] ^ p[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i]);
	if (diff)
		return 0;

	st->auth_rx_seq = seq;
	st->auth_rx_seen = 1;
	return 1;
}

/* Write our own section into a reply whose 24-byte header is already
 * built. The caller has set the A bit and the length; this fills what
 * follows and signs it.
 *
 * Returns 0 if the digest could not be produced, which the caller must
 * treat as "send nothing": a packet with the A bit set and a section
 * full of zeroes is worse than no packet at all.
 */
static __always_inline int xdp_auth_build(struct bfd_ctrl_pkt *bfd,
					  const struct tx_cfg *cfg,
					  struct session_state *st,
					  struct auth_scratch *sc,
					  void *data_end)
{
	__u8 *p = (__u8 *)bfd;
	__u8 *blk = sc->blk;
	__u8 *dig = sc->dig;
	__u32 seq;
	int i;

	if ((void *)(p + BFD_MIN_LEN + BFD_AUTH_SHA1_LEN) > data_end)
		return 0;

	seq = st->auth_tx_seq + 1;
	st->auth_tx_seq = seq;

	p[BFD_MIN_LEN]     = cfg->auth_type;
	p[BFD_MIN_LEN + 1] = BFD_AUTH_SHA1_LEN;
	p[BFD_MIN_LEN + 2] = cfg->auth_keyid;
	p[BFD_MIN_LEN + 3] = 0;
	p[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF]     = (__u8)(seq >> 24);
	p[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + 1] = (__u8)(seq >> 16);
	p[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + 2] = (__u8)(seq >> 8);
	p[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + 3] = (__u8)seq;
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		p[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = 0;

	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		blk[i] = (i < BFD_MIN_LEN + BFD_AUTH_SHA1_LEN) ? p[i] : 0;
	if (!hmac_sha1_blocks(cfg->auth_kpad, blk,
			      BFD_MIN_LEN + BFD_AUTH_SHA1_LEN, dig))
		return 0;

	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		p[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = dig[i];
	return 1;
}

#endif /* BFD_XDP_AUTH_H */
