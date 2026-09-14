// SPDX-License-Identifier: GPL-2.0
/* auth.h - authentication on the fast path (RFC 5880 s6.7).
 *
 * Every type bfdd can produce: simple password, and keyed SHA1 in its
 * plain and meticulous forms. Which sessions keep RX-clocked TX should
 * not depend on which authentication an operator picked.
 *
 * Keyed SHA1 is the easy one, which is not obvious. Those packets are
 * always 52 bytes, so every bound here is a compile-time constant. A
 * simple-password packet is 24 + 3 + however long the key is - 28 to 43
 * bytes - so its length is a runtime value and the packet reads have to
 * be proven against it. That is what the copy into scratch below is
 * for: one loop carries the whole variable-length problem, and
 * everything after it works on a fixed-size zero-padded block.
 *
 * Include after maps.h.
 */
#ifndef BFD_XDP_AUTH_H
#define BFD_XDP_AUTH_H

#include "bfd_shared.h"
#include "bfd_auth.h"

/* Where the BFD payload starts, which is a constant per family: the
 * parser rejects IPv4 options outright, so the v4 header is always
 * twenty bytes. Computed rather than subtracted from the packet
 * pointers, because the verifier will not do arithmetic that reaches
 * pkt_end. */
#define BFD_OFF_V4 (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
		    sizeof(struct udphdr))
#define BFD_OFF_V6 (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + \
		    sizeof(struct udphdr))

/* Is this a session the program can authenticate for? Must agree with
 * the engine's ktx_answers: if the two disagree the fast path either
 * answers without a section, or stays quiet while userspace waits for
 * it to answer. */
static __always_inline int xdp_auth_fast(const struct tx_cfg *cfg)
{
	return cfg->auth_type == BFD_AUTH_SIMPLE ||
	       cfg->auth_type == BFD_AUTH_KEYED_SHA1 ||
	       cfg->auth_type == BFD_AUTH_METICULOUS_SHA1;
}

/* How long a packet of this session's type is, 0 if we cannot make one.
 * Bounded to BFD_MAX_LEN so the verifier can use it as a length. */
static __always_inline __u32 xdp_auth_len(const struct tx_cfg *cfg)
{
	__u32 n;

	if (cfg->auth_type == BFD_AUTH_SIMPLE) {
		if (!cfg->auth_keylen ||
		    cfg->auth_keylen > BFD_AUTH_SIMPLE_MAXKEY)
			return 0;
		n = BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + cfg->auth_keylen;
	} else if (cfg->auth_type == BFD_AUTH_KEYED_SHA1 ||
		   cfg->auth_type == BFD_AUTH_METICULOUS_SHA1) {
		n = BFD_MIN_LEN + BFD_AUTH_SHA1_LEN;
	} else {
		return 0;
	}
	return n > BFD_MAX_LEN ? 0 : n;
}

/* The packet into the zero-padded scratch block, and back again.
 *
 * Through bpf_xdp_load_bytes rather than a loop over the packet.
 * A hand-written copy bounded by a runtime length does not survive
 * the optimiser: the compiler unrolls it, the per-iteration bound
 * check folds away with the index, and the verifier is left staring at
 * a constant offset past the range it has proven. The helper takes the
 * length as an argument and does the bounds check in the kernel, which
 * is the whole reason it exists.
 *
 * Everything downstream then reads a fixed-size block whose tail is
 * known to be zero, which is also the shape the digest wants.
 */
/* Pin a length so the verifier still has its lower bound at the call.
 *
 * bpf_xdp_load_bytes and bpf_xdp_store_bytes take ARG_CONST_SIZE, not
 * ARG_CONST_SIZE_OR_ZERO, so the size register must carry a non-zero
 * umin. The range checks below establish one, and on a 6.1 verifier it
 * does not survive: the value is a u8 widened to u32, clang spills it
 * across the zeroing loop, and the fill comes back carrying only the
 * tnum. umax=255 is kept, umin=0 is not. check_helper_mem_access then
 * tests the destination against a zero-length access, which is why the
 * refusal names the destination register and reads
 * "invalid access to map value, value_size=168 off=0 size=0" rather than
 * saying anything about the length at all.
 *
 * Laundering through an empty asm makes the value opaque, so the check
 * that follows cannot be folded back or hoisted above the spill and lands
 * on the register the helper is handed. Same reason and same shape as
 * sha1_barrier in hmac_sha1.h.
 *
 * Two compare-and-branch pairs on kernels that never needed it.
 */
static __always_inline __u32 xdp_len_pin(__u32 len)
{
	__asm__ __volatile__("" : "+r"(len));
	return len;
}

static __always_inline int xdp_auth_load(struct xdp_md *ctx, __u32 off,
					 __u32 len, __u8 *blk)
{
	int i;

	if (len < BFD_MIN_LEN || len > BFD_MAX_LEN)
		return 0;
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		blk[i] = 0;
	/* After the loop, which is where clang spills it. One pin, not two:
	 * a second before the loop buys nothing the verifier keeps, and the
	 * extra live value costs stack this path does not have. */
	len = xdp_len_pin(len);
	if (len < BFD_MIN_LEN || len > BFD_MAX_LEN)
		return 0;
	return bpf_xdp_load_bytes(ctx, off, blk, len) == 0;
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
static __always_inline int xdp_auth_verify(struct xdp_md *ctx, __u32 boff,
					   const struct bfd_ctrl_pkt *bfd,
					   const struct tx_cfg *cfg,
					   struct session_state *st,
					   struct auth_scratch *sc)
{
	__u8 *blk = sc->blk;
	__u8 *dig = sc->dig;
	const struct xdp_auth_key *k;
	__u32 len = bfd->len;
	__u32 want, idx, seq = 0;
	__u8 key_id, type;
	__u8 diff = 0;
	int i, found = -1;

	/* Bounded before anything is read, so a packet claiming a shape we
	 * could not hold never reaches the copy. */
	if (len < BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR || len > BFD_MAX_LEN)
		return 0;
	if (!xdp_auth_load(ctx, boff, len, blk))
		return 0;

	type = blk[BFD_MIN_LEN];
	key_id = blk[BFD_MIN_LEN + 2];
	if (blk[BFD_MIN_LEN + 1] != len - BFD_MIN_LEN)
		return 0;

	/* The peer names the key it signed with. Anything the engine left
	 * here is acceptable now, which during a rollover includes the key
	 * we have already stopped transmitting under. */
	for (i = 0; i < BFD_AUTH_ACCEPT_MAX; i++) {
		if (i >= cfg->auth_nkeys)
			break;
		if (cfg->auth_accept[i].key_id == key_id &&
		    cfg->auth_accept[i].type == type) {
			found = i;
			break;
		}
	}
	if (found < 0)
		return 0;

	/* Masked rather than merely bounded by the loop, so the verifier
	 * can see the access is in range without tracking the search. */
	idx = (__u32)found & (BFD_AUTH_ACCEPT_MAX - 1);
	k = &cfg->auth_accept[idx];

	/* Copied out before it is used, so everything below works from a
	 * fixed offset. \see auth_scratch.kpad */
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		sc->kpad[i] = k->kpad[i];

	/* The length the named key produces, which is what the packet must
	 * have claimed. */
	if (type == BFD_AUTH_SIMPLE) {
		if (!k->keylen || k->keylen > BFD_AUTH_SIMPLE_MAXKEY)
			return 0;
		want = BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + k->keylen;
	} else if (type == BFD_AUTH_KEYED_SHA1 ||
		   type == BFD_AUTH_METICULOUS_SHA1) {
		want = BFD_MIN_LEN + BFD_AUTH_SHA1_LEN;
	} else {
		/* Named explicitly rather than falling into the SHA1 arm.
		 * The accept set carries bfdd's key type byte verbatim, so
		 * keyed MD5 (2 and 3) can land here, and treating it as
		 * SHA1 meant measuring a 24 byte section against 28 and
		 * digesting it with the wrong algorithm. It failed closed,
		 * but by arithmetic rather than by decision. Userspace says
		 * the same thing in bfd_auth_pkt_len, which returns 0 for
		 * anything outside the three types this implements. */
		return 0;
	}
	if (len != want)
		return 0;

	/* Simple password: no digest and no sequence, just the secret in
	 * the clear (RFC 5880 s6.7.1). Compared over the whole padded
	 * field rather than the configured length - both sides are zero
	 * past the key, and a compare that stops early leaks the password
	 * a byte at a time to anyone who can time it. */
	if (type == BFD_AUTH_SIMPLE) {
		for (i = 0; i < BFD_AUTH_SIMPLE_MAXKEY; i++)
			diff |= (__u8)(blk[BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + i] ^
				       sc->kpad[i]);
		return diff == 0;
	}

	for (i = 0; i < 4; i++)
		seq = (seq << 8) | blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + i];

	/* RFC 5880 s6.7.4, the same window the slow path applies. The first
	 * packet has nothing to be judged against and sets the window
	 * instead, which is what lets a peer that restarted resynchronise. */
	if (st->auth_rx_seen &&
	    !bfd_auth_seq_ok(seq, st->auth_rx_seq,
			     type == BFD_AUTH_METICULOUS_SHA1,
			     bfd->detect_mult))
		return 0;

	for (i = 0; i < SHA1_DIGEST_LEN; i++) {
		sc->rcv[i] = blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i];
		blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = 0;
	}
	if (!hmac_sha1_blocks(sc->kpad, blk,
			      BFD_MIN_LEN + BFD_AUTH_SHA1_LEN, dig, sc->tmp))
		return 0;

	/* Compared in full rather than bailing on the first difference: an
	 * early return times out proportionally to how much of the digest
	 * was right. */
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		diff |= (__u8)(dig[i] ^ sc->rcv[i]);
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
/* The 16-bit word sum of the assembled payload.
 *
 * Words are read exactly as the rest of the fold reads them - straight
 * out of memory, not assembled byte by byte into a big-endian value.
 * A ones-complement sum is only byte-order agnostic if every term is
 * accumulated the same way; mixing the two conventions byte-swaps this
 * contribution and the checksum comes out wrong. It costs nothing on
 * IPv4, which sends no UDP checksum at all, and breaks every IPv6
 * session, which must.
 *
 * A constant 26 words covers the longest payload. The block is zero
 * past the section, and zeroes add nothing - which is also exactly the
 * pad an odd-length payload needs.
 */
static __always_inline __u32 xdp_auth_sum(const __u8 *blk)
{
	const __u16 *w = (const __u16 *)blk;
	__u32 sum = 0;
	int i;

	for (i = 0; i < BFD_MAX_LEN / 2; i++)
		sum += w[i];
	return sum;
}

/* Builds the section, and hands back the 16-bit sum of the whole BFD
 * payload for the v6 checksum.
 *
 * Summed here, off the scratch, rather than in the caller off the
 * packet. The section's length is a runtime value, and a guarded loop
 * over packet bytes does not survive the optimiser - it rewrites
 * `p + i + 1 > end` into arithmetic on pkt_end, which the verifier
 * refuses. The scratch is zero past the section, so a constant sweep of
 * BFD_MAX_LEN bytes covers exactly the payload and nothing else: the
 * trailing zeroes contribute nothing to a ones-complement sum.
 */
static __always_inline int xdp_auth_build(struct xdp_md *ctx, __u32 boff,
					  const struct bfd_ctrl_pkt *bfd,
					  const struct tx_cfg *cfg,
					  struct session_state *st,
					  struct auth_scratch *sc,
					  __u32 *psum)
{
	__u8 *blk = sc->blk;
	__u8 *dig = sc->dig;
	__u32 want = xdp_auth_len(cfg);
	__u32 seq;
	int i;

	/* Assembled in the scratch and written back in one store, rather
	 * than poked into the packet field by field: the section's length
	 * is a runtime value, and the same optimiser problem that defeats
	 * a hand-written copy defeats a hand-written write. */
	if (want < BFD_MIN_LEN || want > BFD_MAX_LEN)
		return 0;
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		blk[i] = 0;
	if (bpf_xdp_load_bytes(ctx, boff, blk, BFD_MIN_LEN))
		return 0;

	blk[BFD_MIN_LEN]     = cfg->auth_type;
	blk[BFD_MIN_LEN + 1] = (__u8)(want - BFD_MIN_LEN);
	blk[BFD_MIN_LEN + 2] = cfg->auth_keyid;

	if (cfg->auth_type == BFD_AUTH_SIMPLE) {
		for (i = 0; i < BFD_AUTH_SIMPLE_MAXKEY; i++)
			blk[BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + i] =
				cfg->auth_kpad[i];
		want = xdp_len_pin(want);
		if (want < BFD_MIN_LEN || want > BFD_MAX_LEN)
			return 0;
		if (bpf_xdp_store_bytes(ctx, boff, blk, want))
			return 0;
		*psum = xdp_auth_sum(blk);
		return 1;
	}

	seq = st->auth_tx_seq + 1;
	st->auth_tx_seq = seq;

	blk[BFD_MIN_LEN + 3] = 0;
	blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF]     = (__u8)(seq >> 24);
	blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + 1] = (__u8)(seq >> 16);
	blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + 2] = (__u8)(seq >> 8);
	blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + 3] = (__u8)seq;
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = 0;

	if (!hmac_sha1_blocks(cfg->auth_kpad, blk,
			      BFD_MIN_LEN + BFD_AUTH_SHA1_LEN, dig, sc->tmp))
		return 0;
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = dig[i];

	want = xdp_len_pin(want);
	if (want < BFD_MIN_LEN || want > BFD_MAX_LEN)
		return 0;
	if (bpf_xdp_store_bytes(ctx, boff, blk, want))
		return 0;
	*psum = xdp_auth_sum(blk);
	return 1;
}

#endif /* BFD_XDP_AUTH_H */
