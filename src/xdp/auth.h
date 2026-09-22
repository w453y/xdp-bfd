// SPDX-License-Identifier: GPL-2.0
/* auth.h - authentication on the fast path (RFC 5880 s6.7): simple password
 * and keyed SHA1, plain and meticulous.
 *
 * Keyed SHA1 packets are a fixed 52 bytes; simple-password ones vary with the
 * key (28-43), so the packet is copied into a zero-padded scratch block first
 * and everything after works on fixed sizes. Include after maps.h.
 */
#ifndef BFD_XDP_AUTH_H
#define BFD_XDP_AUTH_H

#include "bfd_shared.h"
#include "bfd_auth.h"

/* Offset of the BFD payload: constant per family, since IPv4 options are
 * rejected. Computed, as the verifier will not do arithmetic that reaches
 * pkt_end.
 */
#define BFD_OFF_V4 (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
#define BFD_OFF_V6 (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr))

/* Can the program authenticate for this session? Must agree with the engine's
 * auth_fast_capable.
 */
static __always_inline int xdp_auth_fast(const struct tx_cfg *cfg)
{
	return cfg->auth_type == BFD_AUTH_SIMPLE || cfg->auth_type == BFD_AUTH_KEYED_SHA1 ||
	       cfg->auth_type == BFD_AUTH_METICULOUS_SHA1;
}

/* How long a packet of this session's type is, 0 if we cannot make one.
 * Bounded to BFD_MAX_LEN so the verifier can use it as a length.
 */
static __always_inline __u32 xdp_auth_len(const struct tx_cfg *cfg)
{
	__u32 n;

	if (cfg->auth_type == BFD_AUTH_SIMPLE) {
		if (!cfg->auth_keylen || cfg->auth_keylen > BFD_AUTH_SIMPLE_MAXKEY)
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

/* Hide a length from the optimiser so the verifier keeps its lower bound at
 * the helper call.
 *
 * bpf_xdp_load_bytes and bpf_xdp_store_bytes take ARG_CONST_SIZE, which needs
 * a non-zero umin. On a 6.1 verifier the spilled value loses it and the load
 * fails with "invalid access to map value, value_size=168 off=0 size=0". Same
 * trick as sha1_barrier in hmac_sha1.h.
 */
static __always_inline __u32 xdp_len_pin(__u32 len)
{
	__asm__ __volatile__("" : "+r"(len));
	return len;
}

/* Copy the packet into the zero-padded scratch block. bpf_xdp_load_bytes,
 * because a loop bounded by a runtime length does not survive the
 * optimiser and verifier.
 */
static __always_inline int xdp_auth_load(struct xdp_md *ctx, __u32 off, __u32 len, __u8 *blk)
{
	int i;

	if (len < BFD_MIN_LEN || len > BFD_MAX_LEN)
		return 0;
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		blk[i] = 0;
	/* After the loop, where clang spills it. One pin is enough. */
	len = xdp_len_pin(len);
	if (len < BFD_MIN_LEN || len > BFD_MAX_LEN)
		return 0;
	return bpf_xdp_load_bytes(ctx, off, blk, len) == 0;
}

/* Verify a received packet's auth section and advance the replay window on
 * success. The digest covers the packet with its digest field zeroed, hence
 * the copy. The window is kernel-owned while the fast path answers.
 */
static __always_inline int xdp_auth_verify(struct xdp_md *ctx, __u32 boff,
					   const struct bfd_ctrl_pkt *bfd, const struct tx_cfg *cfg,
					   struct session_state *st, struct auth_scratch *sc)
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
	 * could not hold never reaches the copy.
	 */
	if (len < BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR || len > BFD_MAX_LEN)
		return 0;
	if (!xdp_auth_load(ctx, boff, len, blk))
		return 0;

	type = blk[BFD_MIN_LEN];
	key_id = blk[BFD_MIN_LEN + 2];
	if (blk[BFD_MIN_LEN + 1] != len - BFD_MIN_LEN)
		return 0;

	/* Find the key the peer names among those acceptable now; during a
	 * rollover that includes the one we stopped sending with.
	 */
	for (i = 0; i < BFD_AUTH_ACCEPT_MAX; i++) {
		if (i >= cfg->auth_nkeys)
			break;
		if (cfg->auth_accept[i].key_id == key_id && cfg->auth_accept[i].type == type) {
			found = i;
			break;
		}
	}
	if (found < 0)
		return 0;

	/* Masked rather than merely bounded by the loop, so the verifier
	 * can see the access is in range without tracking the search.
	 */
	idx = (__u32)found & (BFD_AUTH_ACCEPT_MAX - 1);
	k = &cfg->auth_accept[idx];

	/* Copied out before it is used, so everything below works from a
	 * fixed offset. \see auth_scratch.kpad
	 */
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		sc->kpad[i] = k->kpad[i];

	/* The length the named key produces, which is what the packet must
	 * have claimed.
	 */
	if (type == BFD_AUTH_SIMPLE) {
		if (!k->keylen || k->keylen > BFD_AUTH_SIMPLE_MAXKEY)
			return 0;
		want = BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + k->keylen;
	} else if (type == BFD_AUTH_KEYED_SHA1 || type == BFD_AUTH_METICULOUS_SHA1) {
		want = BFD_MIN_LEN + BFD_AUTH_SHA1_LEN;
	} else {
		/* Keyed MD5 (types 2 and 3) is not supported; refuse it
		 * explicitly, as bfd_auth_pkt_len does.
		 */
		return 0;
	}
	if (len != want)
		return 0;

	/* Simple password (RFC 5880 s6.7.1): compare the whole padded field in
	 * constant time.
	 */
	if (type == BFD_AUTH_SIMPLE) {
		for (i = 0; i < BFD_AUTH_SIMPLE_MAXKEY; i++)
			diff |= (__u8)(blk[BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + i] ^ sc->kpad[i]);
		return diff == 0;
	}

	for (i = 0; i < 4; i++)
		seq = (seq << 8) | blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + i];

	/* RFC 5880 s6.7.4, the same window the slow path applies. The first
	 * packet has nothing to be judged against and sets the window
	 * instead, which is what lets a peer that restarted resynchronise.
	 */
	if (st->auth_rx_seen &&
	    !bfd_auth_seq_ok(seq, st->auth_rx_seq, type == BFD_AUTH_METICULOUS_SHA1,
			     bfd->detect_mult))
		return 0;

	for (i = 0; i < SHA1_DIGEST_LEN; i++) {
		sc->rcv[i] = blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i];
		blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = 0;
	}
	if (!hmac_sha1_blocks(sc->kpad, blk, BFD_MIN_LEN + BFD_AUTH_SHA1_LEN, dig, sc->tmp))
		return 0;

	/* Constant-time compare. */
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		diff |= (__u8)(dig[i] ^ sc->rcv[i]);
	if (diff)
		return 0;

	st->auth_rx_seq = seq;
	st->auth_rx_seen = 1;
	return 1;
}

/* 16-bit word sum of the assembled payload, read the same way as the rest of
 * the checksum fold; mixing byte orders breaks the v6 checksum. 26 words
 * covers the longest payload, and the zero tail adds nothing.
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

/* Build our auth section into a reply whose 24-byte header is already built,
 * and return the payload's 16-bit sum for the v6 checksum. Summed from the
 * scratch block, since a loop over packet bytes of runtime length fails
 * verification.
 *
 * Returns 0 if no section could be built, and the caller must then send
 * nothing.
 */
static __always_inline int xdp_auth_build(struct xdp_md *ctx, __u32 boff,
					  const struct bfd_ctrl_pkt *bfd, const struct tx_cfg *cfg,
					  struct session_state *st, struct auth_scratch *sc,
					  __u32 *psum)
{
	__u8 *blk = sc->blk;
	__u8 *dig = sc->dig;
	__u32 want = xdp_auth_len(cfg);
	__u32 seq;
	int i;

	/* Assembled in the scratch block and written back in one store, for
	 * the same verifier reason as the load.
	 */
	if (want < BFD_MIN_LEN || want > BFD_MAX_LEN)
		return 0;
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		blk[i] = 0;
	if (bpf_xdp_load_bytes(ctx, boff, blk, BFD_MIN_LEN))
		return 0;

	blk[BFD_MIN_LEN] = cfg->auth_type;
	blk[BFD_MIN_LEN + 1] = (__u8)(want - BFD_MIN_LEN);
	blk[BFD_MIN_LEN + 2] = cfg->auth_keyid;

	if (cfg->auth_type == BFD_AUTH_SIMPLE) {
		for (i = 0; i < BFD_AUTH_SIMPLE_MAXKEY; i++)
			blk[BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + i] = cfg->auth_kpad[i];
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
	blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF] = (__u8)(seq >> 24);
	blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + 1] = (__u8)(seq >> 16);
	blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + 2] = (__u8)(seq >> 8);
	blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + 3] = (__u8)seq;
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = 0;

	if (!hmac_sha1_blocks(cfg->auth_kpad, blk, BFD_MIN_LEN + BFD_AUTH_SHA1_LEN, dig, sc->tmp))
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
