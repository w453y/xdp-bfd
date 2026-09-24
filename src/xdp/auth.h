// SPDX-License-Identifier: GPL-2.0
/* auth.h - RFC 5880 s6.7 on the fast path: simple password, keyed and
 * meticulous SHA1. The packet is copied into a zero-padded scratch block so
 * everything works on fixed sizes. Include after maps.h.
 */
#ifndef BFD_XDP_AUTH_H
#define BFD_XDP_AUTH_H

#include "bfd_shared.h"
#include "bfd_auth.h"

/* Constant per family, since IPv4 options are rejected; the verifier will not
 * do arithmetic that reaches pkt_end.
 */
#define BFD_OFF_V4 (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
#define BFD_OFF_V6 (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr))

/* Must agree with the engine's auth_fast_capable. */
static __always_inline int xdp_auth_fast(const struct tx_cfg *cfg)
{
	return cfg->auth_type == BFD_AUTH_SIMPLE || cfg->auth_type == BFD_AUTH_KEYED_SHA1 ||
	       cfg->auth_type == BFD_AUTH_METICULOUS_SHA1;
}

/* 0 if we cannot make one; bounded so the verifier accepts it as a length. */
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

/* Hide a length from the optimiser so the verifier keeps its non-zero lower
 * bound for ARG_CONST_SIZE. A 6.1 verifier otherwise fails with "invalid access
 * to map value ... size=0". As sha1_barrier.
 */
static __always_inline __u32 xdp_len_pin(__u32 len)
{
	__asm__ __volatile__("" : "+r"(len));
	return len;
}

/* bpf_xdp_load_bytes: a loop bounded by a runtime length does not survive the verifier. */
static __always_inline int xdp_auth_load(struct xdp_md *ctx, __u32 off, __u32 len, __u8 *blk)
{
	int i;

	if (len < BFD_MIN_LEN || len > BFD_MAX_LEN)
		return 0;
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		blk[i] = 0;
	/* After the loop, where clang spills it. */
	len = xdp_len_pin(len);
	if (len < BFD_MIN_LEN || len > BFD_MAX_LEN)
		return 0;
	return bpf_xdp_load_bytes(ctx, off, blk, len) == 0;
}

/* Advance the replay window on success. The digest covers the packet with the
 * digest zeroed, hence the copy.
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

	/* Before anything is read. */
	if (len < BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR || len > BFD_MAX_LEN)
		return 0;
	if (!xdp_auth_load(ctx, boff, len, blk))
		return 0;

	type = blk[BFD_MIN_LEN];
	key_id = blk[BFD_MIN_LEN + 2];
	if (blk[BFD_MIN_LEN + 1] != len - BFD_MIN_LEN)
		return 0;

	/* During a rollover the accept set includes the key we stopped sending with. */
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

	/* Masked, so the verifier sees the access in range. */
	idx = (__u32)found & (BFD_AUTH_ACCEPT_MAX - 1);
	k = &cfg->auth_accept[idx];

	/* Copied out so everything below uses a fixed offset. */
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		sc->kpad[i] = k->kpad[i];

	/* The length the named key produces is what the packet must claim. */
	if (type == BFD_AUTH_SIMPLE) {
		if (!k->keylen || k->keylen > BFD_AUTH_SIMPLE_MAXKEY)
			return 0;
		want = BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + k->keylen;
	} else if (type == BFD_AUTH_KEYED_SHA1 || type == BFD_AUTH_METICULOUS_SHA1) {
		want = BFD_MIN_LEN + BFD_AUTH_SHA1_LEN;
	} else {
		/* Keyed MD5 is not supported. */
		return 0;
	}
	if (len != want)
		return 0;

	/* RFC 5880 s6.7.1: the whole padded field, in constant time. */
	if (type == BFD_AUTH_SIMPLE) {
		for (i = 0; i < BFD_AUTH_SIMPLE_MAXKEY; i++)
			diff |= (__u8)(blk[BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + i] ^ sc->kpad[i]);
		return diff == 0;
	}

	for (i = 0; i < 4; i++)
		seq = (seq << 8) | blk[BFD_MIN_LEN + BFD_AUTH_SHA1_SEQ_OFF + i];

	/* RFC 5880 s6.7.4. The first packet sets the window instead, so a
	 * restarted peer can resync.
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

	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		diff |= (__u8)(dig[i] ^ sc->rcv[i]);
	if (diff)
		return 0;

	st->auth_rx_seq = seq;
	st->auth_rx_seen = 1;
	return 1;
}

/* Read the same way as the rest of the checksum fold; mixing byte orders breaks v6. */
static __always_inline __u32 xdp_auth_sum(const __u8 *blk)
{
	const __u16 *w = (const __u16 *)blk;
	__u32 sum = 0;
	int i;

	for (i = 0; i < BFD_MAX_LEN / 2; i++)
		sum += w[i];
	return sum;
}

/* Build our auth section after the 24-byte header and return its 16-bit sum for
 * the v6 checksum. 0 if none could be built; then send nothing.
 */
static __always_inline int xdp_auth_build(struct xdp_md *ctx, __u32 boff,
					  const struct bfd_ctrl_pkt *bfd, const struct tx_cfg *cfg,
					  struct auth_scratch *sc, __u32 *psum)
{
	__u8 *blk = sc->blk;
	__u8 *dig = sc->dig;
	__u32 want = xdp_auth_len(cfg);
	__u32 seq;
	int i;

	/* Written back in one store, for the same verifier reason as the load. */
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

	/* RFC 5880 s6.7.3, from the counter shared with the engine. */
	{
		__u32 slot = cfg->slot;
		/* The engine sizes auth_seq (--max-sessions); the lookup bounds it. */
		__u64 *sq = bpf_map_lookup_elem(&auth_seq, &slot);

		if (!sq)
			return 0;
		seq = (__u32)(__sync_fetch_and_add(sq, 1) + 1);
	}

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
