// SPDX-License-Identifier: GPL-2.0
/* hmac_sha1.h - SHA1 and HMAC-SHA1 for both planes (RFC 5880 s6.7).
 *
 * The kernel has no hashing kfunc, so the fast path carries its own; one
 * implementation keeps both planes' digests identical. Bounded: a keyed-SHA1
 * packet is 52 bytes, so the HMAC is four fixed block compressions. Oversized
 * input returns 0 and writes nothing. */
#ifndef BFD_HMAC_SHA1_H
#define BFD_HMAC_SHA1_H

#include <linux/types.h>

/* bpf_helpers.h supplies __always_inline on the BPF side; the host build
 * needs its own. */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifdef __clang__
#define SHA1_UNROLL _Pragma("unroll")
#else
#define SHA1_UNROLL
#endif

/* On BPF, sha1_compress and hmac_sha1_blocks are real calls: fully inlined,
 * their message schedules overrun the 512-byte stack. */
#if defined(__bpf__)
#define SHA1_CORE static __attribute__((noinline))
#else
#define SHA1_CORE static inline
#endif

#define SHA1_DIGEST_LEN 20
#define SHA1_BLOCK_LEN  64

/* The message HMAC will accept. 55 keeps the inner hash at exactly two
 * blocks: 64 bytes of padded key, the message, one 0x80 byte and an
 * 8-byte length still fit in 128. A BFD auth packet is 52. */
#define HMAC_SHA1_MAX_MSG 55

/* Opaque to the optimiser. A bpf-to-bpf callee must set R0, and LLVM would
 * otherwise fold away a constant return. */
static __always_inline int sha1_barrier(int v)
{
	__asm__ __volatile__("" : "+r"(v));
	return v;
}

#define SHA1_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* One block into the state. The message schedule rolls through 16 words
 * instead of expanding to 80, which keeps this off the BPF stack limit
 * with room to spare. */
SHA1_CORE int sha1_compress(__u32 h[5], const __u8 b[SHA1_BLOCK_LEN])
{
	__u32 w[16];
	__u32 a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
	int i;

SHA1_UNROLL
	for (i = 0; i < 16; i++)
		w[i] = ((__u32)b[4 * i] << 24) | ((__u32)b[4 * i + 1] << 16) |
		       ((__u32)b[4 * i + 2] << 8) | (__u32)b[4 * i + 3];

	/* A loop: unrolled, eighty rounds spill past the BPF frame. */
	for (i = 0; i < 80; i++) {
		__u32 f, k, t, wi;

		if (i < 16) {
			wi = w[i];
		} else {
			wi = w[(i + 13) & 15] ^ w[(i + 8) & 15] ^
			     w[(i + 2) & 15] ^ w[i & 15];
			wi = SHA1_ROTL(wi, 1);
			w[i & 15] = wi;
		}

		if (i < 20) {
			f = (bb & c) | (~bb & d);
			k = 0x5a827999u;
		} else if (i < 40) {
			f = bb ^ c ^ d;
			k = 0x6ed9eba1u;
		} else if (i < 60) {
			f = (bb & c) | (bb & d) | (c & d);
			k = 0x8f1bbcdcu;
		} else {
			f = bb ^ c ^ d;
			k = 0xca62c1d6u;
		}

		t = SHA1_ROTL(a, 5) + f + e + k + wi;
		e = d;
		d = c;
		c = SHA1_ROTL(bb, 30);
		bb = a;
		a = t;
	}

	h[0] += a;
	h[1] += bb;
	h[2] += c;
	h[3] += d;
	h[4] += e;
	return sha1_barrier(1);
}

static __always_inline void sha1_init(__u32 h[5])
{
	h[0] = 0x67452301u;
	h[1] = 0xefcdab89u;
	h[2] = 0x98badcfeu;
	h[3] = 0x10325476u;
	h[4] = 0xc3d2e1f0u;
}

static __always_inline void sha1_out(const __u32 h[5], __u8 out[SHA1_DIGEST_LEN])
{
	int i;

SHA1_UNROLL
	for (i = 0; i < 5; i++) {
		out[4 * i]     = (__u8)(h[i] >> 24);
		out[4 * i + 1] = (__u8)(h[i] >> 16);
		out[4 * i + 2] = (__u8)(h[i] >> 8);
		out[4 * i + 3] = (__u8)h[i];
	}
}

/* Finish a hash whose leading whole blocks are already in `h`.
 *
 * `blk` holds `len` message bytes, zero past them, and is padded in place.
 * `prior` is the byte count of the leading blocks. Takes a pre-padded block
 * because a data-dependent copy loop makes the verifier fork on every
 * iteration. */
static __always_inline int sha1_finish(__u32 h[5], __u8 blk[SHA1_BLOCK_LEN], __u32 len,
			   __u64 prior, __u8 out[SHA1_DIGEST_LEN])
{
	__u64 bits = (prior + len) * 8;
	int i;

	if (len >= SHA1_BLOCK_LEN)
		return 0;

	blk[len] = 0x80;

	/* No room for the 8-byte length after the 0x80: this block goes as
	 * it stands and the trailer takes a zeroed one of its own. */
	if (len + 9 > SHA1_BLOCK_LEN) {
		if (!sha1_compress(h, blk))
			return 0;
		for (i = 0; i < SHA1_BLOCK_LEN; i++)
			blk[i] = 0;
	}

	for (i = 0; i < 8; i++)
		blk[SHA1_BLOCK_LEN - 1 - i] = (__u8)(bits >> (8 * i));

	if (!sha1_compress(h, blk))
		return 0;
	sha1_out(h, out);
	return sha1_barrier(1);
}

/* SHA1 of a message shorter than one block. Host side, for tests. */
static inline int sha1_short(const __u8 *msg, __u32 len, __u8 out[SHA1_DIGEST_LEN])
{
	__u8 blk[SHA1_BLOCK_LEN] = {};
	__u32 h[5];
	__u32 i;

	if (len >= SHA1_BLOCK_LEN)
		return 0;
	for (i = 0; i < len; i++)
		blk[i] = msg[i];
	sha1_init(h);
	return sha1_finish(h, blk, len, 0, out);
}

/* HMAC-SHA1 (RFC 2104) over pre-padded blocks. `kpad` is the key zero-filled
 * to a block, which is K' for any short key. `msgblk` is the message,
 * zero-filled, and is written to. Returns 0 without touching `out` if the
 * message does not fit one block. */
SHA1_CORE int hmac_sha1_blocks(const __u8 kpad[SHA1_BLOCK_LEN],
			       __u8 msgblk[SHA1_BLOCK_LEN], __u32 msglen,
			       __u8 out[SHA1_DIGEST_LEN],
			       __u8 tmp[SHA1_BLOCK_LEN])
{
	/* `tmp` is caller-owned scratch (the per-CPU map on the fast path),
	 * keeping 64 bytes off the verifier's 512-byte stack budget.
	 * Clobbered; must not alias the key, message or output. */
	__u32 h[5];
	int i;

	if (msglen > HMAC_SHA1_MAX_MSG)
		return 0;

	/* The inner digest is parked in `out` to save stack. */
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		tmp[i] = 0x36 ^ kpad[i];
	sha1_init(h);
	if (!sha1_compress(h, tmp) ||
	    !sha1_finish(h, msgblk, msglen, SHA1_BLOCK_LEN, out))
		return 0;

	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		tmp[i] = 0x5c ^ kpad[i];
	sha1_init(h);
	if (!sha1_compress(h, tmp))
		return 0;

	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		tmp[i] = (i < SHA1_DIGEST_LEN) ? out[i] : 0;
	if (!sha1_finish(h, tmp, SHA1_DIGEST_LEN, SHA1_BLOCK_LEN, out))
		return 0;
	return 1;
}

/* Plain key and message. Host side only: the copies loop over runtime lengths,
 * which the verifier cannot take; the fast path uses hmac_sha1_blocks. */
static inline int hmac_sha1(const __u8 *key, __u32 keylen, const __u8 *msg,
			    __u32 msglen, __u8 out[SHA1_DIGEST_LEN])
{
	__u8 kpad[SHA1_BLOCK_LEN] = {};
	__u8 mblk[SHA1_BLOCK_LEN] = {};
	__u32 i;

	if (keylen > SHA1_BLOCK_LEN || msglen > HMAC_SHA1_MAX_MSG)
		return 0;
	for (i = 0; i < keylen; i++)
		kpad[i] = key[i];
	for (i = 0; i < msglen; i++)
		mblk[i] = msg[i];
	{
		__u8 tmp[SHA1_BLOCK_LEN];

		return hmac_sha1_blocks(kpad, mblk, msglen, out, tmp);
	}
}

#endif /* BFD_HMAC_SHA1_H */
