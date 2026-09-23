// SPDX-License-Identifier: GPL-2.0
/* hmac_sha1.h - SHA1 and HMAC-SHA1 for both planes, since the kernel has no
 * hashing kfunc. A keyed SHA1 packet is 52 bytes, so the HMAC is four fixed
 * compressions; oversized input returns 0.
 */
#ifndef BFD_HMAC_SHA1_H
#define BFD_HMAC_SHA1_H

#include <linux/types.h>

/* The BPF side gets it from bpf_helpers.h. */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifdef __clang__
#define SHA1_UNROLL _Pragma("unroll")
#else
#define SHA1_UNROLL
#endif

/* Real calls on BPF: inlined, their schedules overrun the 512-byte stack. */
#if defined(__bpf__)
#define SHA1_CORE static __attribute__((noinline))
#else
#define SHA1_CORE static inline
#endif

#define SHA1_DIGEST_LEN 20
#define SHA1_BLOCK_LEN	64

/* Keeps the inner hash at two blocks: 64 bytes of key, the message, 0x80 and an
 * 8-byte length fit 128.
 */
#define HMAC_SHA1_MAX_MSG 55

/* A bpf-to-bpf callee must set R0, and LLVM would fold a constant return away. */
static __always_inline int sha1_barrier(int v)
{
	__asm__ __volatile__("" : "+r"(v));
	return v;
}

#define SHA1_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* The schedule rolls through 16 words, not 80, to stay within the BPF stack. */
SHA1_CORE int sha1_compress(__u32 h[5], const __u8 b[SHA1_BLOCK_LEN])
{
	__u32 w[16];
	__u32 a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
	int i;

	SHA1_UNROLL
	for (i = 0; i < 16; i++)
		w[i] = ((__u32)b[4 * i] << 24) | ((__u32)b[4 * i + 1] << 16) |
		       ((__u32)b[4 * i + 2] << 8) | (__u32)b[4 * i + 3];

	/* Unrolled, eighty rounds spill past the BPF frame. */
	for (i = 0; i < 80; i++) {
		__u32 f, k, t, wi;

		if (i < 16) {
			wi = w[i];
		} else {
			wi = w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i & 15];
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
		out[4 * i] = (__u8)(h[i] >> 24);
		out[4 * i + 1] = (__u8)(h[i] >> 16);
		out[4 * i + 2] = (__u8)(h[i] >> 8);
		out[4 * i + 3] = (__u8)h[i];
	}
}

/* blk holds len bytes, zero past them, and is padded in place; prior counts the
 * leading blocks. Pre-padded, since a data-dependent copy loop forks the
 * verifier every iteration.
 */
static __always_inline int sha1_finish(__u32 h[5], __u8 blk[SHA1_BLOCK_LEN], __u32 len,
				       __u64 prior, __u8 out[SHA1_DIGEST_LEN])
{
	__u64 bits = (prior + len) * 8;
	int i;

	if (len >= SHA1_BLOCK_LEN)
		return 0;

	blk[len] = 0x80;

	/* No room for the length: this block goes as is, the trailer gets its own. */
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

/* Host side, for tests. */
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

/* RFC 2104 over pre-padded blocks: kpad is the key zero-filled to a block,
 * msgblk the message, written to. 0 without touching out if the message does
 * not fit.
 */
SHA1_CORE int hmac_sha1_blocks(const __u8 kpad[SHA1_BLOCK_LEN], __u8 msgblk[SHA1_BLOCK_LEN],
			       __u32 msglen, __u8 out[SHA1_DIGEST_LEN], __u8 tmp[SHA1_BLOCK_LEN])
{
	/* tmp is caller scratch, off the 512-byte stack; must not alias the others. */
	__u32 h[5];
	int i;

	if (msglen > HMAC_SHA1_MAX_MSG)
		return 0;

	/* Inner digest parked in out to save stack. */
	for (i = 0; i < SHA1_BLOCK_LEN; i++)
		tmp[i] = 0x36 ^ kpad[i];
	sha1_init(h);
	if (!sha1_compress(h, tmp) || !sha1_finish(h, msgblk, msglen, SHA1_BLOCK_LEN, out))
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

/* Host side only: runtime-length copies the verifier cannot take. */
static inline int hmac_sha1(const __u8 *key, __u32 keylen, const __u8 *msg, __u32 msglen,
			    __u8 out[SHA1_DIGEST_LEN])
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
