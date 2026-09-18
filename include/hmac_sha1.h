// SPDX-License-Identifier: GPL-2.0
/*
 * hmac_sha1.h - SHA1 and HMAC-SHA1, compiled by both planes.
 *
 * BFD authentication (RFC 5880 s6.7) needs a keyed digest over the
 * control packet, and the kernel offers no hashing kfunc - bpf_crypto_*
 * is skcipher only - so the fast path has to carry its own. One
 * implementation, included by src/xdp/ and src/engine/ alike, because a
 * digest that disagrees between the two planes fails closed on every
 * packet and looks exactly like a wrong key.
 *
 * Bounded on purpose. A BFD control packet with a keyed-SHA1 auth
 * section is 52 bytes, so nothing here loops over packet data: the
 * message never exceeds one block, and the whole HMAC is four fixed
 * block compressions. The limits are asserted rather than assumed, and
 * every entry point returns 0 and writes nothing when they are exceeded,
 * so an oversized input cannot silently produce a partial digest.
 */
#ifndef BFD_HMAC_SHA1_H
#define BFD_HMAC_SHA1_H

#include <linux/types.h>

/* Both spellings exist only on the BPF side, where bpf_helpers.h
 * supplies them. The host build needs its own. */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifdef __clang__
#define SHA1_UNROLL _Pragma("unroll")
#else
#define SHA1_UNROLL
#endif

/* The block compression and the padding step get their own stack frames
 * on the BPF side rather than being inlined. Forced inline they are
 * expanded six times between them - four compressions, two finishes -
 * and each expansion keeps its own message schedule, which overruns the
 * 512-byte BPF stack. As calls they cost one frame each, well inside the
 * verifier's nesting limit. The host build inlines as it likes. */
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

/* Opaque to the optimiser.
 *
 * The two functions below are called, not inlined, and a bpf-to-bpf
 * callee must leave a scalar in R0 or the verifier rejects whatever the
 * frame happened to hold there. Both return a constant, and LLVM sees
 * every caller of a static function, so it propagates that constant and
 * never emits the assignment. Laundering the value through an empty asm
 * makes it opaque and forces the return to be real.
 */
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

	/* Deliberately a loop. Unrolled, eighty rounds of live state spill
	 * past the BPF frame; as a loop the whole compression fits in
	 * well under half of it, and the verifier walks it without
	 * complaint. */
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
 * Inlined, unlike the compression: the block belongs to the caller, so
 * this holds two scalars and a frame of its own would be pure overhead
 * against the verifier's 512-byte budget for the whole call chain.
 *
 * `blk` is one 64-byte block holding `len` message bytes with the rest
 * already zero, and it is written to: the padding goes in place. `prior`
 * is how many bytes the leading blocks held, since the length SHA1
 * appends counts the whole message.
 *
 * Takes a padded block rather than a pointer and a length because the
 * copy loop that would fill it is data-dependent, and the verifier forks
 * its state on every one of 64 iterations. A caller on the fast path has
 * to assemble the block anyway - the digest field has to be zeroed
 * before hashing - so nothing is lost.
 */
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

/* SHA1 of a message shorter than one block. Host side only, and used by
 * the tests rather than by either plane; the fast path always has a key
 * and goes through the HMAC below. */
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

/* HMAC-SHA1 (RFC 2104) over pre-padded blocks.
 *
 * `kpad` is the key in a 64-byte block, zero-filled past its length -
 * which is also how RFC 2104 defines K' for any key shorter than a
 * block, so nothing here needs the key length at all. `msgblk` is the
 * message in a 64-byte block, likewise zero-filled, and is written to.
 *
 * Returns 0 without touching `out` when the message is too long for a
 * single block to hold it and its padding. A truncated digest is never
 * an option: it would differ from the peer's on every packet and read
 * exactly like a wrong key.
 */
SHA1_CORE int hmac_sha1_blocks(const __u8 kpad[SHA1_BLOCK_LEN],
			       __u8 msgblk[SHA1_BLOCK_LEN], __u32 msglen,
			       __u8 out[SHA1_DIGEST_LEN],
			       __u8 tmp[SHA1_BLOCK_LEN])
{
	/* One block buffer, not two, and the caller's rather than ours.
	 *
	 * The BPF verifier charges a whole call chain against a single
	 * 512-byte budget, and this sits under the packet path, so the
	 * sixty-four bytes were the largest thing in the chain that did not
	 * have to be on the stack. On the fast path `tmp` is a region of
	 * the per-CPU scratch map, which costs no stack at all; a host
	 * caller passes a local and pays what it used to.
	 *
	 * It measured: the chain came to 544 bytes under a 6.1 verifier's
	 * accounting, against a 512 budget, and this is what brought it
	 * under. A newer verifier accounted the same chain differently and
	 * accepted it, which is the argument for the margin rather than
	 * against it.
	 *
	 * Caller-owned, clobbered, and must alias neither the key, the
	 * message block nor the output. The key pad is dead the moment it
	 * has been compressed, which is before the buffer is needed again
	 * for the inner digest, so one region serves both. */
	__u32 h[5];
	int i;

	if (msglen > HMAC_SHA1_MAX_MSG)
		return 0;

	/* The inner digest is parked in `out` rather than in a local of its
	 * own. The verifier charges a whole call chain against 512 bytes
	 * and this sits under the packet path, so twenty bytes is worth
	 * having. `out` must not alias the key or the message block, which
	 * no caller has reason to do. */
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

/* The same thing for a caller holding a plain key and message.
 *
 * Host side only. The two copies below are bounded by runtime lengths,
 * which is the shape that makes the verifier enumerate every iteration -
 * on the fast path use hmac_sha1_blocks and assemble the blocks there.
 */
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
