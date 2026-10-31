// SPDX-License-Identifier: GPL-2.0
/* bfd_auth.h - the RFC 5880 s6.7 section: simple password, keyed and
 * meticulous SHA1. A keyed SHA1 key uses the RFC's digest with
 * BFD_AUTH_F_RFC_SHA1, else bfdd's HMAC; the two do not interoperate.
 */
#ifndef BFD_AUTH_H
#define BFD_AUTH_H

#include "bfd_shared.h"
#include "hmac_sha1.h"

/* The RFC form: SHA1 of a message that pads into one block, as sha1_finish
 * takes it.
 */
SHA1_CORE int sha1_block(__u8 blk[SHA1_BLOCK_LEN], __u32 len, __u8 out[SHA1_DIGEST_LEN])
{
	__u32 h[5];

	if (len > SHA1_BLOCK_LEN - 9)
		return 0;
	sha1_init(h);
	return sha1_finish(h, blk, len, 0, out);
}

/* Userspace only. pkt holds BFD_MIN_LEN + BFD_AUTH_SHA1_LEN bytes; kpad is
 * zero past the key, which pads it for the RFC form.
 */
static inline int bfd_auth_sha1(const __u8 *pkt, const __u8 kpad[SHA1_BLOCK_LEN], __u8 flags,
				__u8 out[SHA1_DIGEST_LEN])
{
	int rfc = flags & BFD_AUTH_F_RFC_SHA1;
	__u8 blk[SHA1_BLOCK_LEN] = {};
	int i;

	for (i = 0; i < BFD_MIN_LEN + BFD_AUTH_SHA1_LEN; i++)
		blk[i] = pkt[i];
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = rfc ? kpad[i] : 0;

	if (rfc)
		return sha1_block(blk, BFD_MIN_LEN + BFD_AUTH_SHA1_LEN, out);

	__u8 tmp[SHA1_BLOCK_LEN];

	return hmac_sha1_blocks(kpad, blk, BFD_MIN_LEN + BFD_AUTH_SHA1_LEN, out, tmp);
}

/* 0 for a type we do not produce. */
static inline __u8 bfd_auth_pkt_len(__u8 auth_type, __u8 keylen)
{
	if (auth_type == BFD_AUTH_SIMPLE)
		return keylen && keylen <= BFD_AUTH_SIMPLE_MAXKEY
			       ? BFD_MIN_LEN + BFD_AUTH_SIMPLE_HDR + keylen
			       : 0;
	if (auth_type == BFD_AUTH_KEYED_SHA1 || auth_type == BFD_AUTH_METICULOUS_SHA1)
		return BFD_MIN_LEN + BFD_AUTH_SHA1_LEN;
	return 0;
}

/* Whether we can sign and verify with this key. */
static inline int bfd_auth_key_ok(__u8 auth_type, __u8 flags, __u8 keylen)
{
	if (!bfd_auth_pkt_len(auth_type, keylen) || (flags & ~BFD_AUTH_F_RFC_SHA1))
		return 0;
	if (!(flags & BFD_AUTH_F_RFC_SHA1))
		return 1;
	return (auth_type == BFD_AUTH_KEYED_SHA1 || auth_type == BFD_AUTH_METICULOUS_SHA1) &&
	       keylen <= BFD_AUTH_RFC_SHA1_MAXKEY;
}

/* Append to a 24-byte packet with len and the A bit set. Returns the length, 0
 * on refusal; pkt needs BFD_MAX_LEN.
 */
static inline __u8 bfd_auth_build(__u8 *pkt, __u8 auth_type, __u8 keyid, const __u8 *key,
				  __u8 keylen, const __u8 kpad[SHA1_BLOCK_LEN], __u8 flags,
				  __u32 seq)
{
	__u8 len = bfd_auth_pkt_len(auth_type, keylen);
	__u8 *a = pkt + BFD_MIN_LEN;
	int i;

	if (!len || !bfd_auth_key_ok(auth_type, flags, keylen))
		return 0;

	a[0] = auth_type;
	a[1] = len - BFD_MIN_LEN;
	a[2] = keyid;

	if (auth_type == BFD_AUTH_SIMPLE) {
		for (i = 0; i < keylen; i++)
			a[BFD_AUTH_SIMPLE_HDR + i] = key[i];
		return len;
	}

	a[3] = 0;
	a[BFD_AUTH_SHA1_SEQ_OFF] = (__u8)(seq >> 24);
	a[BFD_AUTH_SHA1_SEQ_OFF + 1] = (__u8)(seq >> 16);
	a[BFD_AUTH_SHA1_SEQ_OFF + 2] = (__u8)(seq >> 8);
	a[BFD_AUTH_SHA1_SEQ_OFF + 3] = (__u8)seq;
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		a[BFD_AUTH_SHA1_DIG_OFF + i] = 0;

	if (!bfd_auth_sha1(pkt, kpad, flags, a + BFD_AUTH_SHA1_DIG_OFF))
		return 0;
	return len;
}

/* RFC 5880 s6.7.4: [rx_seq, rx_seq + 3*mult], from +1 if meticulous, circular. */
static inline int bfd_auth_seq_ok(__u32 seq, __u32 rx_seq, int meticulous, __u8 mult)
{
	__u32 lo = meticulous ? 1u : 0u;
	__u32 span = 3u * (mult ? mult : 3u);
	__u32 d = seq - rx_seq; /* circular, deliberately unsigned */

	return d >= lo && d <= span;
}

enum bfd_auth_verdict {
	BFD_AUTH_OK = 0,
	BFD_AUTH_MALFORMED, /* section absent, short, or the wrong type */
	BFD_AUTH_BADKEY,    /* key id or password does not match */
	BFD_AUTH_BADDIGEST,
	BFD_AUTH_REPLAY, /* sequence number outside the replay window */
};

/* rx_seq and seen change only on success. The first packet sets the window, as
 * bfdd does. mult is the packet's Detect Mult (s6.7.4).
 */
static inline int bfd_auth_check(const __u8 *pkt, __u8 len, __u8 auth_type, __u8 keyid,
				 const __u8 *key, __u8 keylen, const __u8 kpad[SHA1_BLOCK_LEN],
				 __u8 flags, __u32 *rx_seq, int *seen, __u8 mult)
{
	const __u8 *a = pkt + BFD_MIN_LEN;
	__u8 want = bfd_auth_pkt_len(auth_type, keylen);
	__u8 dig[SHA1_DIGEST_LEN];
	__u32 seq;
	int i;

	if (!want || len != want || len < BFD_MIN_LEN + 3 ||
	    !bfd_auth_key_ok(auth_type, flags, keylen))
		return BFD_AUTH_MALFORMED;
	if (a[0] != auth_type || a[1] != len - BFD_MIN_LEN)
		return BFD_AUTH_MALFORMED;
	if (a[2] != keyid)
		return BFD_AUTH_BADKEY;

	if (auth_type == BFD_AUTH_SIMPLE) {
		__u8 diff = 0;

		/* Constant time: an early return leaks the password a byte at a time. */
		for (i = 0; i < keylen; i++)
			diff |= (__u8)(a[BFD_AUTH_SIMPLE_HDR + i] ^ key[i]);
		return diff ? BFD_AUTH_BADKEY : BFD_AUTH_OK;
	}

	seq = ((__u32)a[BFD_AUTH_SHA1_SEQ_OFF] << 24) |
	      ((__u32)a[BFD_AUTH_SHA1_SEQ_OFF + 1] << 16) |
	      ((__u32)a[BFD_AUTH_SHA1_SEQ_OFF + 2] << 8) | (__u32)a[BFD_AUTH_SHA1_SEQ_OFF + 3];

	if (*seen && !bfd_auth_seq_ok(seq, *rx_seq, auth_type == BFD_AUTH_METICULOUS_SHA1, mult))
		return BFD_AUTH_REPLAY;

	if (!bfd_auth_sha1(pkt, kpad, flags, dig))
		return BFD_AUTH_MALFORMED;
	{
		__u8 diff = 0;

		for (i = 0; i < SHA1_DIGEST_LEN; i++)
			diff |= (__u8)(dig[i] ^ a[BFD_AUTH_SHA1_DIG_OFF + i]);
		if (diff)
			return BFD_AUTH_BADDIGEST;
	}

	/* Every accepted packet moves the window. */
	*rx_seq = seq;
	*seen = 1;
	return BFD_AUTH_OK;
}

#endif /* BFD_AUTH_H */
