// SPDX-License-Identifier: GPL-2.0
/* bfd_auth.h - the authentication section (RFC 5880 s6.7): simple password and
 * keyed SHA1, plain and meticulous, the types bfdd produces.
 *
 * The digest follows bfdd, not the RFC: bfdd zeroes the digest field and
 * computes an HMAC, where s6.7.3 describes a plain SHA1 with the key in the
 * field. The two do not interoperate.
 */
#ifndef BFD_AUTH_H
#define BFD_AUTH_H

#include "bfd_shared.h"
#include "hmac_sha1.h"

/* HMAC over a control packet with the digest field zeroed, as bfdd does.
 * Userspace only; the fast path calls hmac_sha1_blocks directly. `pkt` must
 * hold BFD_MIN_LEN + BFD_AUTH_SHA1_LEN bytes.
 */
static inline int bfd_auth_sha1(const __u8 *pkt, const __u8 kpad[SHA1_BLOCK_LEN],
				__u8 out[SHA1_DIGEST_LEN])
{
	__u8 blk[SHA1_BLOCK_LEN] = {};
	int i;

	for (i = 0; i < BFD_MIN_LEN + BFD_AUTH_SHA1_LEN; i++)
		blk[i] = pkt[i];
	for (i = 0; i < SHA1_DIGEST_LEN; i++)
		blk[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF + i] = 0;

	__u8 tmp[SHA1_BLOCK_LEN];

	return hmac_sha1_blocks(kpad, blk, BFD_MIN_LEN + BFD_AUTH_SHA1_LEN, out, tmp);
}

/* How long a packet of this type is. 0 for a type we do not produce. */
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

/* Append the auth section to a 24-byte packet whose `len` and A bit are set;
 * return the packet length, or 0 on refusal. `pkt` needs room for BFD_MAX_LEN.
 */
static inline __u8 bfd_auth_build(__u8 *pkt, __u8 auth_type, __u8 keyid, const __u8 *key,
				  __u8 keylen, const __u8 kpad[SHA1_BLOCK_LEN], __u32 seq)
{
	__u8 len = bfd_auth_pkt_len(auth_type, keylen);
	__u8 *a = pkt + BFD_MIN_LEN;
	int i;

	if (!len)
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

	if (!bfd_auth_sha1(pkt, kpad, a + BFD_AUTH_SHA1_DIG_OFF))
		return 0;
	return len;
}

/* Is the sequence inside the replay window (RFC 5880 s6.7.4)? [rx_seq, rx_seq
 * + 3*mult], starting at +1 for meticulous, in circular unsigned space.
 */
static inline int bfd_auth_seq_ok(__u32 seq, __u32 rx_seq, int meticulous, __u8 mult)
{
	__u32 lo = meticulous ? 1u : 0u;
	__u32 span = 3u * (mult ? mult : 3u);
	__u32 d = seq - rx_seq; /* circular distance, deliberately unsigned */

	return d >= lo && d <= span;
}

/* Why an authenticated packet was not accepted. */
enum bfd_auth_verdict {
	BFD_AUTH_OK = 0,
	BFD_AUTH_MALFORMED, /* section absent, short, or the wrong type */
	BFD_AUTH_BADKEY,    /* key id or password does not match */
	BFD_AUTH_BADDIGEST,
	BFD_AUTH_REPLAY, /* sequence number outside the replay window */
};

/* Check a received packet's auth section. `rx_seq` and `seen` carry the replay
 * window and change only on success; the first packet sets the window, as in
 * bfdd, so a restarted peer can resync. `mult` is the packet's Detect Mult
 * (s6.7.4).
 */
static inline int bfd_auth_check(const __u8 *pkt, __u8 len, __u8 auth_type, __u8 keyid,
				 const __u8 *key, __u8 keylen, const __u8 kpad[SHA1_BLOCK_LEN],
				 __u32 *rx_seq, int *seen, __u8 mult)
{
	const __u8 *a = pkt + BFD_MIN_LEN;
	__u8 want = bfd_auth_pkt_len(auth_type, keylen);
	__u8 dig[SHA1_DIGEST_LEN];
	__u32 seq;
	int i;

	if (!want || len != want || len < BFD_MIN_LEN + 3)
		return BFD_AUTH_MALFORMED;
	if (a[0] != auth_type || a[1] != len - BFD_MIN_LEN)
		return BFD_AUTH_MALFORMED;
	if (a[2] != keyid)
		return BFD_AUTH_BADKEY;

	if (auth_type == BFD_AUTH_SIMPLE) {
		__u8 diff = 0;

		/* Constant time over the configured length: a password
		 * compare that returns early leaks it a byte at a time.
		 */
		for (i = 0; i < keylen; i++)
			diff |= (__u8)(a[BFD_AUTH_SIMPLE_HDR + i] ^ key[i]);
		return diff ? BFD_AUTH_BADKEY : BFD_AUTH_OK;
	}

	seq = ((__u32)a[BFD_AUTH_SHA1_SEQ_OFF] << 24) |
	      ((__u32)a[BFD_AUTH_SHA1_SEQ_OFF + 1] << 16) |
	      ((__u32)a[BFD_AUTH_SHA1_SEQ_OFF + 2] << 8) | (__u32)a[BFD_AUTH_SHA1_SEQ_OFF + 3];

	if (*seen && !bfd_auth_seq_ok(seq, *rx_seq, auth_type == BFD_AUTH_METICULOUS_SHA1, mult))
		return BFD_AUTH_REPLAY;

	if (!bfd_auth_sha1(pkt, kpad, dig))
		return BFD_AUTH_MALFORMED;
	{
		__u8 diff = 0;

		for (i = 0; i < SHA1_DIGEST_LEN; i++)
			diff |= (__u8)(dig[i] ^ a[BFD_AUTH_SHA1_DIG_OFF + i]);
		if (diff)
			return BFD_AUTH_BADDIGEST;
	}

	/* Advance on every accepted packet, or the window never moves. */
	*rx_seq = seq;
	*seen = 1;
	return BFD_AUTH_OK;
}

#endif /* BFD_AUTH_H */
