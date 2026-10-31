// SPDX-License-Identifier: GPL-2.0
/* hmac_run.c - the shared HMAC-SHA1 and the keyed SHA1 section on the host,
 * against known answers; xdp_run runs them in the kernel.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "hmac_sha1.h"
#include "hmac_vectors.h"
#include "bfd_auth.h"
#include "auth_vectors.h"

static int fails;

static void hex(const unsigned char *b, int n, char *out)
{
	for (int i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", b[i]);
}

static void case_vec(const struct hmac_vec *v)
{
	unsigned char got[SHA1_DIGEST_LEN];
	char a[64], b[64];

	if (!hmac_sha1(v->key, v->keylen, v->msg, v->msglen, got)) {
		printf("FAIL %-28s refused key %u msg %u\n", v->name, v->keylen, v->msglen);
		fails++;
		return;
	}
	if (memcmp(v->want, got, SHA1_DIGEST_LEN)) {
		hex(v->want, SHA1_DIGEST_LEN, a);
		hex(got, SHA1_DIGEST_LEN, b);
		printf("FAIL %-28s\n     want %s\n     got  %s\n", v->name, a, b);
		fails++;
		return;
	}
	printf("ok   %-28s key %2u msg %2u\n", v->name, v->keylen, v->msglen);
}

/* The block API is what the fast path calls. */
static void case_blocks(const struct hmac_vec *v)
{
	__u8 kpad[SHA1_BLOCK_LEN] = {}, mblk[SHA1_BLOCK_LEN] = {};
	__u8 tmp[SHA1_BLOCK_LEN];
	unsigned char got[SHA1_DIGEST_LEN];

	memcpy(kpad, v->key, v->keylen);
	memcpy(mblk, v->msg, v->msglen);
	if (!hmac_sha1_blocks(kpad, mblk, v->msglen, got, tmp) ||
	    memcmp(v->want, got, SHA1_DIGEST_LEN)) {
		printf("FAIL %-28s block API disagrees with the wrapper\n", v->name);
		fails++;
		return;
	}
	printf("ok   %-28s via blocks\n", v->name);
}

/* A refused input must leave the output untouched. */
static void case_refusal(void)
{
	unsigned char key[16], msg[128], out[SHA1_DIGEST_LEN];
	__u8 kpad[SHA1_BLOCK_LEN] = {}, mblk[SHA1_BLOCK_LEN] = {};
	__u8 tmp[SHA1_BLOCK_LEN];
	int bad = 0;

	memset(key, 'k', sizeof(key));
	memset(msg, 'm', sizeof(msg));
	memset(out, 0xa5, sizeof(out));

	if (hmac_sha1(key, sizeof(key), msg, HMAC_SHA1_MAX_MSG + 1, out)) {
		printf("     accepted a message over the stated maximum\n");
		bad = 1;
	}
	if (hmac_sha1(key, SHA1_BLOCK_LEN + 1, msg, 16, out)) {
		printf("     accepted a key longer than one block\n");
		bad = 1;
	}
	if (hmac_sha1_blocks(kpad, mblk, HMAC_SHA1_MAX_MSG + 1, out, tmp)) {
		printf("     block API accepted an oversized message\n");
		bad = 1;
	}
	for (int i = 0; i < SHA1_DIGEST_LEN; i++)
		if (out[i] != 0xa5) {
			printf("     wrote into the output on refusal\n");
			bad = 1;
			break;
		}

	if (bad) {
		printf("FAIL %-28s\n", "refusals-write-nothing");
		fails++;
	} else {
		printf("ok   %-28s\n", "refusals-write-nothing");
	}
}

/* Accepted under its own digest only, and rebuilt byte for byte. */
static void case_auth_vec(const struct auth_vec *v)
{
	__u8 klen = (__u8)strlen(v->key);
	__u8 kpad[SHA1_BLOCK_LEN] = {}, buf[BFD_MAX_LEN] = {};
	const __u8 *p = v->pkt;
	__u32 seq = (__u32)p[28] << 24 | (__u32)p[29] << 16 | (__u32)p[30] << 8 | p[31];
	__u32 rx_seq = 0;
	int seen = 0, bad = 0;

	memcpy(kpad, v->key, klen);
	if (bfd_auth_check(p, sizeof(v->pkt), p[24], p[26], (const __u8 *)v->key, klen, kpad,
			   v->flags, &rx_seq, &seen, p[2]) != BFD_AUTH_OK) {
		printf("     refused\n");
		bad = 1;
	}
	rx_seq = 0;
	seen = 0;
	if (bfd_auth_check(p, sizeof(v->pkt), p[24], p[26], (const __u8 *)v->key, klen, kpad,
			   v->flags ^ BFD_AUTH_F_RFC_SHA1, &rx_seq, &seen,
			   p[2]) != BFD_AUTH_BADDIGEST) {
		printf("     the other digest accepted it too\n");
		bad = 1;
	}
	memcpy(buf, p, BFD_MIN_LEN);
	if (bfd_auth_build(buf, p[24], p[26], (const __u8 *)v->key, klen, kpad, v->flags, seq) !=
		    sizeof(v->pkt) ||
	    memcmp(buf, p, sizeof(v->pkt))) {
		printf("     rebuilt section differs\n");
		bad = 1;
	}
	if (bad) {
		printf("FAIL %-28s\n", v->name);
		fails++;
		return;
	}
	printf("ok   %-28s verified and rebuilt\n", v->name);
}

/* An RFC key longer than the digest field cannot be padded into it. */
static void case_auth_rfc_long_key(void)
{
	static const char key[] = "twenty-one-bytes-long";
	__u8 kpad[SHA1_BLOCK_LEN] = {}, buf[BFD_MAX_LEN] = {};
	int bad = 0;

	memcpy(kpad, key, sizeof(key) - 1);
	buf[0] = 0x20;
	buf[1] = BFD_F_AUTH;
	buf[3] = BFD_MAX_LEN;
	if (bfd_auth_build(buf, BFD_AUTH_KEYED_SHA1, 1, (const __u8 *)key, sizeof(key) - 1, kpad,
			   BFD_AUTH_F_RFC_SHA1, 1)) {
		printf("     signed with a 21-byte RFC key\n");
		bad = 1;
	}
	if (!bfd_auth_build(buf, BFD_AUTH_KEYED_SHA1, 1, (const __u8 *)key, sizeof(key) - 1, kpad,
			    0, 1)) {
		printf("     refused a 21-byte HMAC key\n");
		bad = 1;
	}
	if (bad) {
		printf("FAIL %-28s\n", "auth-rfc-key-over-20");
		fails++;
		return;
	}
	printf("ok   %-28s refused\n", "auth-rfc-key-over-20");
}

int main(void)
{
	for (int i = 0; i < HMAC_NVECS; i++)
		case_vec(&hmac_vecs[i]);
	for (int i = 0; i < HMAC_NVECS; i++)
		case_blocks(&hmac_vecs[i]);
	case_refusal();
	for (int i = 0; i < AUTH_NVECS; i++)
		case_auth_vec(&auth_vecs[i]);
	case_auth_rfc_long_key();

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
