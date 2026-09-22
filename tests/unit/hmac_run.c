// SPDX-License-Identifier: GPL-2.0
/* hmac_run.c - the shared HMAC-SHA1 on the host, against known answers.
 * xdp_run runs the same vectors through the kernel.
 *
 *     make test-hmac
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "hmac_sha1.h"
#include "hmac_vectors.h"

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

/* The block API is what the fast path calls, so it is checked directly
 * rather than only through the padding wrapper above.
 */
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

int main(void)
{
	for (int i = 0; i < HMAC_NVECS; i++)
		case_vec(&hmac_vecs[i]);
	for (int i = 0; i < HMAC_NVECS; i++)
		case_blocks(&hmac_vecs[i]);
	case_refusal();

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
