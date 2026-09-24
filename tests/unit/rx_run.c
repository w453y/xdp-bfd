// SPDX-License-Identifier: GPL-2.0
/* rx_run.c - rx_accept as a table, over the real rx.o and session.o; no sockets, BPF or root. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "bfd_auth.h"
#include "session.h"
#include "rx.h"

static int fails;

static void report(const char *name, int bad, const char *detail)
{
	if (bad) {
		printf("FAIL %-44s %s\n", name, detail ? detail : "");
		fails++;
	} else {
		printf("ok   %-44s %s\n", name, detail ? detail : "");
	}
}

static const char *vname(enum rx_verdict v)
{
	switch (v) {
	case RX_ACCEPT:
		return "ACCEPT";
	case RX_MALFORMED:
		return "MALFORMED";
	case RX_TTL:
		return "TTL";
	case RX_NO_SESSION:
		return "NO_SESSION";
	case RX_AUTH:
		return "AUTH";
	}
	return "?";
}

#define PEER4	  "10.0.0.2"
#define LOCAL4	  "10.0.0.1"
#define MY_DISC	  0x11111111u
#define PEER_DISC 0x22222222u
#define KEY_ID	  7
static const char KEY[] = "correcthorse";

static struct bfd_addr A_PEER, A_LOCAL, A_OTHER;

/* Ours, Up, single-hop unless min_ttl says otherwise; auth arms the peer's key. */
static struct session *arm(int auth, uint8_t min_ttl)
{
	struct session *s = &sessions[0];

	memset(sessions, 0, (size_t)sess_max * sizeof(*sessions));
	s->used = 1;
	s->lid = 42;
	s->wire_disc = MY_DISC;
	s->rdisc = PEER_DISC;
	s->peer = A_PEER;
	s->local = A_LOCAL;
	s->family = AF_INET;
	s->state = ST_UP;
	s->detect_mult = 3;
	s->min_ttl = min_ttl;
	s->is_mhop = min_ttl < 255;
	if (auth) {
		struct auth_key *k = &s->auth_keys[0];

		s->auth_present = 1;
		s->auth_nkeys = 1;
		s->auth_type = BFD_AUTH_KEYED_SHA1;
		k->type = BFD_AUTH_KEYED_SHA1;
		k->key_id = KEY_ID;
		k->keylen = (uint8_t)strlen(KEY);
		memcpy(k->kpad, KEY, strlen(KEY));
		k->accept_start = 0; /* 0 means always, as bfdd spells it */
		k->send_start = 0;
	}
	return s;
}

/* Zeroed to BFD_MAX_LEN, as rx_drain gives it. Returns the datagram length. */
static size_t build(__u8 *buf, uint8_t state, uint32_t your_disc)
{
	struct bfd_ctrl_pkt *h = (void *)buf;

	memset(buf, 0, BFD_MAX_LEN);
	h->vers_diag = (1 << 5);
	h->flags = (uint8_t)(state << 6);
	h->detect_mult = 3;
	h->len = BFD_MIN_LEN;
	h->my_disc = htonl(PEER_DISC);
	h->your_disc = htonl(your_disc);
	h->min_tx = htonl(50000);
	h->min_rx = htonl(50000);
	return BFD_MIN_LEN;
}

/* Signed as the peer would. */
static size_t build_auth(__u8 *buf, uint8_t state, uint32_t your_disc, uint8_t key_id,
			 const char *key, uint32_t seq)
{
	struct bfd_ctrl_pkt *h = (void *)buf;
	__u8 kpad[64] = { 0 };
	__u8 len;

	build(buf, state, your_disc);
	memcpy(kpad, key, strlen(key));

	/* The digest covers the header. */
	h->flags |= BFD_F_AUTH;
	h->len = bfd_auth_pkt_len(BFD_AUTH_KEYED_SHA1, (__u8)strlen(key));
	len = bfd_auth_build(buf, BFD_AUTH_KEYED_SHA1, key_id, kpad, (__u8)strlen(key), kpad, seq);
	return len;
}

static void check(const char *name, const __u8 *pkt, size_t n, int ttl, const struct bfd_addr *from,
		  const struct bfd_addr *to, int mhop, enum rx_verdict want, const char *detail)
{
	enum rx_verdict got = (enum rx_verdict)(-1);
	struct session *s = rx_accept(pkt, n, ttl, from, to, mhop, &got);
	char msg[160];

	if (got != want || (want == RX_ACCEPT) != (s != NULL)) {
		snprintf(msg, sizeof(msg), "got %s%s, want %s", vname(got),
			 s ? " (session)" : " (none)", vname(want));
		report(name, 1, msg);
		return;
	}
	report(name, 0, detail);
}

int main(void)
{
	__u8 buf[BFD_MAX_LEN];
	size_t n;

	if (sess_table_init(BFD_MAX_SESSIONS))
		return 1;

	key_set_v4(&A_PEER, inet_addr(PEER4));
	key_set_v4(&A_LOCAL, inet_addr(LOCAL4));
	key_set_v4(&A_OTHER, inet_addr("10.0.0.9"));

	/* --- the port names the session type (RFC 5881 s4, RFC 5883 s5) --- */
	arm(0, 200);
	n = build(buf, ST_UP, MY_DISC);
	check("mhop-session-on-3784-refused", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_NO_SESSION,
	      "multihop is 4784 only");
	arm(0, 255);
	n = build(buf, ST_UP, MY_DISC);
	check("1hop-session-on-4784-refused", buf, n, 255, &A_PEER, &A_LOCAL, 1, RX_NO_SESSION,
	      "single-hop is 3784 only");

	/* --- the happy path, and the demux --- */
	arm(0, 255);
	n = build(buf, ST_UP, MY_DISC);
	check("accept-single-hop", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_ACCEPT,
	      "your_disc names us, ttl 255");

	n = build(buf, ST_UP, 0xdeadbeef);
	check("demux-wrong-your-disc", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_NO_SESSION,
	      "a discriminator we never issued");

	/* Down with 0 may match on the pair; Up with 0 may not, or a forger
	 * knowing the pair could feed any session.
	 */
	n = build(buf, ST_DOWN, 0);
	check("demux-zero-disc-down-falls-back", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_ACCEPT,
	      "peer lost state: pair answers");
	n = build(buf, ST_UP, 0);
	check("demux-zero-disc-up-refused", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_NO_SESSION,
	      "no fallback for a peer claiming Up");
	n = build(buf, ST_DOWN, 0);
	check("demux-wrong-pair", buf, n, 255, &A_OTHER, &A_LOCAL, 0, RX_NO_SESSION, "");

	/* --- the header predicate --- */
	n = build(buf, ST_UP, MY_DISC);
	buf[0] = (0 << 5); /* version 0 */
	check("malformed-version", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_MALFORMED, "");
	n = build(buf, ST_UP, MY_DISC);
	((struct bfd_ctrl_pkt *)buf)->len = BFD_MIN_LEN + 8; /* lies long */
	check("malformed-length-lies", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_MALFORMED,
	      "len past the datagram");
	n = build(buf, ST_UP, MY_DISC);
	((struct bfd_ctrl_pkt *)buf)->detect_mult = 0;
	check("malformed-mult-zero", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_MALFORMED, "");

	/* --- GTSM --- */
	n = build(buf, ST_UP, MY_DISC);
	check("gtsm-single-hop-254", buf, n, 254, &A_PEER, &A_LOCAL, 0, RX_TTL,
	      "single hop wants exactly 255");
	check("gtsm-single-hop-no-cmsg", buf, n, -1, &A_PEER, &A_LOCAL, 0, RX_TTL,
	      "a missing cmsg is a refusal, not a pass");

	arm(0, 200);
	check("gtsm-multihop-at-minimum", buf, n, 200, &A_PEER, &A_LOCAL, 1, RX_ACCEPT,
	      "ttl 200, minimum 200");
	check("gtsm-multihop-above-minimum", buf, n, 240, &A_PEER, &A_LOCAL, 1, RX_ACCEPT, "");
	check("gtsm-multihop-below-minimum", buf, n, 199, &A_PEER, &A_LOCAL, 1, RX_TTL, "");
	check("gtsm-multihop-no-cmsg", buf, n, -1, &A_PEER, &A_LOCAL, 1, RX_TTL, "");
	/* The multihop minimum is the session's, so demux runs first. */
	n = build(buf, ST_UP, 0xdeadbeef);
	check("gtsm-multihop-unknown-session-first", buf, n, 1, &A_PEER, &A_LOCAL, 1,
	      RX_NO_SESSION, "demux before the minimum");

	/* --- authentication (RFC 5880 s6.7) --- */
	arm(1, 255);
	n = build(buf, ST_UP, MY_DISC);
	check("auth-bare-packet-on-authed-session", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_AUTH,
	      "no A bit where the session requires one");

	arm(1, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, KEY, 1);
	check("auth-signed-accepted", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_ACCEPT,
	      "correct key and digest");

	arm(1, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, KEY, 1);
	buf[BFD_MIN_LEN + 8] ^= 0xff; /* one digest byte */
	check("auth-bad-digest", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_AUTH,
	      "one flipped digest byte");

	arm(1, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, "wrongkey", 1);
	check("auth-wrong-key", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_AUTH,
	      "signed with a key we do not hold");

	arm(1, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID + 1, KEY, 1);
	check("auth-unknown-key-id", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_AUTH,
	      "names a key id we never configured");

	/* The other half of the rollover rule. */
	arm(1, 255);
	sessions[0].auth_keys[0].accept_start = (int64_t)time(NULL) + 3600;
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, KEY, 1);
	check("auth-key-not-yet-acceptable", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_AUTH,
	      "accept period has not opened");

	/* A peer must not add or strip authentication. */
	arm(0, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, KEY, 1);
	check("auth-signed-on-bare-session", buf, n, 255, &A_PEER, &A_LOCAL, 0, RX_AUTH,
	      "A bit where the session has no key");

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
