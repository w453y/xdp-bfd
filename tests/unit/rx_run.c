// SPDX-License-Identifier: GPL-2.0
/* rx_run.c - the receive decision, driven directly.
 *
 * The four drains in main.c differ only in which socket they read and how
 * the addresses come out of the cmsgs; the decision they make once the
 * packet is in hand is rx_accept, and this is that decision as a table.
 *
 * It exists because both authentication findings of the review round sat
 * on this boundary and nothing on the host could reach them: the only
 * coverage was tests/testbed/netns_userspace.py, which needs namespaces,
 * sockets and root to assert the same rules. Those CASES are here as unit
 * rows; the netns rig keeps only what it alone can test, the socket and
 * cmsg plumbing that feeds this function its arguments.
 *
 * Links the real rx.o and session.o. No sockets, no BPF, no root.
 *
 *     make test-rx
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "bfd_auth.h"
#include "session.h"
#include "rx.h"

/* ---------- stubs: what session.o refers to and this does not use ---- */
int use_ktx;
void ktx_clear(struct session *s) { (void)s; }
void ktx_clear_key(const struct bfd_addr *p, const struct bfd_addr *l,
		   uint32_t d) { (void)p; (void)l; (void)d; }
void echo_peer_refresh(const struct bfd_addr *p, struct session *s)
{ (void)p; (void)s; }
void ktx_update_mhop_flag(void) {}

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
	case RX_ACCEPT:     return "ACCEPT";
	case RX_MALFORMED:  return "MALFORMED";
	case RX_TTL:        return "TTL";
	case RX_NO_SESSION: return "NO_SESSION";
	case RX_AUTH:       return "AUTH";
	}
	return "?";
}

/* ---------- fixtures ---------- */
#define PEER4  "10.0.0.2"
#define LOCAL4 "10.0.0.1"
#define MY_DISC   0x11111111u
#define PEER_DISC 0x22222222u
#define KEY_ID 7
static const char KEY[] = "correcthorse";

static struct bfd_addr A_PEER, A_LOCAL, A_OTHER;

/* One session in the table: ours, Up, single-hop unless min_ttl says
 * otherwise. `auth` arms the accept key the peer is expected to sign
 * with. */
static struct session *arm(int auth, uint8_t min_ttl)
{
	struct session *s = &sessions[0];

	memset(sessions, 0, sizeof(sessions));
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
	if (auth) {
		struct auth_key *k = &s->auth_keys[0];

		s->auth_present = 1;
		s->auth_nkeys = 1;
		s->auth_type = BFD_AUTH_KEYED_SHA1;
		k->type = BFD_AUTH_KEYED_SHA1;
		k->key_id = KEY_ID;
		k->keylen = (uint8_t)strlen(KEY);
		memcpy(k->kpad, KEY, strlen(KEY));
		k->accept_start = 0;   /* 0 means always, as bfdd spells it */
		k->send_start = 0;
	}
	return s;
}

/* A control packet in the receive buffer's shape: BFD_MAX_LEN, zeroed,
 * so a short datagram still leaves every header field defined. Returns
 * the datagram length a socket would have reported. */
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

/* The same packet signed the way the peer would sign it. `seq` and the
 * key id are the two things a forger has to get right and cannot. */
static size_t build_auth(__u8 *buf, uint8_t state, uint32_t your_disc,
			 uint8_t key_id, const char *key, uint32_t seq)
{
	struct bfd_ctrl_pkt *h = (void *)buf;
	__u8 kpad[64] = {0};
	__u8 len;

	build(buf, state, your_disc);
	memcpy(kpad, key, strlen(key));

	/* The A bit and the length go on before the signature: the digest
	 * covers the 24-byte header, so setting either afterwards signs a
	 * packet nobody sent. */
	h->flags |= BFD_F_AUTH;
	h->len = bfd_auth_pkt_len(BFD_AUTH_KEYED_SHA1, (__u8)strlen(key));
	len = bfd_auth_build(buf, BFD_AUTH_KEYED_SHA1, key_id,
			     kpad, (__u8)strlen(key), kpad, seq);
	return len;
}

/* ---------- the table ---------- */
static void check(const char *name, const __u8 *pkt, size_t n, int ttl,
		  const struct bfd_addr *from, const struct bfd_addr *to,
		  int mhop, enum rx_verdict want, const char *detail)
{
	enum rx_verdict got = (enum rx_verdict)-1;
	struct session *s = rx_accept(pkt, n, ttl, from, to, mhop, &got);
	char msg[160];

	if (got != want || (want == RX_ACCEPT) != (s != NULL)) {
		snprintf(msg, sizeof(msg), "got %s%s, want %s",
			 vname(got), s ? " (session)" : " (none)", vname(want));
		report(name, 1, msg);
		return;
	}
	report(name, 0, detail);
}

int main(void)
{
	__u8 buf[BFD_MAX_LEN];
	size_t n;

	key_set_v4(&A_PEER, inet_addr(PEER4));
	key_set_v4(&A_LOCAL, inet_addr(LOCAL4));
	key_set_v4(&A_OTHER, inet_addr("10.0.0.9"));

	/* --- the happy path, and the demux --- */
	arm(0, 255);
	n = build(buf, ST_UP, MY_DISC);
	check("accept-single-hop", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_ACCEPT, "your_disc names us, ttl 255");

	n = build(buf, ST_UP, 0xdeadbeef);
	check("demux-wrong-your-disc", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_NO_SESSION, "a discriminator we never issued");

	/* your_disc 0 is the peer saying it has lost state, and is the only
	 * case the address pair may answer. Up with a zero your_disc is not
	 * that case, and taking it would let a forger who knows the pair
	 * feed any session. */
	n = build(buf, ST_DOWN, 0);
	check("demux-zero-disc-down-falls-back", buf, n, 255,
	      &A_PEER, &A_LOCAL, 0, RX_ACCEPT, "peer lost state: pair answers");
	n = build(buf, ST_UP, 0);
	check("demux-zero-disc-up-refused", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_NO_SESSION, "no fallback for a peer claiming Up");
	n = build(buf, ST_DOWN, 0);
	check("demux-wrong-pair", buf, n, 255, &A_OTHER, &A_LOCAL, 0,
	      RX_NO_SESSION, "");

	/* --- the header predicate --- */
	n = build(buf, ST_UP, MY_DISC);
	buf[0] = (0 << 5);                       /* version 0 */
	check("malformed-version", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_MALFORMED, "");
	n = build(buf, ST_UP, MY_DISC);
	((struct bfd_ctrl_pkt *)buf)->len = BFD_MIN_LEN + 8;   /* lies long */
	check("malformed-length-lies", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_MALFORMED, "len past the datagram");
	n = build(buf, ST_UP, MY_DISC);
	((struct bfd_ctrl_pkt *)buf)->detect_mult = 0;
	check("malformed-mult-zero", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_MALFORMED, "");

	/* --- GTSM --- */
	n = build(buf, ST_UP, MY_DISC);
	check("gtsm-single-hop-254", buf, n, 254, &A_PEER, &A_LOCAL, 0,
	      RX_TTL, "single hop wants exactly 255");
	check("gtsm-single-hop-no-cmsg", buf, n, -1, &A_PEER, &A_LOCAL, 0,
	      RX_TTL, "a missing cmsg is a refusal, not a pass");

	arm(0, 200);
	check("gtsm-multihop-at-minimum", buf, n, 200, &A_PEER, &A_LOCAL, 1,
	      RX_ACCEPT, "ttl 200, minimum 200");
	check("gtsm-multihop-above-minimum", buf, n, 240, &A_PEER, &A_LOCAL, 1,
	      RX_ACCEPT, "");
	check("gtsm-multihop-below-minimum", buf, n, 199, &A_PEER, &A_LOCAL, 1,
	      RX_TTL, "");
	check("gtsm-multihop-no-cmsg", buf, n, -1, &A_PEER, &A_LOCAL, 1,
	      RX_TTL, "");
	/* The multihop minimum belongs to the session, so it can only be
	 * applied once the demux has found one: a low-TTL packet naming
	 * nothing is refused for the session, not for the TTL. */
	n = build(buf, ST_UP, 0xdeadbeef);
	check("gtsm-multihop-unknown-session-first", buf, n, 1,
	      &A_PEER, &A_LOCAL, 1, RX_NO_SESSION, "demux before the minimum");

	/* --- authentication (RFC 5880 s6.7) --- */
	arm(1, 255);
	n = build(buf, ST_UP, MY_DISC);
	check("auth-bare-packet-on-authed-session", buf, n, 255,
	      &A_PEER, &A_LOCAL, 0, RX_AUTH,
	      "no A bit where the session requires one");

	arm(1, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, KEY, 1);
	check("auth-signed-accepted", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_ACCEPT, "correct key and digest");

	arm(1, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, KEY, 1);
	buf[BFD_MIN_LEN + 8] ^= 0xff;            /* one digest byte */
	check("auth-bad-digest", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_AUTH, "one flipped digest byte");

	arm(1, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, "wrongkey", 1);
	check("auth-wrong-key", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_AUTH, "signed with a key we do not hold");

	arm(1, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID + 1, KEY, 1);
	check("auth-unknown-key-id", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_AUTH, "names a key id we never configured");

	/* A key outside its accept period is not an answer, which is the
	 * other half of the rollover rule. */
	arm(1, 255);
	sessions[0].auth_keys[0].accept_start = (int64_t)time(NULL) + 3600;
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, KEY, 1);
	check("auth-key-not-yet-acceptable", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_AUTH, "accept period has not opened");

	/* An A bit on a session that does not authenticate is refused in
	 * the other direction: a peer must not be able to strip or add
	 * authentication by choosing what it sends. */
	arm(0, 255);
	n = build_auth(buf, ST_UP, MY_DISC, KEY_ID, KEY, 1);
	check("auth-signed-on-bare-session", buf, n, 255, &A_PEER, &A_LOCAL, 0,
	      RX_AUTH, "A bit where the session has no key");

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
