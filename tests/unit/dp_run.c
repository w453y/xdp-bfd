// SPDX-License-Identifier: GPL-2.0
/* dp_run.c - the bfddp framing parser, fed by hand.
 *
 * dp_read() must survive any split of the byte stream: a header one byte
 * at a time, a message across two reads, several in one read, a lying
 * length. Uses a real Unix socket through the engine's own accept path;
 * only the ktx group is stubbed.
 *
 *     make test-dp
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <endian.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "session.h"
#include "dplane.h"
#include "bfddp.h"

/* ---------- stubs ---------- */

#include "ktx_stubs.h"

/* ---------- rig ---------- */

static int fails;
static int cli = -1;                 /* our end, standing in for bfdd */
static char sockpath[64];

static int rig_up(void)
{
	snprintf(sockpath, sizeof(sockpath), "/tmp/dp_run.%d.sock", getpid());
	unlink(sockpath);

	if (dp_listen_init(sockpath)) {
		printf("     dp_listen_init failed\n");
		return 0;
	}

	cli = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cli < 0) {
		printf("     socket: %s\n", strerror(errno));
		return 0;
	}

	struct sockaddr_un sa = { .sun_family = AF_UNIX };

	strncpy(sa.sun_path, sockpath, sizeof(sa.sun_path) - 1);
	if (connect(cli, (void *)&sa, sizeof(sa))) {
		printf("     connect: %s\n", strerror(errno));
		return 0;
	}

	dp_accept();       /* the engine's own accept path installs dp_conn */
	return 1;
}

static void rig_down(void)
{
	if (cli >= 0)
		close(cli);
	cli = -1;
	unlink(sockpath);
}

/* Is the connection still up? dp_fds hands back the current pair, so a
 * dropped connection is visible without reaching into dplane.c. */
static int conn_alive(void)
{
	int l = -1, c = -1;

	dp_fds(&l, &c);
	return c >= 0;
}

static int used_sessions(void)
{
	int n = 0;

	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used)
			n++;
	return n;
}

static void sessions_clear(void)
{
	memset(sessions, 0, sizeof(sessions));
}

/* ---------- message building ---------- */

/* A DP_ADD_SESSION for one v4 peer. bfddp carries both families as in6_addr;
 * SESSION_IPV6 clear means v4 in the first four bytes. */
static size_t build_add(unsigned char *buf, uint32_t lid, const char *local,
			const char *peer)
{
	struct bfddp_message_header *h = (void *)buf;
	struct bfddp_session_msg *s = (void *)(h + 1);
	size_t len = sizeof(*h) + sizeof(*s);

	memset(buf, 0, len);
	h->version = 1;
	h->type    = htons(DP_ADD_SESSION);
	h->length  = htons((uint16_t)len);

	s->lid   = htonl(lid);
	s->flags = htonl(0);            /* v4: SESSION_IPV6 clear */
	{
		/* sm_addrs builds the v4-mapped form; here the address goes in
		 * the first four bytes. */
		uint32_t a = inet_addr(local), b = inet_addr(peer);

		memcpy(&s->src.s6_addr[0], &a, 4);
		memcpy(&s->dst.s6_addr[0], &b, 4);
	}
	s->min_tx      = htonl(10000);
	s->min_rx      = htonl(10000);
	s->ttl         = 255;
	s->detect_mult = 3;
	return len;
}

/* Same message, IPv6, which reaches the session table through a separate
 * branch of sm_addrs. */
static size_t build_add6(unsigned char *buf, uint32_t lid, const char *local,
			 const char *peer)
{
	struct bfddp_message_header *h = (void *)buf;
	struct bfddp_session_msg *s = (void *)(h + 1);
	size_t len = sizeof(*h) + sizeof(*s);

	memset(buf, 0, len);
	h->version = 1;
	h->type    = htons(DP_ADD_SESSION);
	h->length  = htons((uint16_t)len);

	s->lid   = htonl(lid);
	s->flags = htonl(SESSION_IPV6);
	inet_pton(AF_INET6, local, &s->src);
	inet_pton(AF_INET6, peer, &s->dst);
	s->min_tx      = htonl(10000);
	s->min_rx      = htonl(10000);
	s->ttl         = 255;
	s->detect_mult = 3;
	return len;
}

static void feed(const void *p, size_t n)
{
	if (write(cli, p, n) != (ssize_t)n)
		printf("     short write: %s\n", strerror(errno));
}

static void report(const char *name, int bad, const char *detail)
{
	if (bad) {
		printf("FAIL %-44s\n", name);
		fails++;
	} else {
		printf("ok   %-44s %s\n", name, detail ? detail : "");
	}
}

/* An ADD that says the session authenticates. */
static size_t build_add_auth(unsigned char *buf, uint32_t lid,
			     const char *local, const char *peer)
{
	struct bfddp_message_header *h = (void *)buf;
	struct bfddp_session_msg *s = (void *)(h + 1);
	size_t len = build_add(buf, lid, local, peer);

	s->flags = htonl(SESSION_AUTH);
	(void)h;
	return len;
}

/* A two-key chain handing over at t=2000. Key 2 is acceptable from 1500 and
 * key 1 until 3000; that overlap is the rollover. */
static size_t build_session_auth(unsigned char *buf, uint32_t lid)
{
	struct bfddp_message_header *h = (void *)buf;
	struct bfddp_session_auth *a = (void *)(h + 1);
	size_t len = sizeof(*h) + offsetof(struct bfddp_session_auth, keys) +
		     2 * sizeof(a->keys[0]);

	memset(buf, 0, len);
	h->version = 1;
	h->type = htons(DP_SESSION_AUTH);
	h->length = htons((uint16_t)len);

	a->lid = htonl(lid);
	a->key_count = htons(2);

	a->keys[0].type = BFD_AUTH_KEYED_SHA1;
	a->keys[0].key_id = 1;
	a->keys[0].key_len = 8;
	memcpy(a->keys[0].key, "firstkey", 8);
	a->keys[0].send.start = htobe64(1000);
	a->keys[0].send.end = htobe64(2000);
	a->keys[0].accept.start = htobe64(1000);
	a->keys[0].accept.end = htobe64(3000);

	a->keys[1].type = BFD_AUTH_KEYED_SHA1;
	a->keys[1].key_id = 2;
	a->keys[1].key_len = 9;
	memcpy(a->keys[1].key, "secondkey", 9);
	a->keys[1].send.start = htobe64(2001);
	a->keys[1].send.end = htobe64(4000);
	a->keys[1].accept.start = htobe64(1500);
	a->keys[1].accept.end = htobe64(4000);

	return len;
}

/* ---------- cases ---------- */

/* One whole message in one read: the baseline everything else is measured
 * against. */
static void case_whole(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x1001, "10.0.0.1", "10.0.0.2");
	int bad = 0;

	sessions_clear();
	feed(buf, n);
	dp_read();

	if (used_sessions() != 1) {
		printf("     %d sessions after one ADD, want 1\n",
		       used_sessions());
		bad = 1;
	}
	if (!conn_alive()) {
		printf("     connection dropped on a valid message\n");
		bad = 1;
	}
	report("whole-message", bad, "1 session");
}

/* The same message split at every byte boundary. A parser that assumes a
 * message arrives in one piece fails somewhere in here. */
static void case_torn(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x1002, "10.0.0.1", "10.0.0.3");
	int bad = 0;

	for (size_t split = 1; split < n; split++) {
		sessions_clear();

		feed(buf, split);
		dp_read();
		feed(buf + split, n - split);
		dp_read();

		if (used_sessions() != 1) {
			printf("     split at %zu: %d sessions, want 1\n",
			       split, used_sessions());
			bad = 1;
			break;
		}
		if (!conn_alive()) {
			printf("     split at %zu dropped the connection\n",
			       split);
			bad = 1;
			break;
		}
	}
	report("torn-at-every-boundary", bad, "all splits");
}

/* Several messages in one read must all be consumed, not just the first. */
static void case_batched(void)
{
	unsigned char buf[2048];
	size_t off = 0;
	int bad = 0;

	sessions_clear();
	off += build_add(buf + off, 0x2001, "10.0.0.1", "10.0.0.11");
	off += build_add(buf + off, 0x2002, "10.0.0.1", "10.0.0.12");
	off += build_add(buf + off, 0x2003, "10.0.0.1", "10.0.0.13");

	feed(buf, off);
	dp_read();

	if (used_sessions() != 3) {
		printf("     %d sessions after three ADDs in one read\n",
		       used_sessions());
		bad = 1;
	}
	report("three-in-one-read", bad, "3 sessions");
}

/* A length field that cannot be honoured drops the connection, so bfdd
 * reconnects on a clean boundary. The rig is rebuilt afterwards. */
static void case_bad_length(uint16_t mlen, const char *name)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x3001, "10.0.0.1", "10.0.0.21");
	struct bfddp_message_header *h = (void *)buf;
	int bad = 0;

	sessions_clear();
	h->length = htons(mlen);

	feed(buf, n);
	dp_read();

	if (conn_alive()) {
		printf("     length %u did not drop the connection\n", mlen);
		bad = 1;
	}
	if (used_sessions() != 0) {
		printf("     %d sessions built from a bad frame\n",
		       used_sessions());
		bad = 1;
	}
	report(name, bad, "dropped");

	rig_down();
	if (!rig_up())
		printf("     rig rebuild failed\n");
}

/* Session lifecycle: bfdd re-sends an ADD on every config change, so an ADD
 * may create, update or adopt. */

/* A fresh ADD builds a session whose wire discriminator is its lid. */
static void case_fresh(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x4001, "10.0.0.1", "10.0.0.31");
	struct session *s;
	int bad = 0;

	sessions_clear();
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4001);
	if (!s) {
		printf("     no session for the lid\n");
		bad = 1;
	} else {
		if (s->wire_disc != 0x4001) {
			printf("     wire_disc %u, want the lid\n", s->wire_disc);
			bad = 1;
		}
		if (s->family != AF_INET) {
			printf("     family %d, want v4\n", s->family);
			bad = 1;
		}
	}
	report("add-fresh-v4", bad, "wire_disc = lid");
}

/* The v6 branch of sm_addrs: a straight 16-byte copy, no v4-mapping. */
static void case_fresh_v6(void)
{
	unsigned char buf[256];
	size_t n = build_add6(buf, 0x4002, "fd00::1", "fd00::2");
	struct bfd_addr want = {0};
	struct session *s;
	int bad = 0;

	sessions_clear();
	feed(buf, n);
	dp_read();

	inet_pton(AF_INET6, "fd00::2", want.b);

	s = sess_by_lid(0x4002);
	if (!s) {
		printf("     no session for the lid\n");
		bad = 1;
	} else {
		if (s->family != AF_INET6) {
			printf("     family %d, want v6\n", s->family);
			bad = 1;
		}
		if (memcmp(&s->peer, &want, sizeof(want))) {
			printf("     peer address not preserved\n");
			bad = 1;
		}
	}
	report("add-fresh-v6", bad, "16 bytes preserved");
}

/* A second ADD for the same lid updates in place and keeps wire_disc:
 * RFC 5880 requires the discriminator to stay constant while Up, so an
 * adopted session must not get a new one. */
static void case_update_keeps_disc(void)
{
	unsigned char buf[256];
	size_t n;
	struct session *s;
	int bad = 0;

	sessions_clear();
	n = build_add(buf, 0x4003, "10.0.0.1", "10.0.0.32");
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4003);
	if (s)
		s->wire_disc = 0xdeadbeef;   /* stand in for one already Up */

	n = build_add(buf, 0x4003, "10.0.0.1", "10.0.0.32");
	((struct bfddp_session_msg *)(buf + sizeof(struct bfddp_message_header)))
		->min_tx = htonl(50000);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4003);
	if (!s) {
		printf("     session gone after the update\n");
		bad = 1;
	} else {
		if (s->wire_disc != 0xdeadbeef) {
			printf("     wire_disc changed to %u on update\n",
			       s->wire_disc);
			bad = 1;
		}
		if (s->min_tx_us != 50000) {
			printf("     min_tx_us %u, the update did not apply\n",
			       s->min_tx_us);
			bad = 1;
		}
	}
	if (used_sessions() != 1) {
		printf("     %d sessions, the update allocated a new one\n",
		       used_sessions());
		bad = 1;
	}
	report("add-update-keeps-wire-disc", bad, "1 session");
}

/* An ADD of BFDDP_SESSION_MSG_MIN bytes and no DP_SESSION_AUTH gives an
 * unauthenticated session. */
static void case_add_without_auth(void)
{
	unsigned char buf[256];
	size_t full = build_add(buf, 0x5150, "10.0.0.1", "10.0.0.2");
	size_t short_len = sizeof(struct bfddp_message_header) +
			   BFDDP_SESSION_MSG_MIN;
	struct bfddp_message_header *h = (void *)buf;
	struct session *s;

	int bad = 0;

	(void)full;
	h->length = htons((uint16_t)short_len);

	sessions_clear();
	feed(buf, short_len);
	dp_read();

	s = sess_by_lid(0x5150);
	if (!s) {
		printf("     no session from a pre-auth ADD\n");
		bad = 1;
	} else if (s->auth_type || s->auth_keylen) {
		printf("     auth read from bytes that were never sent\n");
		bad = 1;
	}
	report("add-without-auth", bad, "session up, unauthenticated");
}

/* ktx_push_needed compares the key as well as the value, since an address move
 * changes no tx_cfg field. The predicate is tested directly because ktx_mirror
 * is stubbed here. */
static void case_mirror_cache_tracks_key(void)
{
	struct session_key k1 = {}, k2 = {};
	struct tx_cfg c = {};
	struct session s = {};
	uint32_t a1 = inet_addr("10.0.0.41");
	uint32_t a2 = inet_addr("10.0.0.42");
	int bad = 0;

	k1.peer.b[10] = k1.peer.b[11] = 0xff;
	memcpy(&k1.peer.b[12], &a1, 4);
	k2 = k1;
	memcpy(&k2.peer.b[12], &a2, 4);

	c.min_tx_us = 50000;

	if (!ktx_push_needed(&s, &c, &k1)) {
		printf("     nothing pushed yet and it says no push needed\n");
		bad = 1;
	}

	/* Stand in for a push that landed. */
	s.pushed_cfg = c;
	s.pushed_key = k1;
	s.pushed_valid = 1;

	if (ktx_push_needed(&s, &c, &k1)) {
		printf("     same key and same value still wants a push\n");
		bad = 1;
	}
	if (!ktx_push_needed(&s, &c, &k2)) {
		printf("     the address pair moved and it wants no push\n");
		bad = 1;
	}

	c.min_tx_us = 10000;
	if (!ktx_push_needed(&s, &c, &k1)) {
		printf("     the value changed and it wants no push\n");
		bad = 1;
	}

	report("mirror-cache-tracks-key", bad, "key and value both count");
}

/* A repeated ADD must not slow transmission mid-Poll: s6.8.3 keeps the old
 * interval until the peer's Final. */
static void case_repeated_add_during_poll(void)
{
	unsigned char buf[256];
	struct session *s;
	size_t n;
	int bad = 0;

	sessions_clear();
	n = build_add(buf, 0x4009, "10.0.0.1", "10.0.0.40");
	((struct bfddp_session_msg *)(buf + sizeof(struct bfddp_message_header)))
		->min_tx = htonl(10000);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4009);
	if (!s) {
		printf("     session missing after the first add\n");
		printf("FAIL %-44s\n", "repeated-add-holds-applied-tx");
		fails++;
		return;
	}
	s->state = ST_UP;
	s->applied_tx_us = 10000;

	/* Raise it: poll opens, the applied rate stays where it was. */
	n = build_add(buf, 0x4009, "10.0.0.1", "10.0.0.40");
	((struct bfddp_session_msg *)(buf + sizeof(struct bfddp_message_header)))
		->min_tx = htonl(50000);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4009);
	if (!s->polling) {
		printf("     no poll sequence after the increase\n");
		bad = 1;
	}
	if (s->applied_tx_us != 10000) {
		printf("     applied_tx_us %u after the increase, want 10000\n",
		       s->applied_tx_us);
		bad = 1;
	}

	/* The same message again, before any Final. */
	n = build_add(buf, 0x4009, "10.0.0.1", "10.0.0.40");
	((struct bfddp_session_msg *)(buf + sizeof(struct bfddp_message_header)))
		->min_tx = htonl(50000);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4009);
	if (!s->polling) {
		printf("     the repeat ended the poll\n");
		bad = 1;
	}
	if (s->applied_tx_us != 10000) {
		printf("     applied_tx_us %u after the repeat, want 10000\n",
		       s->applied_tx_us);
		bad = 1;
	}

	/* The peer answers: now it may apply. */
	s->polling = 0;
	s->applied_tx_us = s->min_tx_us;
	if (s->applied_tx_us != 50000) {
		printf("     applied_tx_us %u after the final, want 50000\n",
		       s->applied_tx_us);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-44s\n", "repeated-add-holds-applied-tx");
		fails++;
	} else {
		printf("ok   %-44s held 10000 until the final\n",
		       "repeated-add-holds-applied-tx");
	}
}

/* An ADD for an existing lid may move the address pair; the old pair's
 * map entries must be cleared. */
static void case_address_move(void)
{
	unsigned char buf[256];
	struct bfd_addr want = {0};
	uint32_t a = inet_addr("10.0.0.42");
	struct session *s;
	size_t n;
	int bad = 0;

	sessions_clear();
	n = build_add(buf, 0x4004, "10.0.0.1", "10.0.0.41");
	feed(buf, n);
	dp_read();

	n = build_add(buf, 0x4004, "10.0.0.1", "10.0.0.42");
	feed(buf, n);
	dp_read();

	want.b[10] = 0xff;
	want.b[11] = 0xff;
	memcpy(&want.b[12], &a, 4);

	s = sess_by_lid(0x4004);
	if (!s) {
		printf("     session gone after the move\n");
		bad = 1;
	} else if (memcmp(&s->peer, &want, sizeof(want))) {
		printf("     peer address did not move\n");
		bad = 1;
	}
	if (used_sessions() != 1) {
		printf("     %d sessions after an address move\n",
		       used_sessions());
		bad = 1;
	}
	report("add-moves-address-pair", bad, "1 session, new pair");
}

/* Flags map straight through: passive, shutdown and multihop each land in
 * their own field rather than being conflated. */
static void case_flags(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x4005, "10.0.0.1", "10.0.0.51");
	struct bfddp_session_msg *m =
		(void *)(buf + sizeof(struct bfddp_message_header));
	struct session *s;
	int bad = 0;

	sessions_clear();
	m->flags = htonl(SESSION_PASSIVE | SESSION_SHUTDOWN);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4005);
	if (!s) {
		printf("     no session\n");
		bad = 1;
	} else {
		if (!s->passive) {
			printf("     passive flag lost\n");
			bad = 1;
		}
		if (!s->admin_down) {
			printf("     shutdown flag lost\n");
			bad = 1;
		}
	}
	report("add-flags-map-through", bad, "passive + shutdown");
}

/* The chain arrives once and key choice follows the clock; checked at three
 * instants. */
static void case_auth_rollover(void)
{
	unsigned char buf[2048];
	struct session *s;
	int bad = 0;
	size_t n;

	sessions_clear();
	n = build_add_auth(buf, 0x2001, "10.0.0.1", "10.0.0.2");
	feed(buf, n);
	dp_read();
	n = build_session_auth(buf, 0x2001);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x2001);
	if (!s) {
		report("auth-rollover", 1, "no session");
		return;
	}
	if (!s->auth_present || s->auth_nkeys != 2) {
		printf("     present=%u nkeys=%u, want 1 and 2\n",
		       s->auth_present, s->auth_nkeys);
		bad = 1;
	}

	/* Before the handover the first key signs, and the second is
	 * already acceptable so the peer may move first. */
	session_auth_evaluate(s, 1500);
	if (s->auth_keyid != 1) {
		printf("     at 1500 signing with key %u, want 1\n",
		       s->auth_keyid);
		bad = 1;
	}
	if (!session_auth_key_for(s, 2, 1500)) {
		printf("     at 1500 key 2 is not accepted yet\n");
		bad = 1;
	}

	/* After it the second signs, and the first is still accepted so a
	 * packet already in flight is not refused. */
	session_auth_evaluate(s, 2500);
	if (s->auth_keyid != 2) {
		printf("     at 2500 signing with key %u, want 2\n",
		       s->auth_keyid);
		bad = 1;
	}
	if (!session_auth_key_for(s, 1, 2500)) {
		printf("     at 2500 key 1 is no longer accepted\n");
		bad = 1;
	}

	/* Once the first key's accept period closes it is refused. */
	if (session_auth_key_for(s, 1, 3500)) {
		printf("     at 3500 key 1 is still accepted\n");
		bad = 1;
	}

	report("auth-rollover", bad, "key 1 then key 2, overlapping");
}

/* A message claiming more keys than it carries must be refused rather
 * than read past its end. */
static void case_auth_short(void)
{
	unsigned char buf[2048];
	struct session *s;
	size_t n;
	int bad = 0;

	sessions_clear();
	n = build_add_auth(buf, 0x2002, "10.0.0.1", "10.0.0.2");
	feed(buf, n);
	dp_read();

	n = build_session_auth(buf, 0x2002);
	{
		struct bfddp_message_header *h = (void *)buf;
		struct bfddp_session_auth *a = (void *)(h + 1);

		a->key_count = htons(8);   /* only two are there */
	}
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x2002);
	if (!s || s->auth_nkeys != 0) {
		printf("     took %u keys from a message carrying two\n",
		       s ? s->auth_nkeys : 0);
		bad = 1;
	}
	report("auth-short-message", bad, "refused");
}

/* A notification storm overflows the output queue. The connection survives
 * and, once bfdd reads again, the session's final state is delivered. bfdd's
 * end is not drained during the flood. */
static void case_notify_coalesce(void)
{
	struct msg {
		struct bfddp_message_header h;
		struct bfddp_state_change   sc;
	} __attribute__((packed));
	static char buf[1 << 20];
	int alive, hit_overflow = 0, last_state = -1, bad = 0;
	size_t carry = 0;
	ssize_t n;

	if (!rig_up()) { printf("FAIL notify-coalesce (rig)\n"); fails++; rig_down(); return; }
	sessions_clear();

	struct session *s = &sessions[0];
	s->used = 1;
	s->lid = 0xABCD;
	s->state = ST_DOWN;

	for (int i = 0; i < 20000; i++) {
		s->state = (i & 1) ? ST_UP : ST_DOWN;
		dp_notify_state(s);
		if (s->notify_pending)
			hit_overflow = 1;
	}
	s->state = ST_UP;              /* the state that must win */
	dp_notify_state(s);

	alive = conn_alive();

	/* Drain bfdd's end and flush the deferred notification, tracking the
	 * last fully-received state_change. */
	for (int round = 0; round < 400; round++) {
		n = recv(cli, buf + carry, sizeof(buf) - carry, MSG_DONTWAIT);
		if (n > 0) {
			size_t total = carry + (size_t)n, off = 0;
			while (total - off >= sizeof(struct msg)) {
				struct msg *mm = (void *)(buf + off);
				last_state = mm->sc.state;
				off += sizeof(struct msg);
			}
			carry = total - off;
			memmove(buf, buf + off, carry);
		}
		dp_flush();
		dp_notify_flush_pending();
		if (n <= 0 && !s->notify_pending)
			break;
	}

	if (!hit_overflow) { printf("     never overflowed (test ineffective)\n"); bad = 1; }
	if (!alive)        { printf("     connection dropped on overflow\n"); bad = 1; }
	if (s->notify_pending) { printf("     deferred notification never delivered\n"); bad = 1; }
	if (last_state != ST_UP) { printf("     last delivered state %d, want UP %d\n", last_state, ST_UP); bad = 1; }

	if (bad) { printf("FAIL notify-coalesce-survives-overflow\n"); fails++; }
	else printf("ok   %-40s conn alive, final state UP\n", "notify-coalesce-survives-overflow");

	rig_down();
	sessions_clear();
}


/* A wildcard local address (no local-address in bfdd) resolves to the source
 * the kernel would use. A loopback peer makes the result deterministic. */
static void case_local_resolve(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x5001, "0.0.0.0", "127.0.0.2");
	struct session *s;
	uint32_t local4 = 0;
	int bad = 0;

	if (!rig_up()) { report("local-resolve-v4", 1, "rig up"); rig_down(); return; }
	sessions_clear();
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x5001);
	if (!s) {
		printf("     no session for the lid\n");
		bad = 1;
	} else {
		memcpy(&local4, &s->local.b[12], 4);
		if (local4 == 0) {
			printf("     local still 0.0.0.0, not resolved\n");
			bad = 1;
		} else if (local4 != inet_addr("127.0.0.1")) {
			char a[32];
			inet_ntop(AF_INET, &local4, a, sizeof(a));
			printf("     resolved local %s, want 127.0.0.1\n", a);
			bad = 1;
		}
	}
	report("local-resolve-v4", bad, "0.0.0.0 -> 127.0.0.1");
	rig_down();
}

static void case_local_resolve_v6(void)
{
	unsigned char buf[256];
	size_t n = build_add6(buf, 0x5002, "::", "::1");
	struct session *s;
	int bad = 0;

	if (!rig_up()) { report("local-resolve-v6", 1, "rig up"); rig_down(); return; }
	sessions_clear();
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x5002);
	if (!s) {
		printf("     no session for the lid\n");
		bad = 1;
	} else {
		struct in6_addr want, got;
		inet_pton(AF_INET6, "::1", &want);
		memcpy(&got, s->local.b, 16);
		if (memcmp(&got, &want, 16) != 0) {
			char a[64];
			inet_ntop(AF_INET6, &got, a, sizeof(a));
			printf("     resolved local %s, want ::1\n", a);
			bad = 1;
		}
	}
	report("local-resolve-v6", bad, ":: -> ::1");
	rig_down();
}

/* A multihop session with a wildcard local resolves the same way. */
static void case_local_resolve_mhop(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x5003, "0.0.0.0", "127.0.0.2");
	struct bfddp_message_header *h = (void *)buf;
	struct bfddp_session_msg *sm = (void *)(h + 1);
	struct session *s;
	uint32_t local4 = 0;
	int bad = 0;

	sm->flags = htonl(SESSION_MULTIHOP);
	sm->ttl = 250;

	if (!rig_up()) { report("local-resolve-mhop", 1, "rig up"); rig_down(); return; }
	sessions_clear();
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x5003);
	if (!s || !s->is_mhop) {
		printf("     no multihop session for the lid\n");
		bad = 1;
	} else if (!s->local_wildcard) {
		printf("     local_wildcard not set on a wildcard ADD\n");
		bad = 1;
	} else {
		memcpy(&local4, &s->local.b[12], 4);
		if (local4 != inet_addr("127.0.0.1")) {
			char a[32];
			inet_ntop(AF_INET, &local4, a, sizeof(a));
			printf("     resolved local %s, want 127.0.0.1\n", a);
			bad = 1;
		}
	}
	report("local-resolve-mhop", bad, "multihop 0.0.0.0 -> 127.0.0.1");
	rig_down();
}

int main(void)
{
	if (!rig_up()) {
		printf("rig setup failed\n");
		return 1;
	}

	case_whole();
	case_auth_rollover();
	case_auth_short();
	case_torn();
	case_batched();

	case_fresh();
	case_fresh_v6();
	case_update_keeps_disc();
	case_add_without_auth();
	case_mirror_cache_tracks_key();
	case_repeated_add_during_poll();
	case_address_move();
	case_flags();
	case_notify_coalesce();
	case_local_resolve();
	case_local_resolve_v6();
	case_local_resolve_mhop();

	/* Below the header, and above the buffer. */
	case_bad_length(sizeof(struct bfddp_message_header) - 1,
			"bad-length-under-header");
	case_bad_length(0, "bad-length-zero");
	case_bad_length(65535, "bad-length-over-buffer");

	rig_down();
	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
