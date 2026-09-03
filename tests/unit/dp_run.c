// SPDX-License-Identifier: GPL-2.0
/* dp_run.c - the bfddp framing parser, fed by hand.
 *
 * dp_read() is the only part of this engine that faces a network daemon
 * across a byte stream, so it must survive any split: a header arriving
 * one byte at a time, a message spanning two reads, several messages in
 * one read, and a length field that is a lie.
 *
 * No seam was added. The test opens a real Unix socket and lets the
 * engine's own accept path install the connection, so the recv, the
 * buffer carry-over and the drop-connection policy are all in the path
 * being tested.
 *
 * Links the real dplane.o, session.o and fsm.o. Only the ktx group is
 * stubbed, and use_ktx stays 0 so none of it runs.
 *
 *     make test-dp
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "session.h"
#include "dplane.h"
#include "bffdp.h"

/* ---------- stubs ---------- */

int use_ktx;
int sess_fd = -1;

int ktx_covers(int ifindex) { (void)ifindex; return 0; }
int ktx_attach_if(int ifindex, const char *ifname)
{
	(void)ifindex; (void)ifname;
	return -1;
}
void ktx_clear(struct session *s) { (void)s; }
void ktx_clear_key(const struct bfd_addr *peer, const struct bfd_addr *local,
		   uint32_t wire_disc)
{
	(void)peer; (void)local; (void)wire_disc;
}
void ktx_update_mhop_flag(void) { }
void echo_peer_refresh(const struct bfd_addr *peer, struct session *skip)
{
	(void)peer; (void)skip;
}
int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	(void)fd; (void)key; (void)value;
	return -1;
}

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

/* A DP_ADD_SESSION for one v4 peer.
 *
 * bffdp.h carries addresses as struct in6_addr for both families and
 * marks the family by the SESSION_IPV6 flag. For v4 that bit is clear
 * and sm_addrs takes the first four bytes. */
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
		/* sm_addrs reads a v4 address from the FIRST four bytes of the
		 * in6_addr and runs it through key_set_v4; the v4-mapped form
		 * is built there, not here. */
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

/* Same message, IPv6. sm_addrs takes a straight 16-byte copy for v6 and
 * runs the v4 branch through key_set_v4, so the two families reach the
 * session table by different code and only one of them was covered. */
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
	unsigned char buf[1024];
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

/* A length field that cannot be honoured. The policy is deliberate: reset
 * the buffer and keep going would resync onto arbitrary mid-stream bytes,
 * so the connection is dropped and bfdd reconnects from a clean boundary.
 * The rig is rebuilt afterwards because the connection is gone. */
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

/* Session lifecycle. bfdd re-sends an ADD for every config touch, so the
 * same message type has to mean create, update and adopt depending on what
 * is already in the table. */

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

/* An ADD for an existing lid may move the address pair. The old pair's
 * map entries would otherwise stay behind with enable=1 and keep being
 * answered by the fast path. */
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

int main(void)
{
	if (!rig_up()) {
		printf("rig setup failed\n");
		return 1;
	}

	case_whole();
	case_torn();
	case_batched();

	case_fresh();
	case_fresh_v6();
	case_update_keeps_disc();
	case_address_move();
	case_flags();

	/* Below the header, and above the buffer. */
	case_bad_length(sizeof(struct bfddp_message_header) - 1,
			"bad-length-under-header");
	case_bad_length(0, "bad-length-zero");
	case_bad_length(65535, "bad-length-over-buffer");

	rig_down();
	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
