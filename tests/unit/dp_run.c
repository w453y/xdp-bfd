// SPDX-License-Identifier: GPL-2.0
/* dp_run.c - the bfddp framing parser, fed by hand.
 *
 * dp_read() is the only part of this engine that faces a network daemon
 * across a byte stream, and it had no tests. A byte stream means the
 * parser must survive any split: a header arriving one byte at a time, a
 * message spanning two reads, several messages in one read, and a length
 * field that is a lie.
 *
 * No seam was added. dp_listen_init() and dp_accept() are already
 * exported, so the test opens a real Unix socket, connects to it, and lets
 * the engine's own accept path install the connection. The bytes then go
 * in with write(2) and dp_read() is called exactly as the main loop calls
 * it. Slower than calling a parser function directly, and worth it: the
 * recv, the buffer carry-over and the drop-connection policy are all in
 * the path being tested.
 *
 * Links against the real dplane.o, session.o and fsm.o. Only the ktx
 * group is stubbed, and use_ktx stays 0 so none of it runs.
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

int main(void)
{
	if (!rig_up()) {
		printf("rig setup failed\n");
		return 1;
	}

	case_whole();
	case_torn();
	case_batched();

	/* Below the header, and above the buffer. */
	case_bad_length(sizeof(struct bfddp_message_header) - 1,
			"bad-length-under-header");
	case_bad_length(0, "bad-length-zero");
	case_bad_length(65535, "bad-length-over-buffer");

	rig_down();
	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
