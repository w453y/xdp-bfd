// SPDX-License-Identifier: GPL-2.0
/*
 * dp_fuzz.c - libFuzzer target for the bffdp parser.
 *
 * dp_read() is the only part of this engine that takes bytes from a
 * network daemon. tests/unit/dp_run.c covers the enumerable edges with
 * a real socketpair: whole message, three in one read, torn at every
 * byte boundary, the three bad-length classes. Those are cases a person
 * can list.
 *
 * This targets what nobody enumerates: a header claiming one type with
 * another type's payload length, nonsense type codes at plausible
 * lengths, bodies that parse as one message and mean another.
 *
 * NO SOCKET. dp_recv_hook feeds dp_read from the fuzzer's buffer, which
 * is what 03-testing asked for. An earlier version drove a real unix
 * socket per iteration and every bug found was in the connection
 * lifecycle rather than the parser: SIGPIPE on the reply path, and
 * dp_accept's replacement branch closing the fd it had just accepted
 * because the harness freed the number first and the kernel reissued it.
 * None of that is under test. The seam deletes all of it.
 *
 *     make tests/unit/dp_fuzz
 *     ./tests/unit/dp_fuzz -runs=100000
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include "session.h"
#include "dplane.h"
#include "bffdp.h"
#include "log.h"

/* Same stub group dp_run uses, plus the three dplane.c references that
 * only surface when linking from source rather than the prebuilt .o. */
int use_ktx;
int sess_fd = -1;

int ktx_covers(int ifindex) { (void)ifindex; return 0; }
int ktx_attach_if(int ifindex, const char *ifname)
{
	(void)ifindex; (void)ifname; return 0;
}
void ktx_mirror(struct session *s) { (void)s; }
void ktx_forget(struct session *s) { (void)s; }
void ktx_update_mhop_flag(void) { }
void ktx_poll_map(struct session *s, uint64_t t) { (void)s; (void)t; }
void ktx_clear(struct session *s) { (void)s; }
void ktx_clear_key(const struct bfd_addr *peer, const struct bfd_addr *local,
		   uint32_t wire_disc)
{
	(void)peer; (void)local; (void)wire_disc;
}
void echo_peer_refresh(const struct bfd_addr *peer, struct session *skip)
{
	(void)peer; (void)skip;
}

static const uint8_t *feed_p;
static size_t feed_left;

static ssize_t feed_recv(int fd, void *buf, size_t len)
{
	(void)fd;
	if (!feed_left)
		return 0;			/* EOF: peer went away */
	if (len > feed_left)
		len = feed_left;
	memcpy(buf, feed_p, len);
	feed_p += len;
	feed_left -= len;
	return (ssize_t)len;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	dp_recv_hook = feed_recv;

	/* Send the engine's error lines to /dev/null. They are not
	 * level-gated, and "bad frame length" is what most random inputs
	 * produce, so they dominate the run - exec/s reads 0 with them on.
	 * Only this stream moves: the sanitizer reports and libFuzzer's
	 * own stats still go to the real stderr, which is what a finding
	 * is made of. */
	bfd_log_err_fp = fopen("/dev/null", "w");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!size)
		return 0;

	/* dp_conn is static and only dp_accept assigns it. Any non-negative
	 * value gets dp_read past its guard; the hook never touches the fd. */
	dp_set_conn_for_test(1);

	feed_p = data;
	feed_left = size;

	/* Drive until the parser stops consuming: EOF drops the connection,
	 * a bad frame drops it too. Bounded so a parser that neither
	 * consumes nor drops cannot spin. */
	for (int i = 0; i < 64 && feed_left; i++)
		dp_read();
	dp_read();				/* the EOF that tears down */

	return 0;
}
