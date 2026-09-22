// SPDX-License-Identifier: GPL-2.0
/*
 * dp_fuzz.c - libFuzzer target for the bfddp parser.
 *
 * Headers claiming one type with another's payload, unknown types at
 * plausible lengths, and bodies that parse as one message but mean
 * another. dp_recv_hook feeds dp_read straight from the fuzzer's buffer;
 * no socket.
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
#include "bfddp.h"
#include "log.h"

#include "ktx_stubs.h"

static const uint8_t *feed_p;
static size_t feed_left;

static ssize_t feed_recv(int fd, void *buf, size_t len)
{
	(void)fd;
	if (!feed_left)
		return 0; /* EOF: peer went away */
	if (len > feed_left)
		len = feed_left;
	memcpy(buf, feed_p, len);
	feed_p += len;
	feed_left -= len;
	return (ssize_t)len;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	/* Let an ADD on any interface attach, so the stub does not steer the
	 * parser into the uncovered branch.
	 */
	ktx_stub_attach_rc = 0;

	(void)argc;
	(void)argv;
	dp_recv_hook = feed_recv;

	/* Send the engine's error lines to /dev/null, since "bad frame length"
	 * dominates random input. Sanitizer and libFuzzer output still go to
	 * stderr.
	 */
	bfd_log_err_fp = fopen("/dev/null", "w");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!size)
		return 0;

	/* dp_conn is static and only dp_accept assigns it. Any non-negative
	 * value gets dp_read past its guard; the hook never touches the fd.
	 */
	dp_set_conn_for_test(1);

	feed_p = data;
	feed_left = size;

	/* Drive until the parser stops consuming: EOF drops the connection,
	 * a bad frame drops it too. Bounded so a parser that neither
	 * consumes nor drops cannot spin.
	 */
	for (int i = 0; i < 64 && feed_left; i++)
		dp_read();
	dp_read(); /* the EOF that tears down */

	return 0;
}
