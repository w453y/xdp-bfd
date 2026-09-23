// SPDX-License-Identifier: GPL-2.0
/* Part of dp_run, split by subject; compiled as one unit via
 * tests/unit/dp_run.c.
 */

/* Framing: dp_read() over any split of the byte stream, and lengths it
 * cannot honour.
 */

/* One whole message in one read: the baseline everything else is measured
 * against.
 */
static void case_whole(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x1001, "10.0.0.1", "10.0.0.2");
	int bad = 0;

	sessions_clear();
	feed(buf, n);
	dp_read();

	if (used_sessions() != 1) {
		printf("     %d sessions after one ADD, want 1\n", used_sessions());
		bad = 1;
	}
	if (!conn_alive()) {
		printf("     connection dropped on a valid message\n");
		bad = 1;
	}
	report("whole-message", bad, "1 session");
}

/* The same message split at every byte boundary. A parser that assumes a
 * message arrives in one piece fails somewhere in here.
 */
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
			printf("     split at %zu: %d sessions, want 1\n", split, used_sessions());
			bad = 1;
			break;
		}
		if (!conn_alive()) {
			printf("     split at %zu dropped the connection\n", split);
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
		printf("     %d sessions after three ADDs in one read\n", used_sessions());
		bad = 1;
	}
	report("three-in-one-read", bad, "3 sessions");
}

/* A length field that cannot be honoured drops the connection, so bfdd
 * reconnects on a clean boundary. The rig is rebuilt afterwards.
 */
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
		printf("     %d sessions built from a bad frame\n", used_sessions());
		bad = 1;
	}
	report(name, bad, "dropped");

	rig_down();
	if (!rig_up())
		printf("     rig rebuild failed\n");
}
