// SPDX-License-Identifier: GPL-2.0
/* Part of dp_run, split by subject; compiled as one unit via
 * tests/unit/dp_run.c.
 */

/* A wildcard local address (no local-address in bfdd) resolves to the source
 * the kernel would use. A loopback peer makes the result deterministic.
 */
static void case_local_resolve(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x5001, "0.0.0.0", "127.0.0.2");
	struct session *s;
	uint32_t local4 = 0;
	int bad = 0;

	if (!rig_up()) {
		report("local-resolve-v4", 1, "rig up");
		rig_down();
		return;
	}
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

	if (!rig_up()) {
		report("local-resolve-v6", 1, "rig up");
		rig_down();
		return;
	}
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

	if (!rig_up()) {
		report("local-resolve-mhop", 1, "rig up");
		rig_down();
		return;
	}
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
