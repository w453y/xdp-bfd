// SPDX-License-Identifier: GPL-2.0
/* Part of dp_run, split by subject; compiled as one unit via
 * tests/unit/dp_run.c.
 */

/* The chain arrives once and key choice follows the clock; checked at three
 * instants.
 */
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
		printf("     present=%u nkeys=%u, want 1 and 2\n", s->auth_present, s->auth_nkeys);
		bad = 1;
	}

	/* Before the handover the first key signs, and the second is
	 * already acceptable so the peer may move first.
	 */
	session_auth_evaluate(s, 1500);
	if (s->auth_keyid != 1) {
		printf("     at 1500 signing with key %u, want 1\n", s->auth_keyid);
		bad = 1;
	}
	if (!session_auth_key_for(s, 2, 1500)) {
		printf("     at 1500 key 2 is not accepted yet\n");
		bad = 1;
	}

	/* After it the second signs, and the first is still accepted so a
	 * packet already in flight is not refused.
	 */
	session_auth_evaluate(s, 2500);
	if (s->auth_keyid != 2) {
		printf("     at 2500 signing with key %u, want 2\n", s->auth_keyid);
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
 * than read past its end.
 */
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

		a->key_count = htons(8); /* only two are there */
	}
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x2002);
	if (!s || s->auth_nkeys != 0) {
		printf("     took %u keys from a message carrying two\n", s ? s->auth_nkeys : 0);
		bad = 1;
	}
	report("auth-short-message", bad, "refused");
}
