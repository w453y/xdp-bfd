// SPDX-License-Identifier: GPL-2.0
/* Part of dp_run.c. */

/* bfdd re-sends an ADD on every config change: create, update or adopt. */

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
	struct bfd_addr want = { 0 };
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

/* RFC 5880: constant while Up. */
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
		s->wire_disc = 0xdeadbeef; /* stand in for one already Up */

	n = build_add(buf, 0x4003, "10.0.0.1", "10.0.0.32");
	((struct bfddp_session_msg *)(buf + sizeof(struct bfddp_message_header)))->min_tx =
		htonl(50000);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4003);
	if (!s) {
		printf("     session gone after the update\n");
		bad = 1;
	} else {
		if (s->wire_disc != 0xdeadbeef) {
			printf("     wire_disc changed to %u on update\n", s->wire_disc);
			bad = 1;
		}
		if (s->min_tx_us != 50000) {
			printf("     min_tx_us %u, the update did not apply\n", s->min_tx_us);
			bad = 1;
		}
	}
	if (used_sessions() != 1) {
		printf("     %d sessions, the update allocated a new one\n", used_sessions());
		bad = 1;
	}
	report("add-update-keeps-wire-disc", bad, "1 session");
}

static void case_add_without_auth(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x5150, "10.0.0.1", "10.0.0.2");
	struct session *s;
	int bad = 0;

	sessions_clear();
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x5150);
	if (!s) {
		printf("     no session from an unauthenticated ADD\n");
		bad = 1;
	} else if (s->auth_present || s->auth_type || s->auth_nkeys) {
		printf("     authentication state set without SESSION_AUTH\n");
		bad = 1;
	}
	report("add-without-auth", bad, "session up, unauthenticated");
}

/* An address move changes no tx_cfg field. ktx_mirror is stubbed, so the
 * predicate is tested directly.
 */
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

/* s6.8.3 keeps the old interval until the peer's Final. */
static void case_repeated_add_during_poll(void)
{
	unsigned char buf[256];
	struct session *s;
	size_t n;
	int bad = 0;

	sessions_clear();
	n = build_add(buf, 0x4009, "10.0.0.1", "10.0.0.40");
	((struct bfddp_session_msg *)(buf + sizeof(struct bfddp_message_header)))->min_tx =
		htonl(10000);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4009);
	if (!s) {
		printf("     session missing after the first add\n");
		report("repeated-add-holds-applied-tx", 1, NULL);
		return;
	}
	s->state = ST_UP;
	s->applied_tx_us = 10000;

	/* Raise it: poll opens, the applied rate stays where it was. */
	n = build_add(buf, 0x4009, "10.0.0.1", "10.0.0.40");
	((struct bfddp_session_msg *)(buf + sizeof(struct bfddp_message_header)))->min_tx =
		htonl(50000);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4009);
	if (!s->polling) {
		printf("     no poll sequence after the increase\n");
		bad = 1;
	}
	if (s->applied_tx_us != 10000) {
		printf("     applied_tx_us %u after the increase, want 10000\n", s->applied_tx_us);
		bad = 1;
	}

	/* The same message again, before any Final. */
	n = build_add(buf, 0x4009, "10.0.0.1", "10.0.0.40");
	((struct bfddp_session_msg *)(buf + sizeof(struct bfddp_message_header)))->min_tx =
		htonl(50000);
	feed(buf, n);
	dp_read();

	s = sess_by_lid(0x4009);
	if (!s->polling) {
		printf("     the repeat ended the poll\n");
		bad = 1;
	}
	if (s->applied_tx_us != 10000) {
		printf("     applied_tx_us %u after the repeat, want 10000\n", s->applied_tx_us);
		bad = 1;
	}

	/* The peer answers: now it may apply. */
	s->polling = 0;
	s->applied_tx_us = s->min_tx_us;
	if (s->applied_tx_us != 50000) {
		printf("     applied_tx_us %u after the final, want 50000\n", s->applied_tx_us);
		bad = 1;
	}

	report("repeated-add-holds-applied-tx", bad, "held 10000 until the final");
}

static void case_address_move(void)
{
	unsigned char buf[256];
	struct bfd_addr want = { 0 };
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
		printf("     %d sessions after an address move\n", used_sessions());
		bad = 1;
	}
	report("add-moves-address-pair", bad, "1 session, new pair");
}

/* Each flag lands in its own field. */
static void case_flags(void)
{
	unsigned char buf[256];
	size_t n = build_add(buf, 0x4005, "10.0.0.1", "10.0.0.51");
	struct bfddp_session_msg *m = (void *)(buf + sizeof(struct bfddp_message_header));
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
