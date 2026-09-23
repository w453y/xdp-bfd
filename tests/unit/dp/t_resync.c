// SPDX-License-Identifier: GPL-2.0
/* Part of dp_run.c. */

/* Read what bfdd's end has, flushing the engine between reads. Returns the
 * last state reported for lid, or -1; *counters_id is set if a counters reply
 * with that id arrived.
 */
static int drain_for(uint32_t lid, uint16_t want_id, int *got_reply)
{
	static char buf[1 << 20];
	size_t have = 0;
	int last = -1;

	for (int round = 0; round < 400; round++) {
		ssize_t n = recv(cli, buf + have, sizeof(buf) - have, MSG_DONTWAIT);

		if (n > 0)
			have += (size_t)n;
		size_t off = 0;

		while (have - off >= sizeof(struct bfddp_message_header)) {
			struct bfddp_message_header *h = (void *)(buf + off);
			uint16_t mlen = ntohs(h->length);

			if (mlen < sizeof(*h) || have - off < mlen)
				break;
			if (ntohs(h->type) == BFD_STATE_CHANGE) {
				struct bfddp_state_change *sc = (void *)(h + 1);

				if (ntohl(sc->lid) == lid)
					last = sc->state;
			}
			if (ntohs(h->type) == BFD_SESSION_COUNTERS && ntohs(h->id) == want_id)
				*got_reply = 1;
			off += mlen;
		}
		memmove(buf, buf + off, have - off);
		have -= off;
		dp_flush();
		dp_notify_flush_pending();
		if (n <= 0 && round > 4)
			break;
	}
	return last;
}

/* bfdd ran the session itself while disconnected, and only the engine knows
 * what happened meanwhile: re-adding it must bring bfdd the current state.
 */
static void case_reconnect_resyncs_state(void)
{
	unsigned char buf[256];
	uint64_t saved = dp_hold_us;
	struct session *s;
	size_t n;
	int got = 0, st;

	if (!rig_up()) {
		report("reconnect-resyncs-state", 1, "rig up");
		rig_down();
		return;
	}
	sessions_clear();
	dp_hold_us = 60000000;
	n = build_add(buf, 0x6001, "10.0.0.1", "10.0.0.61");
	feed(buf, n);
	dp_read();
	s = sess_by_lid(0x6001);

	rig_down();
	dp_read(); /* sees the close; the session is held */
	if (s)
		state_transition(s, ST_UP, 0, now_us(), "while bfdd was away");

	rig_up();
	n = build_add(buf, 0x6001, "10.0.0.1", "10.0.0.61");
	feed(buf, n);
	dp_read();
	st = drain_for(0x6001, 0, &got);
	if (st != ST_UP)
		printf("     bfdd was told %d after the re-add, want Up (%d)\n", st, ST_UP);
	report("reconnect-resyncs-state", !s || st != ST_UP, "current state sent");

	dp_hold_us = saved;
	rig_down();
	sessions_clear();
}

/* A notification storm must leave room for a reply: bfdd waits for a counters
 * reply synchronously, so the engine can neither drop it nor the connection.
 */
static void case_counters_reply_fits_during_storm(void)
{
	struct {
		struct bfddp_message_header h;
		uint32_t lid;
	} __attribute__((packed)) req = { 0 };
	struct session *s = &sessions[0];
	int got = 0, alive;

	if (!rig_up()) {
		report("counters-reply-fits-during-storm", 1, "rig up");
		rig_down();
		return;
	}
	sessions_clear();
	s->used = 1;
	s->lid = 0xABCE;
	for (int i = 0; i < 20000; i++) {
		s->state = (i & 1) ? ST_UP : ST_DOWN;
		dp_notify_state(s);
	}

	req.h.version = 1;
	req.h.type = htons(DP_REQUEST_SESSION_COUNTERS);
	req.h.id = htons(77);
	req.h.length = htons(sizeof(req));
	req.lid = htonl(0xABCE);
	feed(&req, sizeof(req));
	dp_read();

	alive = conn_alive();
	if (!alive)
		printf("     the connection dropped on the reply\n");
	else
		drain_for(0xABCE, 77, &got);
	if (alive && !got)
		printf("     no counters reply arrived\n");
	report("counters-reply-fits-during-storm", !alive || !got, "reply delivered");
	rig_down();
	sessions_clear();
}

/* An adopted session keeps its old wire discriminator, so bfdd may later hand
 * that number out as a new lid; the two must not share it.
 */
static void case_adopted_disc_not_reissued(void)
{
	unsigned char buf[256];
	uint64_t saved = dp_hold_us;
	struct session *a, *b;
	size_t n;
	int bad = 0;

	if (!rig_up()) {
		report("adopted-disc-not-reissued", 1, "rig up");
		rig_down();
		return;
	}
	sessions_clear();
	dp_hold_us = 60000000;
	n = build_add(buf, 0x7001, "10.0.0.1", "10.0.0.71");
	feed(buf, n);
	dp_read();
	a = sess_by_lid(0x7001);
	if (a)
		a->state = ST_UP;
	n = build_add(buf, 0x7002, "10.0.0.1", "10.0.0.71"); /* adopts, keeps 0x7001 */
	feed(buf, n);
	dp_read();
	n = build_add(buf, 0x7001, "10.0.0.1", "10.0.0.72"); /* a new session */
	feed(buf, n);
	dp_read();

	a = sess_by_lid(0x7002);
	b = sess_by_lid(0x7001);
	if (!a || !b) {
		printf("     sessions missing\n");
		bad = 1;
	} else if (a->wire_disc == b->wire_disc) {
		printf("     both sessions send my_disc %#x\n", a->wire_disc);
		bad = 1;
	}
	report("adopted-disc-not-reissued", bad, "unique on the wire");
	dp_hold_us = saved;
	rig_down();
	sessions_clear();
}
