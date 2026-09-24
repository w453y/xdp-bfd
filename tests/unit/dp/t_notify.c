// SPDX-License-Identifier: GPL-2.0
/* Part of dp_run.c. */

/* Overflow the queue with bfdd not reading: the connection survives and the
 * final state arrives.
 */
static void case_notify_coalesce(void)
{
	struct msg {
		struct bfddp_message_header h;
		struct bfddp_state_change sc;
	} __attribute__((packed));
	static char buf[1 << 20];
	int alive, hit_overflow = 0, last_state = -1, bad = 0;
	size_t carry = 0;
	ssize_t n;

	if (!rig_up()) {
		printf("     rig setup failed\n");
		report("notify-coalesce-survives-overflow", 1, NULL);
		rig_down();
		return;
	}
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
	s->state = ST_UP; /* the state that must win */
	dp_notify_state(s);

	alive = conn_alive();

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

	if (!hit_overflow) {
		printf("     never overflowed (test ineffective)\n");
		bad = 1;
	}
	if (!alive) {
		printf("     connection dropped on overflow\n");
		bad = 1;
	}
	if (s->notify_pending) {
		printf("     deferred notification never delivered\n");
		bad = 1;
	}
	if (last_state != ST_UP) {
		printf("     last delivered state %d, want UP %d\n", last_state, ST_UP);
		bad = 1;
	}

	report("notify-coalesce-survives-overflow", bad, "conn alive, final state UP");

	rig_down();
	sessions_clear();
}
