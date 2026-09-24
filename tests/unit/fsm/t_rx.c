// SPDX-License-Identifier: GPL-2.0
/* Part of fsm_run.c. */

/* Receive: the RFC 5880 s6.8.6 table, P and F, and notification. */

/* From ours with the peer at theirs, expect want and want_diag. */
static void row(uint8_t ours, uint8_t theirs, uint8_t want, uint8_t want_diag, const char *name)
{
	struct session *s;
	struct bfd_ctrl_pkt p = pkt(theirs, 0);
	uint64_t t = 2000000;
	int bad = 0;

	s = sess_init(ours);
	fsm_rx(s, &p, t);

	if (s->state != want) {
		printf("     %s + peer %s -> %s, want %s\n", st_name(ours), st_name(theirs),
		       st_name(s->state), st_name(want));
		bad = 1;
	}
	if (s->state != ours && s->diag != want_diag) {
		printf("     diag %u, want %u\n", s->diag, want_diag);
		bad = 1;
	}

	report(name, bad, st_name(s->state));
}

static void run_table(void)
{
	/* RFC 5880 s6.8.6. Init + peer Down is not a transition: the peer has not seen us yet. */
	row(ST_DOWN, ST_DOWN, ST_INIT, 0, "down+down=init");
	row(ST_DOWN, ST_INIT, ST_UP, 0, "down+init=up");
	row(ST_DOWN, ST_UP, ST_DOWN, 0, "down+up=down");

	row(ST_INIT, ST_DOWN, ST_INIT, 0, "init+down=init");
	row(ST_INIT, ST_INIT, ST_UP, 0, "init+init=up");
	row(ST_INIT, ST_UP, ST_UP, 0, "init+up=up");

	row(ST_UP, ST_DOWN, ST_DOWN, 3, "up+down=down-diag3");
	row(ST_UP, ST_INIT, ST_UP, 0, "up+init=up");
	row(ST_UP, ST_UP, ST_UP, 0, "up+up=up");

	/* Peer AdminDown takes any state down with diag 3. */
	row(ST_DOWN, ST_ADMINDOWN, ST_DOWN, 3, "down+admindown=down");
	row(ST_INIT, ST_ADMINDOWN, ST_DOWN, 3, "init+admindown=down");
	row(ST_UP, ST_ADMINDOWN, ST_DOWN, 3, "up+admindown=down");
}

/* A change to the peer's echo interval alone reaches the control plane. */
static void case_echo_only_change_notifies(void)
{
	struct bfd_ctrl_pkt p = pkt(ST_UP, 0);
	struct session *s;
	int bad = 0;
	int base;

	s = sess_init(ST_UP);
	s->rdisc = 0x22222222;
	s->r_min_echo = 50000;

	p.min_echo_rx = htonl(50000);
	notify_calls = 0;
	fsm_rx(s, &p, 2000000);
	base = notify_calls;
	if (base) {
		printf("     %d notifications for a packet that changed nothing\n", base);
		bad = 1;
	}

	/* Only the echo interval moves. */
	p.min_echo_rx = htonl(200000);
	fsm_rx(s, &p, 2100000);
	if (notify_calls != base + 1) {
		printf("     %d notifications for an echo-only change, want 1\n",
		       notify_calls - base);
		bad = 1;
	}
	if (s->r_min_echo != 200000) {
		printf("     r_min_echo %u, want 200000\n", s->r_min_echo);
		bad = 1;
	}

	/* Withdrawing echo is a change too. */
	p.min_echo_rx = htonl(0);
	fsm_rx(s, &p, 2200000);
	if (notify_calls != base + 2) {
		printf("     withdrawing echo did not notify\n");
		bad = 1;
	}

	report("echo-only-change-notifies", bad, "notified twice");
}

/* admin_down short-circuits before any transition. */
static void case_admin_down(void)
{
	struct session *s;
	struct bfd_ctrl_pkt p = pkt(ST_INIT, 0);

	s = sess_init(ST_DOWN);
	s->admin_down = 1;
	fsm_rx(s, &p, 2000000);

	if (s->state != ST_DOWN)
		printf("     admin_down session moved to %s\n", st_name(s->state));
	report("admin-down-ignores-peer", s->state != ST_DOWN, "Down");
}

/* The P and F bits. P asks for a Final; F answers our poll and ends it. */
static void case_poll_bits(void)
{
	struct session *s;
	int bad = 0;

	s = sess_init(ST_UP);
	struct bfd_ctrl_pkt pp = pkt(ST_UP, F_P);

	fsm_rx(s, &pp, 2000000);
	if (!s->send_final) {
		printf("     incoming P did not arm send_final\n");
		bad = 1;
	}

	s = sess_init(ST_UP);
	s->polling = 1;
	s->min_tx_us = 50000;
	s->applied_tx_us = 10000;
	struct bfd_ctrl_pkt pf = pkt(ST_UP, F_F);

	fsm_rx(s, &pf, 2000000);
	if (s->polling) {
		printf("     incoming F did not end the poll\n");
		bad = 1;
	}
	if (s->applied_tx_us != 50000) {
		printf("     applied_tx_us is %u, want 50000 after the poll\n", s->applied_tx_us);
		bad = 1;
	}

	report("poll-final-bits", bad, NULL);
}

/* Only while Up, only on a change, after the update. */
static void case_notify(void)
{
	struct session *s;
	struct bfd_ctrl_pkt p;
	int bad = 0;

	/* Nothing changed: no notify. */
	s = sess_init(ST_UP);
	notify_calls = 0;
	p = pkt(ST_UP, 0);
	fsm_rx(s, &p, 2000000);
	if (notify_calls != 0) {
		printf("     unchanged packet notified %d time(s)\n", notify_calls);
		bad = 1;
	}

	/* Timer change while Up: notify. */
	s = sess_init(ST_UP);
	notify_calls = 0;
	p = pkt(ST_UP, 0);
	p.min_tx = htonl(50000);
	fsm_rx(s, &p, 2000000);
	if (notify_calls != 1) {
		printf("     timer change notified %d time(s), want 1\n", notify_calls);
		bad = 1;
	}
	if (s->r_min_tx != 50000) {
		printf("     r_min_tx is %u at notify time, want 50000\n", s->r_min_tx);
		bad = 1;
	}

	/* It changes the peer's budget for us. */
	s = sess_init(ST_UP);
	notify_calls = 0;
	p = pkt(ST_UP, 0);
	p.detect_mult = 5;
	fsm_rx(s, &p, 2000000);
	if (notify_calls != 1) {
		printf("     mult change notified %d time(s), want 1\n", notify_calls);
		bad = 1;
	}

	/* Same change below Up: no notify, because the session is not Up. */
	s = sess_init(ST_DOWN);
	notify_calls = 0;
	p = pkt(ST_UP, 0);
	p.min_tx = htonl(50000);
	fsm_rx(s, &p, 2000000);
	if (notify_calls != 0) {
		printf("     change while Down notified %d time(s)\n", notify_calls);
		bad = 1;
	}

	report("notify-on-change-only", bad, NULL);
}

/* RFC 5880 s6.8.6: in AdminDown the packet is discarded before the Poll is
 * answered.
 */
static void case_no_final_in_admin_down(void)
{
	struct session *s = sess_init(ST_ADMINDOWN);
	struct bfd_ctrl_pkt p = pkt(ST_UP, F_P);

	s->admin_down = 1;
	fsm_rx(s, &p, 2000000);
	if (s->send_final)
		printf("     a Final is pending while AdminDown\n");
	report("no-final-in-admin-down", s->send_final, "Poll discarded");
}
