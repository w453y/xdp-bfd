// SPDX-License-Identifier: GPL-2.0
/* Part of fsm_run.c. */

/* Transmit: what holds it, what survives a failed send, and jitter. */

/* RFC 5880 s6.8.7: a zero Required Min RX stops periodic TX; Poll, Final and an
 * unsent D still go. Not before anything is heard (s6.8.1).
 */
static void case_zero_remote_min_rx_halts_tx(void)
{
	struct bfd_ctrl_pkt p = pkt(ST_UP, 0);
	struct session *s;
	int bad = 0;

	s = sess_init(ST_UP);
	s->rdisc = 0x44444444;
	s->r_state = ST_UP;

	/* Never heard from: must transmit, or it cannot come up. */
	s->last_rx_us = 0;
	s->r_min_rx = 0;
	s->next_tx_us = 0;
	fsm_tx(s, 2000000);
	if (!s->tx_pkts) {
		printf("     silent before hearing a peer at all\n");
		bad = 1;
	}

	/* The peer says zero. */
	p.min_rx = htonl(0);
	fsm_rx(s, &p, 2100000);
	if (s->r_min_rx != 0) {
		printf("     r_min_rx %u after the peer advertised zero\n", s->r_min_rx);
		bad = 1;
	}

	s->tx_pkts = 0;
	s->next_tx_us = 0;
	fsm_tx(s, 2200000);
	if (s->tx_pkts) {
		printf("     still transmitting against a zero Min RX\n");
		bad = 1;
	}
	if (ktx_answers(s)) {
		printf("     the fast path is still armed to answer\n");
		bad = 1;
	}

	/* A Final still has to reach it. */
	s->send_final = 1;
	s->next_tx_us = 0;
	fsm_tx(s, 2300000);
	if (!s->tx_pkts) {
		printf("     a pending Final was withheld\n");
		bad = 1;
	}

	/* And so does a Poll. */
	s->tx_pkts = 0;
	s->polling = 1;
	s->next_tx_us = 0;
	fsm_tx(s, 2400000);
	if (!s->tx_pkts) {
		printf("     a Poll was withheld\n");
		bad = 1;
	}
	s->polling = 0;

	/* A non-zero advertisement resumes it. */
	s->tx_pkts = 0;
	p.min_rx = htonl(50000);
	fsm_rx(s, &p, 2500000);
	s->next_tx_us = 0;
	fsm_tx(s, 2600000);
	if (!s->tx_pkts) {
		printf("     still silent after the peer withdrew the zero\n");
		bad = 1;
	}

	report("zero-remote-min-rx-halts-tx", bad, "halted, Poll and Final exempt");
}

/* A pending Final and the demand quota survive a failed send. */
static void case_failed_send_keeps_pending(void)
{
	struct session *s;
	int bad = 0;

	s = sess_init(ST_UP);
	s->rdisc = 0x33333333;
	s->send_final = 1;
	s->just_up = 1;
	s->demand = 1;
	s->r_state = ST_UP;
	s->next_tx_us = 0;

	fsm_send_hook = refuse_send;
	fsm_tx(s, 2000000);
	fsm_send_hook = NULL;

	if (s->tx_pkts) {
		printf("     tx_pkts %llu after a refused send\n", (unsigned long long)s->tx_pkts);
		bad = 1;
	}
	if (!s->tx_fail) {
		printf("     the refusal was not counted\n");
		bad = 1;
	}
	if (!s->send_final) {
		printf("     send_final cleared by a send that did not happen\n");
		bad = 1;
	}
	if (!s->just_up) {
		printf("     just_up cleared by a send that did not happen\n");
		bad = 1;
	}
	if (s->demand_announced) {
		printf("     demand quota spent on a refused send\n");
		bad = 1;
	}

	/* The schedule comes round again and the socket is working. */
	s->next_tx_us = 0;
	fsm_tx(s, 2100000);
	if (!s->tx_pkts) {
		printf("     nothing sent once the socket recovered\n");
		bad = 1;
	}
	if (s->send_final) {
		printf("     the Final was never answered\n");
		bad = 1;
	}

	report("failed-send-keeps-pending", bad, "pending held, then sent");
}

/* RFC 5880 s6.8.7: passive gates TX, not the state machine. */
static void case_passive(void)
{
	struct bfd_ctrl_pkt p = pkt(ST_DOWN, 0);
	struct session *s;
	int bad = 0;

	s = sess_init(ST_DOWN);
	s->passive = 1;
	s->rdisc = 0;
	s->last_rx_us = 0;
	s->next_tx_us = 0;

	/* Nothing heard from the peer: silent. */
	fsm_tx(s, 2000000);
	if (s->tx_pkts) {
		printf("     passive transmitted %llu before hearing a peer\n",
		       (unsigned long long)s->tx_pkts);
		bad = 1;
	}

	/* The peer speaks first, as passive requires. */
	fsm_rx(s, &p, 2000000);
	if (s->state != ST_INIT) {
		printf("     passive stayed %s on the peer's Down, want Init\n", st_name(s->state));
		bad = 1;
	}

	/* Now it has a discriminator to answer, so it may transmit. */
	s->next_tx_us = 0;
	fsm_tx(s, 2100000);
	if (!s->tx_pkts) {
		printf("     passive still silent after the peer was heard\n");
		bad = 1;
	}

	report("passive-silent-then-init", bad, "silent, then Init");
}

/* RFC 5880 s6.8.7, as a property over many draws. */
static void case_jitter(uint8_t mult, unsigned int lo_pct, unsigned int hi_pct, const char *name)
{
	const uint32_t iv = 10000;
	const int draws = 10000;
	uint64_t lo = (uint64_t)iv * lo_pct / 100;
	uint64_t hi = (uint64_t)iv * hi_pct / 100;
	uint64_t seen_lo = ~0ull, seen_hi = 0;
	struct session *s;
	char detail[64];
	int bad = 0;

	for (int i = 0; i < draws; i++) {
		uint64_t t = 100000000ull + (uint64_t)i * iv * 4;

		s = sess_init(ST_UP);
		s->detect_mult = mult;
		s->r_mult = mult;
		s->min_tx_us = iv;
		s->applied_tx_us = iv;
		s->r_min_rx = iv;
		s->last_rx_us = t;
		s->next_tx_us = t;

		fsm_tx(s, t);

		uint64_t gap = s->next_tx_us - t;

		if (gap < seen_lo)
			seen_lo = gap;
		if (gap > seen_hi)
			seen_hi = gap;
	}

	if (seen_lo < lo) {
		printf("     min gap %lluus, below %llu%% of %u\n", (unsigned long long)seen_lo,
		       (unsigned long long)lo_pct, iv);
		bad = 1;
	}
	if (seen_hi > hi) {
		printf("     max gap %lluus, above %llu%% of %u\n", (unsigned long long)seen_hi,
		       (unsigned long long)hi_pct, iv);
		bad = 1;
	}
	/* Without jitter the spread collapses. */
	if (seen_hi - seen_lo < (hi - lo) / 2) {
		printf("     spread %llu-%lluus is too narrow to be jittered\n",
		       (unsigned long long)seen_lo, (unsigned long long)seen_hi);
		bad = 1;
	}

	snprintf(detail, sizeof(detail), "%llu-%lluus of %u", (unsigned long long)seen_lo,
		 (unsigned long long)seen_hi, iv);
	report(name, bad, detail);
}

/* RFC 5880 s6.8.7: below Up the 1s slow rate, but never faster than the
 * peer's Required Min RX.
 */
static void case_slow_rate_honours_remote_min_rx(void)
{
	uint64_t lo = ~0ull;
	struct session *s;

	for (int i = 0; i < 2000; i++) {
		uint64_t t = 100000000ull + (uint64_t)i * 10000000ull;

		s = sess_init(ST_DOWN);
		s->r_min_rx = 2000000;
		s->next_tx_us = t;
		fsm_tx(s, t);
		if (s->next_tx_us - t < lo)
			lo = s->next_tx_us - t;
	}
	if (lo < 1500000)
		printf("     next packet %lluus after the last; the peer asked for 2s\n",
		       (unsigned long long)lo);
	report("slow-rate-honours-remote-min-rx", lo < 1500000, "no faster than 2s less jitter");
}
