// SPDX-License-Identifier: GPL-2.0
/* Part of fsm_run.c. */

/* Detection: the budget, and the poll-aware detect basis. */

/* fsm.c's copy of the rule; xdp_run drives bfd_xdp.c's. Cleared so step 0 has
 * no prior interval.
 */
static void dv_row(const struct dv_case *c)
{
	struct session *s = sess_init(ST_UP);
	uint64_t t = 2000000;
	char detail[32];
	int bad = 0;

	s->detect_iv_us = 0;
	s->last_rx_us = 0;
	s->min_rx_us = c->local_min_rx_us;

	for (int i = 0; i < c->nsteps; i++) {
		const struct dv_step *st = &c->steps[i];
		struct bfd_ctrl_pkt p = pkt(ST_UP, 0);

		p.min_tx = htonl(st->adv_min_tx_us);
		t += st->gap_us;
		fsm_rx(s, &p, t);

		if (s->detect_iv_us != st->want_iv_us) {
			printf("     step %d: detect_iv_us %u, want %u\n", i, s->detect_iv_us,
			       st->want_iv_us);
			bad = 1;
		}
	}

	snprintf(detail, sizeof(detail), "iv %u", s->detect_iv_us);
	report(c->name, bad, detail);
}

static void run_detect_vectors(void)
{
	for (int i = 0; i < DV_NCASES; i++)
		dv_row(&dv_cases[i]);
}

/* mult * interval, r_mult before detect_mult, max(r_min_tx, min_rx_us) without detect_iv_us. */
static void case_detect(const char *name, uint32_t iv_us, uint8_t r_mult, uint8_t detect_mult,
			uint64_t silent_us, uint8_t want)
{
	struct session *s;

	s = sess_init(ST_UP);
	s->detect_iv_us = iv_us;
	s->r_mult = r_mult;
	s->detect_mult = detect_mult;
	s->last_rx_us = 10000000;

	fsm_detect(s, s->last_rx_us + silent_us);

	if (s->state != want)
		printf("     state %s, want %s\n", st_name(s->state), st_name(want));
	report(name, s->state != want, st_name(s->state));
}

/* now before last_rx_us: the delta clamps to 0 instead of wrapping. */
static void case_detect_negative(void)
{
	struct session *s;

	s = sess_init(ST_UP);
	s->last_rx_us = 10000000;
	fsm_detect(s, s->last_rx_us - 5000);

	if (s->state != ST_UP)
		printf("     state %s - the delta wrapped\n", st_name(s->state));
	report("detect-negative-delta", s->state != ST_UP, "Up");
}

/* Below Up, and before any packet has arrived, there is nothing to detect. */
static void case_detect_guards(void)
{
	struct session *s;
	int bad = 0;

	s = sess_init(ST_DOWN);
	fsm_detect(s, s->last_rx_us + 10000000);
	if (s->state != ST_DOWN) {
		printf("     Down session moved to %s\n", st_name(s->state));
		bad = 1;
	}

	s = sess_init(ST_UP);
	s->last_rx_us = 0;
	fsm_detect(s, 10000000);
	if (s->state != ST_UP) {
		printf("     session with no rx yet moved to %s\n", st_name(s->state));
		bad = 1;
	}

	report("detect-guards", bad, NULL);
}

/* The doubled budget assumes the sweep covers the session. A multihop session
 * arriving on an interface without the program never reaches it, so it must
 * keep the plain budget.
 */
static void case_backstop_needs_kernel_sight(void)
{
	struct session *s;
	int bad = 0;

	use_ktx = 1;
	stub_events_fd = 3;

	s = sess_init(ST_UP);
	s->is_mhop = 1;
	s->ktx_seen_us = 0;
	fsm_detect(s, s->last_rx_us + 40000);
	if (s->state != ST_DOWN) {
		printf("     unseen by the kernel, still %s past the 30ms budget\n",
		       st_name(s->state));
		bad = 1;
	}

	s = sess_init(ST_UP);
	s->is_mhop = 1;
	s->ktx_seen_us = s->last_rx_us;
	fsm_detect(s, s->last_rx_us + 40000);
	if (s->state != ST_UP) {
		printf("     seen by the kernel, but userspace did not leave it the sweep\n");
		bad = 1;
	}

	use_ktx = 0;
	stub_events_fd = -1;
	report("backstop-needs-kernel-sight", bad, "plain budget when the kernel is blind");
}
