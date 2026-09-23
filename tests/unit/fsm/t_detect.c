// SPDX-License-Identifier: GPL-2.0
/* Part of fsm_run, split by subject; compiled as one unit via
 * tests/unit/fsm_run.c.
 */

/* Detection: the budget, and the poll-aware detect basis. */

/* Drive detect_vectors.h through fsm.c's copy of the rule; xdp_run drives
 * bfd_xdp.c's copy with the same vectors. last_rx_us and detect_iv_us are
 * cleared so step 0 takes the no-prior-interval branch.
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

/* fsm_detect: the budget is mult * interval, preferring r_mult over our
 * detect_mult, and max(r_min_tx, min_rx_us) when detect_iv_us is unset.
 */
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
