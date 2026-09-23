// SPDX-License-Identifier: GPL-2.0
/* Part of fsm_run, split by subject; compiled as one unit via
 * tests/unit/fsm_run.c.
 */

/* Demand mode (RFC 5880 s6.6).
 *
 * Drives the predicates through fsm_tx and fsm_detect, so the wiring is
 * covered. tx_pkts witnesses transmission, demand_announced the D bit.
 */

/* A session Up with the peer Up, optionally demanding on either side. */
static struct session *demand_sess(int we_demand, int peer_demands)
{
	struct session *s = sess_init(ST_UP);

	s->r_state = ST_UP;
	s->demand = we_demand;
	s->r_flags = peer_demands ? BFD_F_DEMAND : 0;
	/* Past the announcement quota by default: these cases are about
	 * the steady state, and the one that is not says so.
	 */
	s->demand_announced = DEMAND_ANNOUNCE_N;
	return s;
}

/* The D bit goes out only once BOTH ends are Up (s6.8.6). */
static void case_demand_bit(void)
{
	struct session *s;

	s = demand_sess(1, 0);
	s->r_state = ST_INIT;
	s->demand_announced = 0;
	s->next_tx_us = 0;
	fsm_tx(s, 2000000);
	report("demand-bit-withheld-until-peer-up", s->demand_announced != 0,
	       "no D while peer is Init");

	s = demand_sess(1, 0);
	s->demand_announced = 0;
	s->next_tx_us = 0;
	fsm_tx(s, 2000000);
	report("demand-bit-set-when-both-up", s->demand_announced != 1, "D on the wire");

	/* Not configured to demand: never set it, however Up both are. */
	s = demand_sess(0, 0);
	s->demand_announced = 0;
	s->next_tx_us = 0;
	fsm_tx(s, 2000000);
	report("demand-bit-absent-when-unconfigured", s->demand_announced != 0, "no D");
}

/* s6.8.7: transmission stops because the PEER demanded, not because we
 * did.
 */
static void case_demand_tx_hold(void)
{
	struct session *s;
	uint64_t t = 2000000;

	s = demand_sess(0, 1);
	s->next_tx_us = 0;
	fsm_tx(s, t);
	report("demand-tx-held-when-peer-demands", s->tx_pkts != 0, "silent");

	/* We demand, the peer does not: we keep transmitting. */
	s = demand_sess(1, 0);
	s->next_tx_us = 0;
	fsm_tx(s, t);
	report("demand-tx-runs-when-only-we-demand", s->tx_pkts != 1, "still transmitting");

	/* A pending Final outranks the hold: the peer asked for it. */
	s = demand_sess(0, 1);
	s->next_tx_us = 0;
	s->send_final = 1;
	fsm_tx(s, t);
	report("demand-tx-final-exempt", s->tx_pkts != 1, "Final sent");

	/* So does our own Poll - it is the only way to verify the path. */
	s = demand_sess(0, 1);
	s->next_tx_us = 0;
	s->polling = 1;
	fsm_tx(s, t);
	report("demand-tx-poll-exempt", s->tx_pkts != 1, "Poll sent");

	/* The hold needs the peer Up too, not just its D bit. */
	s = demand_sess(0, 1);
	s->r_state = ST_INIT;
	s->next_tx_us = 0;
	fsm_tx(s, t);
	report("demand-tx-needs-peer-up", s->tx_pkts != 1, "transmitting");
}

/* A demanding session verifies its own path (RFC 5880 s6.6). The negatives
 * matter too: no poll right after hearing the peer, and none faster than the
 * detect budget.
 */
static void case_demand_poll(void)
{
	struct session *s;
	uint64_t t = 2000000;
	uint64_t saved = demand_poll_us;

	demand_poll_us = 1000000;

	/* Heard from a moment ago: nothing to verify. */
	s = demand_sess(1, 1);
	s->last_rx_us = t - 10000;
	fsm_tx(s, t);
	report("demand-poll-not-when-fresh", s->polling || s->demand_polls, "no poll");

	/* Unverified for the interval: poll. */
	s = demand_sess(1, 1);
	s->last_rx_us = t - 1000000;
	fsm_tx(s, t);
	report("demand-poll-when-stale", !s->polling || s->demand_polls != 1, "poll started");

	/* The poll re-arms detection from now. */
	report("demand-poll-rearms-detection", s->last_rx_us != t, "clock reset");

	/* Only we demand: detection is held, so the poll is what catches a
	 * dead peer.
	 */
	s = demand_sess(1, 0);
	s->last_rx_us = t - 1000000;
	fsm_tx(s, t);
	report("demand-poll-when-only-we-demand", s->demand_polls != 1, "poll started");

	/* The peer demands and we do not: our detection is running, so
	 * silence is already a fault and there is nothing to verify.
	 */
	s = demand_sess(0, 1);
	s->last_rx_us = t - 1000000;
	fsm_tx(s, t);
	report("demand-poll-not-when-only-peer-demands", s->demand_polls, "no poll");

	/* Never faster than the detect budget. The knob asks for 10ms; the
	 * session's budget is 3 x 10ms, so 20ms of silence is not yet due.
	 */
	demand_poll_us = 10000;
	s = demand_sess(1, 1);
	s->last_rx_us = t - 20000;
	fsm_tx(s, t);
	report("demand-poll-floors-at-detect-budget", s->demand_polls, "no poll");
	s = demand_sess(1, 1);
	s->last_rx_us = t - 40000;
	fsm_tx(s, t);
	report("demand-poll-fires-past-detect-budget", s->demand_polls != 1, "poll started");

	/* Zero turns it off. */
	demand_poll_us = 0;
	s = demand_sess(1, 1);
	s->last_rx_us = t - 60000000;
	fsm_tx(s, t);
	report("demand-poll-disarmed", s->polling || s->demand_polls, "no poll");

	demand_poll_us = saved;
}

/* Both ends demanding: we must get our own D out before going quiet, or
 * the peer never learns to stop and keeps transmitting forever.
 */
static void case_demand_announce(void)
{
	struct session *s = demand_sess(1, 1);
	uint64_t t = 2000000;
	int sent = 0;

	s->demand_announced = 0;
	/* Just heard from the peer, as on arriving here. A stale clock would
	 * trigger a verification poll, which lifts the hold under test.
	 */
	s->last_rx_us = t;
	for (int i = 0; i < 20; i++) {
		s->next_tx_us = 0; /* due every pass */
		fsm_tx(s, t);
		t += 10000;
	}
	sent = (int)s->tx_pkts;
	report("demand-announces-before-holding", sent != DEMAND_ANNOUNCE_N,
	       "3 D-marked, then quiet");
	report("demand-announce-counts-only-marked", s->demand_announced != DEMAND_ANNOUNCE_N,
	       "quota reached");

	/* Coming back round to Up is a fresh negotiation: the peer on the
	 * other side has not heard our D bit this time.
	 */
	state_transition(s, ST_DOWN, 1, t, "test");
	report("demand-announce-resets-on-transition", s->demand_announced != 0, "counter cleared");
}

/* s6.8.4: the detection timer does not run while WE are demanding - the
 * peer's silence is what we asked for.
 */
static void case_demand_detect_hold(void)
{
	struct session *s;
	/* last_rx_us is 1000000 and the budget is 3 x 10ms, so this is far
	 * past it: without a hold every one of these goes Down.
	 */
	uint64_t t = 1000000 + 500000;

	s = demand_sess(1, 0);
	fsm_detect(s, t);
	report("demand-detect-held-when-we-demand", s->state != ST_UP, "stayed Up through silence");

	/* The peer demanding does not license US to stop timing it out. */
	s = demand_sess(0, 1);
	fsm_detect(s, t);
	report("demand-detect-runs-when-peer-demands", s->state != ST_DOWN, "timed out");

	/* Our own Poll re-arms detection: that is what bounds the poll, so
	 * a lost Final brings the session down instead of hanging.
	 */
	s = demand_sess(1, 0);
	s->polling = 1;
	fsm_detect(s, t);
	report("demand-detect-runs-while-polling", s->state != ST_DOWN, "poll is bounded");

	/* And it needs the peer Up, same as the rest. */
	s = demand_sess(1, 0);
	s->r_state = ST_INIT;
	fsm_detect(s, t);
	report("demand-detect-needs-peer-up", s->state != ST_DOWN, "timed out");
}
