// SPDX-License-Identifier: GPL-2.0
/* fsm_run.c - the engine's state machine, driven directly.
 *
 * RFC 5880 s6.8.6 is a table: our state, the peer's state, and a few flags
 * decide the transition, the diagnostic and whether the control plane is
 * told. Nothing has ever tested it. The lab suite exercises it only
 * incidentally, through whatever FRR happens to do.
 *
 * No seams were needed. fsm_rx, fsm_detect and fsm_tx all take their clock
 * as a parameter, and fsm.o refers to only three engine symbols outside
 * libc: dp_notify_state, sessions and use_ktx. All three are stubbed
 * below, so this links against the real fsm.o with no test build of the
 * engine and no #ifdefs in shipped code.
 *
 * tx_one's sendto lands on an unopened socket and fails; fsm.c ignores the
 * return, which suits us. This asserts state, diag and notification, not
 * what reached the wire - the wire side is tests/unit/xdp_run.c and the
 * injection suite.
 *
 *     make test-fsm
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "session.h"
#include "fsm.h"

/* ---------- stubs ---------- */

struct session sessions[MAX_SESSIONS];
int use_ktx;                 /* 0: the kernel-TX gate in fsm_tx stays shut */

static int notify_calls;

void dp_notify_state(struct session *s)
{
	(void)s;
	notify_calls++;
}

/* ---------- helpers ---------- */

static int fails;

/* A session in a chosen state with a peer already known. Timers are the
 * mesh's 10ms; nothing here depends on the values except the detect tests. */
/* Sessions must live in the global array: fsm.c derives a session's
 * slot index by pointer arithmetic against `sessions`, so a
 * stack-local struct produces a garbage index the moment anything
 * reaches tx_one. Every case below uses slot 0. */
#define TEST_SLOT 0

static struct session *sess_init(uint8_t state)
{
	struct session *s = &sessions[TEST_SLOT];

	memset(s, 0, sizeof(*s));
	s->used         = 1;
	s->lid          = 0x11111111;
	s->wire_disc    = s->lid;
	s->state        = state;
	s->min_tx_us    = 10000;
	s->applied_tx_us = 10000;
	s->min_rx_us    = 10000;
	s->detect_mult  = 3;
	s->r_min_tx     = 10000;
	s->r_min_rx     = 10000;
	s->r_mult       = 3;
	s->detect_iv_us = 10000;
	s->last_rx_us   = 1000000;
	return s;
}

static struct bfd_ctrl_pkt pkt(uint8_t peer_state, uint8_t extra_flags)
{
	struct bfd_ctrl_pkt p = {0};

	p.vers_diag   = 1 << 5;
	p.flags       = (peer_state << 6) | extra_flags;
	p.detect_mult = 3;
	p.len         = 24;
	p.my_disc     = htonl(0x22222222);
	p.your_disc   = htonl(0x11111111);
	p.min_tx      = htonl(10000);
	p.min_rx      = htonl(10000);
	return p;
}

static const char *st_name(uint8_t s)
{
	switch (s) {
	case ST_ADMINDOWN: return "AdminDown";
	case ST_DOWN:      return "Down";
	case ST_INIT:      return "Init";
	case ST_UP:        return "Up";
	default:           return "?";
	}
}

/* ---------- the table ---------- */

/* One row: from `ours` with the peer at `theirs`, expect to land in `want`
 * with diagnostic `want_diag`.
 *
 * The passive and admin_down columns are separate cases below rather than
 * columns here, because they change whether the row applies at all. */
static void row(uint8_t ours, uint8_t theirs, uint8_t want,
		uint8_t want_diag, const char *name)
{
	struct session *s;
	struct bfd_ctrl_pkt p = pkt(theirs, 0);
	uint64_t t = 2000000;
	int bad = 0;

	s = sess_init(ours);
	fsm_rx(s, &p, t);

	if (s->state != want) {
		printf("     %s + peer %s -> %s, want %s\n", st_name(ours),
		       st_name(theirs), st_name(s->state), st_name(want));
		bad = 1;
	}
	if (s->state != ours && s->diag != want_diag) {
		printf("     diag %u, want %u\n", s->diag, want_diag);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-44s\n", name);
		fails++;
	} else {
		printf("ok   %-44s %s\n", name, st_name(s->state));
	}
}

static void run_table(void)
{
	/* RFC 5880 s6.8.6. Down + peer Down starts the handshake; Down +
	 * peer Init completes it in one step. Init + peer Down is NOT a
	 * transition: the peer has not seen us yet. */
	row(ST_DOWN, ST_DOWN, ST_INIT, 0, "down+down=init");
	row(ST_DOWN, ST_INIT, ST_UP,   0, "down+init=up");
	row(ST_DOWN, ST_UP,   ST_DOWN, 0, "down+up=down");

	row(ST_INIT, ST_DOWN, ST_INIT, 0, "init+down=init");
	row(ST_INIT, ST_INIT, ST_UP,   0, "init+init=up");
	row(ST_INIT, ST_UP,   ST_UP,   0, "init+up=up");

	row(ST_UP,   ST_DOWN, ST_DOWN, 3, "up+down=down-diag3");
	row(ST_UP,   ST_INIT, ST_UP,   0, "up+init=up");
	row(ST_UP,   ST_UP,   ST_UP,   0, "up+up=up");

	/* AdminDown from the peer tears down from any state, diag 3
	 * (neighbour signalled session down), and is checked before the
	 * per-state switch. */
	row(ST_DOWN, ST_ADMINDOWN, ST_DOWN, 3, "down+admindown=down");
	row(ST_INIT, ST_ADMINDOWN, ST_DOWN, 3, "init+admindown=down");
	row(ST_UP,   ST_ADMINDOWN, ST_DOWN, 3, "up+admindown=down");
}

/* A passive session does not start the handshake: it answers, but Down +
 * peer Down leaves it Down rather than moving to Init. */
static void case_passive(void)
{
	struct session *s;
	struct bfd_ctrl_pkt p = pkt(ST_DOWN, 0);

	s = sess_init(ST_DOWN);
	s->passive = 1;
	fsm_rx(s, &p, 2000000);

	if (s->state != ST_DOWN) {
		printf("     passive session moved to %s\n", st_name(s->state));
		printf("FAIL %-44s\n", "passive-down+down-stays-down");
		fails++;
	} else {
		printf("ok   %-44s Down\n", "passive-down+down-stays-down");
	}
}

/* admin_down short-circuits before any transition. */
static void case_admin_down(void)
{
	struct session *s;
	struct bfd_ctrl_pkt p = pkt(ST_INIT, 0);

	s = sess_init(ST_DOWN);
	s->admin_down = 1;
	fsm_rx(s, &p, 2000000);

	if (s->state != ST_DOWN) {
		printf("     admin_down session moved to %s\n",
		       st_name(s->state));
		printf("FAIL %-44s\n", "admin-down-ignores-peer");
		fails++;
	} else {
		printf("ok   %-44s Down\n", "admin-down-ignores-peer");
	}
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
		printf("     applied_tx_us is %u, want 50000 after the poll\n",
		       s->applied_tx_us);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-44s\n", "poll-final-bits");
		fails++;
	} else {
		printf("ok   %-44s\n", "poll-final-bits");
	}
}

/* dp_notify_state runs only when something the control plane reports
 * actually moved, and only while Up. It also has to run AFTER the session
 * is updated: it reads the peer's timers, flags, mult and discriminator
 * out of the session, and it used to ship the previous values. */
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
		printf("     unchanged packet notified %d time(s)\n",
		       notify_calls);
		bad = 1;
	}

	/* Timer change while Up: notify. */
	s = sess_init(ST_UP);
	notify_calls = 0;
	p = pkt(ST_UP, 0);
	p.min_tx = htonl(50000);
	fsm_rx(s, &p, 2000000);
	if (notify_calls != 1) {
		printf("     timer change notified %d time(s), want 1\n",
		       notify_calls);
		bad = 1;
	}
	if (s->r_min_tx != 50000) {
		printf("     r_min_tx is %u at notify time, want 50000\n",
		       s->r_min_tx);
		bad = 1;
	}

	/* Mult-only change: bfdd displays it and it alters the peer's
	 * budget for us, so it counts. */
	s = sess_init(ST_UP);
	notify_calls = 0;
	p = pkt(ST_UP, 0);
	p.detect_mult = 5;
	fsm_rx(s, &p, 2000000);
	if (notify_calls != 1) {
		printf("     mult change notified %d time(s), want 1\n",
		       notify_calls);
		bad = 1;
	}

	/* Same change below Up: no notify, because the session is not Up. */
	s = sess_init(ST_DOWN);
	notify_calls = 0;
	p = pkt(ST_UP, 0);
	p.min_tx = htonl(50000);
	fsm_rx(s, &p, 2000000);
	if (notify_calls != 0) {
		printf("     change while Down notified %d time(s)\n",
		       notify_calls);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-44s\n", "notify-on-change-only");
		fails++;
	} else {
		printf("ok   %-44s\n", "notify-on-change-only");
	}
}

/* fsm_detect. The budget is mult * interval, and both have fallbacks:
 * r_mult is preferred over our own detect_mult (the peer's multiplier is
 * what governs how long it will wait for us), and detect_iv_us falls back
 * to max(r_min_tx, min_rx_us) when unset. */
static void case_detect(const char *name, uint32_t iv_us, uint8_t r_mult,
			uint8_t detect_mult, uint64_t silent_us, uint8_t want)
{
	struct session *s;

	s = sess_init(ST_UP);
	s->detect_iv_us = iv_us;
	s->r_mult       = r_mult;
	s->detect_mult  = detect_mult;
	s->last_rx_us   = 10000000;

	fsm_detect(s, s->last_rx_us + silent_us);

	if (s->state != want) {
		printf("     state %s, want %s\n", st_name(s->state),
		       st_name(want));
		printf("FAIL %-44s\n", name);
		fails++;
	} else {
		printf("ok   %-44s %s\n", name, st_name(s->state));
	}
}

/* now earlier than last_rx_us. fsm_detect clamps the signed delta to 0
 * rather than letting it wrap, which would otherwise read as ~584 years
 * of silence and tear down every session on a clock step. */
static void case_detect_negative(void)
{
	struct session *s;

	s = sess_init(ST_UP);
	s->last_rx_us = 10000000;
	fsm_detect(s, s->last_rx_us - 5000);

	if (s->state != ST_UP) {
		printf("     state %s - the delta wrapped\n", st_name(s->state));
		printf("FAIL %-44s\n", "detect-negative-delta");
		fails++;
	} else {
		printf("ok   %-44s Up\n", "detect-negative-delta");
	}
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
		printf("     session with no rx yet moved to %s\n",
		       st_name(s->state));
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-44s\n", "detect-guards");
		fails++;
	} else {
		printf("ok   %-44s\n", "detect-guards");
	}
}

/* RFC 5880 s6.8.7: the transmit interval is jittered to 75-100% of the
 * negotiated value, or 75-90% when detect_mult is 1 (with a multiplier of
 * one there is no slack for a late packet, so the ceiling comes down).
 *
 * A property, not a value: draw enough intervals to see the bounds. This
 * is the kind of thing that silently regresses to "no jitter at all" and
 * nobody notices until a mesh synchronises into a burst. */
static void case_jitter(uint8_t mult, unsigned lo_pct, unsigned hi_pct,
			const char *name)
{
	const uint32_t iv = 10000;
	const int draws = 10000;
	uint64_t lo = (uint64_t)iv * lo_pct / 100;
	uint64_t hi = (uint64_t)iv * hi_pct / 100;
	uint64_t seen_lo = ~0ull, seen_hi = 0;
	struct session *s;
	int bad = 0;

	for (int i = 0; i < draws; i++) {
		uint64_t t = 100000000ull + (uint64_t)i * iv * 4;

		s = sess_init(ST_UP);
		s->detect_mult   = mult;
		s->r_mult        = mult;
		s->min_tx_us     = iv;
		s->applied_tx_us = iv;
		s->r_min_rx      = iv;
		s->last_rx_us    = t;
		s->next_tx_us    = t;

		fsm_tx(s, t);

		uint64_t gap = s->next_tx_us - t;

		if (gap < seen_lo)
			seen_lo = gap;
		if (gap > seen_hi)
			seen_hi = gap;
	}

	if (seen_lo < lo) {
		printf("     min gap %lluus, below %llu%% of %u\n",
		       (unsigned long long)seen_lo,
		       (unsigned long long)lo_pct, iv);
		bad = 1;
	}
	if (seen_hi > hi) {
		printf("     max gap %lluus, above %llu%% of %u\n",
		       (unsigned long long)seen_hi,
		       (unsigned long long)hi_pct, iv);
		bad = 1;
	}
	/* If the jitter were removed the spread would collapse; require it
	 * to cover at least half the permitted band. */
	if (seen_hi - seen_lo < (hi - lo) / 2) {
		printf("     spread %llu-%lluus is too narrow to be jittered\n",
		       (unsigned long long)seen_lo, (unsigned long long)seen_hi);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-44s\n", name);
		fails++;
	} else {
		printf("ok   %-44s %llu-%lluus of %u\n", name,
		       (unsigned long long)seen_lo, (unsigned long long)seen_hi,
		       iv);
	}
}

int main(void)
{
	run_table();
	case_passive();
	case_admin_down();
	case_poll_bits();
	case_notify();

	/* 10ms basis, mult 3: 30ms budget */
	case_detect("detect-under-budget", 10000, 3, 3, 20000, ST_UP);
	case_detect("detect-past-budget",  10000, 3, 3, 40000, ST_DOWN);
	/* r_mult wins over detect_mult: budget 10ms, not 50ms */
	case_detect("detect-uses-peer-mult", 10000, 1, 5, 20000, ST_DOWN);
	/* detect_iv_us unset falls back to max(r_min_tx, min_rx_us) = 10ms */
	case_detect("detect-iv-fallback-under", 0, 3, 3, 20000, ST_UP);
	case_detect("detect-iv-fallback-past",  0, 3, 3, 40000, ST_DOWN);
	case_detect_negative();
	case_detect_guards();

	case_jitter(3, 75, 100, "jitter-mult3-75-100pct");
	case_jitter(1, 75,  90, "jitter-mult1-75-90pct");

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
