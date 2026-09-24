// SPDX-License-Identifier: GPL-2.0
/* fsm_run.c - the engine's state machine, case by case, with its engine
 * dependencies stubbed. Sends fail, so this checks state, diag and
 * notification, not the wire.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "bfd_auth.h"
#include "session.h"
#include "fsm.h"
#include "detect_vectors.h"

#include "report.h"


static struct session table[BFD_MAX_SESSIONS];
struct session *sessions = table;
int sess_max = BFD_MAX_SESSIONS;
uint64_t sess_wake_at[SESSIONS_CEIL];
int use_ktx;	       /* 0: the kernel-TX gate in fsm_tx stays shut */
uint64_t *ktx_seq_mem; /* no program: the session's own counter */

/* No program, so no sweep ring unless a case pretends there is one. */
static int stub_events_fd = -1;

void ktx_sync(struct session *s, uint64_t t)
{
	(void)s;
	(void)t;
}

int ktx_events_fd(void)
{
	return stub_events_fd;
}

static int notify_calls;

void dp_notify_state(struct session *s)
{
	(void)s;
	notify_calls++;
}


#include "fsm/harness.c"
#include "fsm/t_rx.c"
#include "fsm/t_tx.c"
#include "fsm/t_detect.c"
#include "fsm/t_demand.c"
#include "fsm/t_auth.c"

int main(void)
{
	run_table();
	run_detect_vectors();
	case_zero_remote_min_rx_halts_tx();
	case_failed_send_keeps_pending();
	case_tx_bind_skips_taken_ports();
	case_tx_next_at();
	case_authenticated_output_verifies();
	case_no_sendable_key_sends_nothing();
	case_echo_only_change_notifies();
	case_passive();
	case_admin_down();
	case_poll_bits();
	case_notify();
	case_slow_rate_honours_remote_min_rx();
	case_no_final_in_admin_down();
	case_auth_window_ages_without_send_key();

	/* 10ms basis, mult 3: 30ms budget */
	case_detect("detect-under-budget", 10000, 3, 3, 20000, ST_UP);
	case_detect("detect-past-budget", 10000, 3, 3, 40000, ST_DOWN);
	/* r_mult wins over detect_mult: budget 10ms, not 50ms */
	case_detect("detect-uses-peer-mult", 10000, 1, 5, 20000, ST_DOWN);
	/* detect_iv_us unset falls back to max(r_min_tx, min_rx_us) = 10ms */
	case_detect("detect-iv-fallback-under", 0, 3, 3, 20000, ST_UP);
	case_detect("detect-iv-fallback-past", 0, 3, 3, 40000, ST_DOWN);
	case_detect_negative();
	case_detect_guards();
	case_backstop_needs_kernel_sight();

	case_jitter(3, 75, 100, "jitter-mult3-75-100pct");
	case_jitter(1, 75, 90, "jitter-mult1-75-90pct");

	case_demand_bit();
	case_demand_tx_hold();
	case_demand_poll();
	case_demand_announce();
	case_demand_detect_hold();

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
