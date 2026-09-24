// SPDX-License-Identifier: GPL-2.0
/* main.c - the engine: a BFD data plane driven by FRR bfdd over bfddp, or one
 * static session.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/timerfd.h>
#include <sys/utsname.h>

#include "bfd_shared.h"
#include "util.h"
#include "log.h"
#include "session.h"
#include "dplane.h"
#include "ktx.h"
#include "fsm.h"
#include "stats.h"
#include "echo_tx.h"
#include "opts.h"
#include "sock.h"
#include "static.h"

/* A timerfd, since SO_RCVTIMEO rounds under 1ms up. */
static int tick_fd = -1;

/* For the stats dump. */
uint64_t loop_passes;
uint64_t loop_rx_wakeups; /* passes with a v4 control packet */

/* Log2 buckets, microseconds. */
uint64_t loop_gap_us[24];

/* An orderly exit sends AdminDown instead of leaving peers to time out. */
static volatile sig_atomic_t shutdown_wanted;
/* SIGUSR2 with --pin: exit leaving the program answering, for the next
 * engine to take over. A new engine started with the same --pin sends it
 * itself; a supervisor sending it restarts us on HANDOVER_EXIT.
 */
static volatile sig_atomic_t handover_wanted;
#define HANDOVER_EXIT 75
/* The dead-man bound is pushed this far out, so the program answers while no
 * engine runs, and no longer.
 */
#define HANDOVER_GRACE_US (10ull * 1000000)

static void shutdown_on_signal(int sig)
{
	if (sig == SIGUSR2)
		handover_wanted = 1;
	shutdown_wanted = 1;
}

/* --check: load the object and exit without attaching. */
static int check_load(void)
{
	struct utsname un;
	int rc = ktx_load();

	uname(&un);
	if (rc == 0)
		printf("xdp-bfd %s: bfd_xdp.o loads and is ABI-matched on %s %s\n",
		       BFD_XDP_VERSION, un.sysname, un.release);
	else
		printf("xdp-bfd %s: object did NOT load on %s %s (see above)\n", BFD_XDP_VERSION,
		       un.sysname, un.release);
	return rc ? 1 : 0;
}

static int tick_open(unsigned int tick_us)
{
	struct itimerspec its = {
		.it_interval = { .tv_sec = tick_us / 1000000,
				 .tv_nsec = (tick_us % 1000000) * 1000 },
	};

	if (tick_us != TICK_US_DEFAULT)
		log_info("engine: main loop tick %uus (default %uus)\n", tick_us, TICK_US_DEFAULT);
	tick_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (tick_fd < 0) {
		perror("timerfd_create");
		return -1;
	}
	its.it_value = its.it_interval;
	if (timerfd_settime(tick_fd, 0, &its, NULL)) {
		perror("timerfd_settime");
		return -1;
	}
	return 0;
}

/* Keys arrive once with their periods; notice rollovers once a second. */
static void auth_rollover_tick(void)
{
	static int64_t last;
	int64_t now = (int64_t)time(NULL);
	int i;

	if (now == last)
		return;
	last = now;

	for (i = 0; i < sess_max; i++) {
		struct session *s = &sessions[i];

		if (!s->used || !s->auth_nkeys)
			continue;
		if (s->auth_next_change == 0 || now < s->auth_next_change)
			continue;
		if (session_auth_evaluate(s, now))
			log_info("lid=%u authentication key %u is now in use\n", s->lid,
				 s->auth_keyid);
		/* Refresh the accept set even if the send key did not move. */
		ktx_mirror(s);
	}
}

/* A TX socket per session besides the shared ones; the usual soft limit is
 * 1024.
 */
static void nofile_raise(void)
{
	struct rlimit r;

	if (getrlimit(RLIMIT_NOFILE, &r))
		return;
	if (r.rlim_cur < r.rlim_max) {
		r.rlim_cur = r.rlim_max;
		setrlimit(RLIMIT_NOFILE, &r);
		getrlimit(RLIMIT_NOFILE, &r);
	}
	if (r.rlim_cur < sess_max + 64)
		log_err("open files limited to %llu; sessions past that send from the fallback socket\n",
			(unsigned long long)r.rlim_cur);
}

static int sessions_used(void)
{
	int n = 0;

	for (int i = 0; i < sess_max; i++)
		n += sessions[i].used;
	return n;
}

/* dp-hold orphans stay silent. */
static void shutdown_announce(void)
{
	int announced = 0;

	for (int i = 0; i < sess_max; i++) {
		struct session *cs = &sessions[i];

		if (!cs->used || cs->orphaned)
			continue;
		fsm_announce_down(cs);
		announced++;
	}
	log_info("shutdown: announced AdminDown on %d session(s)\n", announced);
}

static void poll_add(struct pollfd *pfd, int *np, int fd)
{
	if (fd < 0)
		return;
	pfd[*np].fd = fd;
	pfd[*np].events = POLLIN;
	(*np)++;
}

/* Services the dplane and marks the RX sockets with packets. */
static void loop_wait(int ready[RX_NSOCK])
{
	struct pollfd pfd[4 + RX_NSOCK] = { 0 };
	int dp_l = -1, dp_c = -1, rdl = 0, rdc = 0, np = 0;
	uint64_t exp;

	dp_fds(&dp_l, &dp_c);
	poll_add(pfd, &np, tick_fd);
	poll_add(pfd, &np, ktx_events_fd());
	for (int i = 0; i < RX_NSOCK; i++)
		poll_add(pfd, &np, rx_socks[i].fd);
	poll_add(pfd, &np, dp_l);
	poll_add(pfd, &np, dp_c);

	poll(pfd, np, -1);
	if (pfd[0].revents & POLLIN)
		(void)!read(tick_fd, &exp, sizeof(exp));

	for (int k = 0; k < np; k++) {
		if (!(pfd[k].revents & POLLIN))
			continue;
		for (int i = 0; i < RX_NSOCK; i++)
			if (pfd[k].fd == rx_socks[i].fd)
				ready[i] = 1;
		if (dp_l >= 0 && pfd[k].fd == dp_l)
			rdl = 1;
		if (dp_c >= 0 && pfd[k].fd == dp_c)
			rdc = 1;
	}
	if (rdl)
		dp_accept();
	if (rdc)
		dp_read();
}

static void loop_gap_record(uint64_t t)
{
	static uint64_t prev;

	if (prev) {
		uint64_t d = t - prev;
		int b = 0;

		while (d >>= 1)
			b++;
		loop_gap_us[b < 24 ? b : 23]++;
	}
	prev = t;
}

/* SESSION_AUTH but no DP_SESSION_AUTH: a bfdd without the key extension. It
 * never heals, so warn after 1s.
 */
static void auth_keys_watch(struct session *cs, uint64_t t)
{
	if (cs->auth_present && cs->auth_nkeys == 0) {
		if (!cs->auth_keys_deadline_us)
			cs->auth_keys_deadline_us = t + 1000000;
		else if (!cs->auth_nokeys_warned && t >= cs->auth_keys_deadline_us) {
			log_err("lid=%u: bfdd offloaded an authenticated session but sent no keys within 1s; this bfdd predates the DP_SESSION_AUTH key extension. Upgrade bfdd or keep authenticated sessions off the data plane.\n",
				cs->lid);
			cs->auth_nokeys_warned = 1;
		}
	} else {
		cs->auth_keys_deadline_us = 0;
		cs->auth_nokeys_warned = 0;
	}
}

/* A session nothing touched is still looked at this often. */
#define WAKE_CAP_US 100000

/* The soonest anything in the pass acts on the session. */
static uint64_t sess_next_wake(const struct session *s, uint64_t t)
{
	uint64_t w = t + WAKE_CAP_US, at = fsm_tx_next_at(s, t);

	if (at < w)
		w = at;
	if (s->state != ST_DOWN && s->state != ST_ADMINDOWN && s->last_rx_us &&
	    !demand_detect_held(s)) {
		uint64_t iv = s->detect_iv_us;
		uint8_t mult = s->r_mult ? s->r_mult : s->detect_mult;

		if (!iv)
			iv = s->r_min_tx > s->min_rx_us ? s->r_min_tx : s->min_rx_us;
		at = s->last_rx_us + (uint64_t)mult * iv;
		if (at < w)
			w = at;
	}
	if (echo_interval(s) && s->next_echo_tx_us < w)
		w = s->next_echo_tx_us;
	if (s->orphaned && s->orphan_deadline_us < w)
		w = s->orphan_deadline_us;
	return w > t ? w : t;
}

static void session_pass(uint64_t t)
{
	if (dp_reconcile_us && t >= dp_reconcile_us) {
		dp_reconcile_us = 0;
		for (int i = 0; i < sess_max; i++)
			if (sessions[i].used && sessions[i].orphaned)
				sess_teardown_one(&sessions[i], "not re-added by bfdd");
	}

	/* Sweep verdicts first, so this pass sees them. */
	ktx_drain_events();

	ktx_sync_due(t);
	for (int i = 0; i < sess_max; i++) {
		struct session *cs = &sessions[i];

		/* The wake array only, so a session not due costs no cache miss. */
		if (sess_wake_at[i] > t)
			continue;
		if (!cs->used) {
			sess_wake_at[i] = UINT64_MAX;
			continue;
		}
		if (cs->orphaned && t >= cs->orphan_deadline_us) {
			sess_teardown_one(cs, "hold expired");
			continue;
		}
		auth_keys_watch(cs, t);
		fsm_detect(cs, t);
		fsm_tx(cs, t);
		echo_tx_maybe(cs, t);
		dp_reresolve_wildcard(cs, t);
		ktx_mirror(cs);
		/* Whatever touched it during the visit has been handled. */
		sess_wake_at[i] = cs->used ? sess_next_wake(cs, t) : UINT64_MAX;
	}
}

int main(int argc, char **argv)
{
	/* Per socket per pass, so a flood cannot starve TX, detection or the
	 * dplane.
	 */
	const int drain_budget = 64;
	struct opts o;
	int rc;

	setvbuf(stdout, NULL, _IOLBF, 0);

	rc = opts_parse(argc, argv, &o);
	if (rc)
		return rc < 0 ? 1 : 0;
	if (o.check) {
		ktx_pin_dir = NULL; /* loads only; takes nothing over */
		return check_load();
	}
	if (!opts_complete(&o, argv[0]))
		return 1;
	if (sess_table_init(sess_max)) {
		log_err("cannot allocate %d sessions\n", sess_max);
		return 1;
	}

	nofile_raise();
	/* A running engine hands over only once the slow part, loading and
	 * verifying the object, is done here: then it is gone for milliseconds.
	 */
	if (ktx_pin_dir) {
		int old = ktx_pin_holder();

		if (old && (ktx_load() || ktx_pin_take_over(old)))
			return 1;
	}
	if (rx_open_all() || tick_open(o.tick_us))
		return 1;
	tx_open_fallback();

	if (o.ktx_if) {
		if (ktx_attach(o.ktx_if))
			return 1;
		echo_tx_init(o.ktx_if);
		use_ktx = 1;
	}
	if (o.dplane && dp_listen_init(o.dplane))
		return 1;
	/* Before the first pass, so nothing overwrites what the program holds. */
	if (ktx_reused)
		ktx_adopt(dp_hold_us);
	ktx_pin_claim();

	srandom(getpid() ^ time(NULL));
	/* The handlers only set flags. */
	signal(SIGUSR1, stats_on_signal);
	signal(SIGTERM, shutdown_on_signal);
	signal(SIGINT, shutdown_on_signal);
	if (ktx_pin_dir)
		signal(SIGUSR2, shutdown_on_signal);

	if (o.local && static_session_add(&o))
		return 1;

	for (;;) {
		int ready[RX_NSOCK] = { 0 };
		uint64_t t;

		auth_rollover_tick();

		dp_flush();

		/* Deferred state changes go out in the room the flush freed. */
		dp_notify_flush_pending();

		if (shutdown_wanted && handover_wanted) {
			ktx_heartbeat(now_us() + HANDOVER_GRACE_US);
			log_info("handover: leaving %d session(s) to the next engine\n",
				 sessions_used());
			return HANDOVER_EXIT;
		}
		if (shutdown_wanted) {
			shutdown_announce();
			ktx_unpin();
			break;
		}
		if (stats_wanted) {
			stats_wanted = 0;
			stats_dump();
		}

		loop_wait(ready);
		t = now_us();
		loop_passes++;
		/* After poll(), so a loop stuck in poll stops the dead-man
		 * heartbeat.
		 */
		ktx_heartbeat(t);
		loop_gap_record(t);

		for (int i = 0; i < RX_NSOCK; i++) {
			if (ready[i] && rx_drain(&rx_socks[i], t, drain_budget) && i == 0)
				loop_rx_wakeups++;
		}

		session_pass(t);
	}
	return 0;
}
