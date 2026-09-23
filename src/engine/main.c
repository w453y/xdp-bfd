// SPDX-License-Identifier: GPL-2.0
/*
 * main.c - userspace BFD endpoint (RFC 5880/5881 subset).
 *
 * Runs as a distributed-BFD data plane for FRR: bfdd connects over the
 * bfddp protocol and drives session lifecycle, this engine runs the
 * sessions and reports state changes back. Stock FRR, no patches.
 *
 * Modes:
 *   ./bfd_tx <local-ip> <peer-ip> [--kernel-tx <if>]    static session
 *     --auth <type>:<keyid>:<key>   authenticate that static session
 *                                   (simple, keyed-sha1, meticulous-sha1)
 *   ./bfd_tx --dplane <port|sock-path> [--kernel-tx <if>]  bfdd-driven
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
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

/* Loop clock: a timerfd, so sub-millisecond ticks are honoured. SO_RCVTIMEO
 * would round anything under 1ms up.
 */
static int tick_fd = -1;

/* Main loop passes, for the stats dump. */
uint64_t loop_passes;
uint64_t loop_rx_wakeups; /* passes on which the v4 control socket had a packet */

/* Inter-pass gap histogram, log2 buckets in microseconds. */
uint64_t loop_gap_us[24];

/* SIGTERM and SIGINT request an orderly exit, so peers get AdminDown instead
 * of a detect timeout.
 */
static volatile sig_atomic_t shutdown_wanted;

static void shutdown_on_signal(int sig)
{
	(void)sig;
	shutdown_wanted = 1;
}

/* --check: load the object (ABI check and verifier), report the verdict and
 * kernel, and exit without attaching.
 */
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
	/* No SO_RCVTIMEO: poll() is the only wait and every drain is
	 * MSG_DONTWAIT.
	 */
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

/* Re-choose keys whose periods have moved on. The chain arrives once, so
 * rollovers are noticed here; once a second suits periods in whole seconds.
 */
static void auth_rollover_tick(void)
{
	static int64_t last;
	int64_t now = (int64_t)time(NULL);
	int i;

	if (now == last)
		return;
	last = now;

	for (i = 0; i < MAX_SESSIONS; i++) {
		struct session *s = &sessions[i];

		if (!s->used || !s->auth_nkeys)
			continue;
		/* Nothing changes until the next boundary, and a session
		 * whose keys never expire has none.
		 */
		if (s->auth_next_change == 0 || now < s->auth_next_change)
			continue;
		if (session_auth_evaluate(s, now))
			log_info("lid=%u authentication key %u is now in use\n", s->lid,
				 s->auth_keyid);
		/* The acceptable set is evaluated here too, so the program
		 * is refreshed whether or not the transmit key moved.
		 */
		ktx_mirror(s);
	}
}

/* Announce AdminDown to every peer before exiting. dp-hold orphans are
 * skipped: they must survive unnoticed.
 */
static void shutdown_announce(void)
{
	int announced = 0;

	for (int i = 0; i < MAX_SESSIONS; i++) {
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

/* Wait for the tick or any input: the timerfd, the sweep event ring, the RX
 * sockets, and the dplane listener and connection. Services the dplane and
 * sets ready[] for the RX sockets that have packets.
 */
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
	/* Drain the timer so it does not stay readable. */
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

/* Authenticated session whose keys never arrived: SESSION_AUTH but no
 * DP_SESSION_AUTH, as from a bfdd without the key extension. Unlike a
 * rollover gap this never heals, so warn after a 1s grace.
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
		/* keys arrived, or authentication withdrawn: disarm, and
		 * re-arm for a future recurrence.
		 */
		cs->auth_keys_deadline_us = 0;
		cs->auth_nokeys_warned = 0;
	}
}

static void session_pass(uint64_t t)
{
	if (dp_reconcile_us && t >= dp_reconcile_us) {
		dp_reconcile_us = 0;
		for (int i = 0; i < MAX_SESSIONS; i++)
			if (sessions[i].used && sessions[i].orphaned)
				sess_teardown_one(&sessions[i], "not re-added by bfdd");
	}

	/* Apply the sweep's verdicts first, so this pass sees sessions the
	 * kernel already declared down.
	 */
	ktx_drain_events();

	/* One batch map fetch for the whole pass. */
	ktx_poll_all();
	for (int i = 0; i < MAX_SESSIONS; i++) {
		struct session *cs = &sessions[i];

		if (!cs->used)
			continue;
		if (cs->orphaned && t >= cs->orphan_deadline_us) {
			sess_teardown_one(cs, "hold expired");
			continue;
		}
		auth_keys_watch(cs, t);
		ktx_poll_map(cs, t);
		fsm_detect(cs, t);
		fsm_tx(cs, t);
		echo_tx_maybe(cs, t);
		dp_reresolve_wildcard(cs, t);
		ktx_mirror(cs);
	}
}

int main(int argc, char **argv)
{
	/* Packets drained per socket per pass. The bound keeps a flood from
	 * starving TX, detection and the dplane; one per session clears a
	 * legitimate burst in one pass.
	 */
	const int drain_budget = MAX_SESSIONS;
	struct opts o;
	int rc;

	setvbuf(stdout, NULL, _IOLBF, 0);

	rc = opts_parse(argc, argv, &o);
	if (rc)
		return rc < 0 ? 1 : 0;
	if (o.check)
		return check_load();
	if (!opts_complete(&o, argv[0]))
		return 1;

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

	srandom(getpid() ^ time(NULL));
	/* Both handlers set a flag and nothing else; the work happens in the
	 * loop below, so neither needs to be async-signal-safe.
	 */
	signal(SIGUSR1, stats_on_signal);
	signal(SIGTERM, shutdown_on_signal);
	signal(SIGINT, shutdown_on_signal);

	if (o.local && static_session_add(&o))
		return 1;

	for (;;) {
		int ready[RX_NSOCK] = { 0 };
		uint64_t t;

		auth_rollover_tick();

		/* Anything that did not fit the socket last pass. Cheap when
		 * the queue is empty, which is the normal case.
		 */
		dp_flush();

		/* Room the flush just freed goes to sessions whose state
		 * change was deferred rather than dropped.
		 */
		dp_notify_flush_pending();

		if (shutdown_wanted) {
			shutdown_announce();
			break;
		}
		if (stats_wanted) {
			stats_wanted = 0;
			stats_dump();
		}

		loop_wait(ready);
		t = now_us();
		loop_passes++;
		/* Heartbeat for the dead-man gate in bfd_xdp.c. Taken after
		 * poll() returns, so a loop stuck in poll stops beating.
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
