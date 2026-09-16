// SPDX-License-Identifier: GPL-2.0
/* Part of the xdp_run test, split by subject (CI-review item 5).
 * Compiled as one unit via tests/unit/xdp_run.c, which carries the
 * includes, the shared globals and main; include order there is the
 * dependency order (harness first, sweep last). */

/* The detection sweep. None of this has any coverage today: it runs from a
 * bpf_timer, and a timer never fires under test_run.
 *
 * detect_ns is detect_mult * detect_iv_us, and a session is torn down only
 * when the silence exceeds it AND the alive flag was still 1 - the
 * compare-and-swap is what stops two sweeps both emitting a Down. */
static void case_sweep(const char *name, unsigned int iv_us, unsigned int mult,
		       unsigned long long silent_ns, unsigned int alive_in,
		       unsigned int want_alive)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct session_state st = {0}, after = {0};
	struct tx_cfg cfg = {0};
	unsigned long long now = 1000ull * 1000 * 1000 * 60;   /* arbitrary */

	st.last_seen_ns  = now - silent_ns;
	st.detect_iv_us  = iv_us;
	st.detect_mult   = mult;
	st.alive         = alive_in;
	cfg.min_rx_us    = 10000;

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
	if (!sweep_put(&k, &st, &cfg) || !sweep_at(now)) {
		printf("FAIL %-40s setup\n", name);
		fails++;
		return;
	}

	if (bpf_map_lookup_elem(sweep_sess_fd, &k, &after)) {
		printf("FAIL %-40s no state back\n", name);
		fails++;
		return;
	}

	if ((unsigned)after.alive != want_alive) {
		printf("     alive is %u, want %u\n", (unsigned)after.alive, want_alive);
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s alive %u\n", name, (unsigned)after.alive);
	}

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
}

/* Demand mode (RFC 5880 s6.6): the engine asked this peer to stop
 * transmitting, so the silence the sweep measures is the silence we
 * requested. Without the hold every demanding session is torn down one
 * detection time after it goes quiet - which is immediately, since going
 * quiet is the whole point.
 *
 * alive must stay 1 rather than merely skipping the emit: bfd_loader
 * reports the flag directly, so clearing it would show every healthy
 * demand session as down. */
static void case_sweep_demand(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct session_state st = {0}, after = {0};
	struct tx_cfg cfg = {0};
	unsigned long long now = 1000ull * 1000 * 1000 * 60;

	st.last_seen_ns = now - 40000000ull;   /* well past 3 x 10ms */
	st.detect_iv_us = 10000;
	st.detect_mult  = 3;
	st.alive        = 1;
	cfg.min_rx_us   = 10000;
	cfg.demand_hold = 1;

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
	if (!sweep_put(&k, &st, &cfg) || !sweep_at(now) ||
	    bpf_map_lookup_elem(sweep_sess_fd, &k, &after)) {
		printf("FAIL %-40s setup\n", "sweep-demand-hold");
		fails++;
		return;
	}

	if ((unsigned)after.alive != 1) {
		printf("     alive is %u, want 1 - the hold did not apply\n",
		       (unsigned)after.alive);
		printf("FAIL %-40s\n", "sweep-demand-hold");
		fails++;
	} else {
		printf("ok   %-40s alive 1\n", "sweep-demand-hold");
	}

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
}

/* The receive window ages out (RFC 5880 s6.7).
 *
 * A peer that restarts picks a fresh random sequence, which will not sit
 * inside the window its predecessor left behind. Nothing else recovers
 * from that: the program validates authentication whether or not it is
 * answering, so the packets never reach userspace to be reconsidered.
 * Twice the detection time of silence is what the RFC gives for it, and
 * the sweep is where the silence is already measured.
 *
 * Both edges, because a window that ages out too eagerly is a replay
 * window that is not one.
 */
static void case_sweep_auth_resync(const char *name, unsigned long long silent_ns,
				   unsigned int want_seen, int demand_hold)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct session_state st = {0}, after = {0};
	struct tx_cfg cfg = {0};
	unsigned long long now = 1000ull * 1000 * 1000 * 60;

	/* 10ms basis, mult 3: detection is 30ms, so the window ages at 60ms. */
	st.last_seen_ns  = now - silent_ns;
	st.detect_iv_us  = 10000;
	st.detect_mult   = 3;
	st.alive         = 1;
	st.auth_rx_seen  = 1;
	st.auth_rx_seq   = 12345;
	cfg.min_rx_us    = 10000;
	cfg.auth_type    = BFD_AUTH_KEYED_SHA1;
	cfg.auth_present = 1;
	cfg.demand_hold  = demand_hold;

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
	if (!sweep_put(&k, &st, &cfg) || !sweep_at(now) ||
	    bpf_map_lookup_elem(sweep_sess_fd, &k, &after)) {
		printf("FAIL %-40s setup\n", name);
		fails++;
		return;
	}

	if (after.auth_rx_seen != want_seen) {
		printf("     auth_rx_seen is %u, want %u\n",
		       after.auth_rx_seen, want_seen);
		printf("FAIL %-40s\n", name);
		fails++;
	} else if (!want_seen && after.auth_rx_seq) {
		printf("     window cleared but the sequence was left behind\n");
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s auth_rx_seen %u\n", name, after.auth_rx_seen);
	}

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
}

/* now earlier than last_seen_ns. Without the signed guard the subtraction
 * wraps and every session looks silent for ~584 years. */
static void case_sweep_negative(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct session_state st = {0}, after = {0};
	struct tx_cfg cfg = {0};
	unsigned long long now = 1000ull * 1000 * 1000 * 60;

	st.last_seen_ns = now + 5000000ull;   /* 5ms in the future */
	st.detect_iv_us = 10000;
	st.detect_mult  = 3;
	st.alive        = 1;
	cfg.min_rx_us   = 10000;

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
	if (!sweep_put(&k, &st, &cfg) || !sweep_at(now) ||
	    bpf_map_lookup_elem(sweep_sess_fd, &k, &after)) {
		printf("FAIL %-40s setup\n", "sweep-negative-delta");
		fails++;
		return;
	}

	if ((unsigned)after.alive != 1) {
		printf("     alive is %u, want 1 - the delta wrapped\n",
		       (unsigned)after.alive);
		printf("FAIL %-40s\n", "sweep-negative-delta");
		fails++;
	} else {
		printf("ok   %-40s alive 1\n", "sweep-negative-delta");
	}

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
}

/* The echo advisory verdict.
 *
 * sweep.h computes echo_alive from echo_iv_us * detect_mult against
 * echo_last_seen_ns, and the comment there is emphatic that it is advisory
 * only: with userspace echo TX a local stall looks exactly like a path
 * fault, so this must never tear a session down. Every arm below therefore
 * checks alive as well as echo_alive - a stale echo on a session that is
 * receiving control packets must leave alive at 1. */
static void case_echo_advisory(const char *name, unsigned int echo_iv_us,
			       unsigned long long echo_silent_ns,
			       int set_last_seen, unsigned int want_echo_alive)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct session_state st = {0}, after = {0};
	struct tx_cfg cfg = {0};
	unsigned long long now = 1000ull * 1000 * 1000 * 60;
	int bad = 0;

	/* Control traffic is fresh throughout: the session is healthy by the
	 * only measure that is allowed to matter. */
	st.last_seen_ns = now - 1000000ull;
	st.detect_iv_us = 10000;
	st.detect_mult  = 3;
	st.alive        = 1;
	if (set_last_seen)
		st.echo_last_seen_ns = now - echo_silent_ns;

	cfg.min_rx_us  = 10000;
	cfg.echo_iv_us = echo_iv_us;

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
	if (!sweep_put(&k, &st, &cfg) || !sweep_at(now) ||
	    bpf_map_lookup_elem(sweep_sess_fd, &k, &after)) {
		printf("FAIL %-40s setup\n", name);
		fails++;
		return;
	}

	if (after.echo_alive != want_echo_alive) {
		printf("     echo_alive is %u, want %u\n", after.echo_alive,
		       want_echo_alive);
		bad = 1;
	}
	if ((unsigned)after.alive != 1) {
		printf("     alive is %u - the echo verdict tore the session down\n",
		       (unsigned)after.alive);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s echo_alive %u, alive 1\n", name,
		       after.echo_alive);
	}

	bpf_map_delete_elem(sweep_sess_fd, &k);
	bpf_map_delete_elem(sweep_cfg_fd, &k);
}

static void run_sweep_matrix(void)
{
	if (sweep_prog_fd < 0) {
		printf("     sweep object not loaded, skipping\n");
		return;
	}
	/* 10ms basis, mult 3: budget 30ms */
	case_sweep("sweep-silent-past-budget", 10000, 3, 40000000ull, 1, 0);
	case_sweep("sweep-silent-under-budget", 10000, 3, 20000000ull, 1, 1);
	/* already down: the CAS must not fire a second time */
	case_sweep("sweep-already-down-stays", 10000, 3, 40000000ull, 0, 0);
	/* detect_iv_us unset: falls back to max(min_tx_us, cfg->min_rx_us),
	 * which is 10000 here, so the budget is the same 30ms. An entry
	 * predating the field must not be treated as a zero budget. */
	case_sweep("sweep-iv-fallback-past", 0, 3, 40000000ull, 1, 0);
	case_sweep("sweep-iv-fallback-under", 0, 3, 20000000ull, 1, 1);
	/* now before last_seen_ns: a packet raced past the sweep's snapshot.
	 * The guard returns early rather than letting the unsigned delta
	 * wrap into an enormous silence. */
	case_sweep_negative();
	case_auth_required(0);
	case_auth_required(1);

	/* The control: a correctly signed packet is answered. Without it
	 * every rejection below would pass on a build that refused
	 * everything. */
#define KS BFD_AUTH_KEYED_SHA1
#define MS BFD_AUTH_METICULOUS_SHA1
	case_auth_present_without_send_key();
	case_auth_reject("auth-good-signature", KS, "topsecret", 7, 100, 0, 0, 1);
	case_auth_reject("auth-wrong-key",      KS, "wrongkey!", 7, 100, 0, 0, 0);
	case_auth_reject("auth-wrong-keyid",    KS, "topsecret", 9, 100, 0, 0, 0);
	case_auth_reject("auth-bad-digest",     KS, "topsecret", 7, 100, 1, 0, 0);
	/* Replay: the window already sits above this sequence. */
	case_auth_reject("auth-replayed-seq",   KS, "topsecret", 7, 100, 0, 500, 0);

	/* The one thing that separates the two SHA1 types. A sequence
	 * equal to the window is a repeat: RFC 5880 s6.7.4 lets the plain
	 * form take it - which is what allows a Final to answer a Poll
	 * without burning a sequence - and requires meticulous to refuse
	 * it. Same packet, same key, same window, opposite verdicts. */
	case_auth_reject("auth-equal-seq-plain",      KS, "topsecret", 7, 100,
			 0, 100, 1);
	case_auth_reject("auth-equal-seq-meticulous", MS, "topsecret", 7, 100,
			 0, 100, 0);
	/* The window has an upper edge as well as a lower one (s6.7.4:
	 * RcvAuthSeq to RcvAuthSeq+3*Detect Mult). Detect Mult is 3 here,
	 * so 9 ahead is the last acceptable sequence and 10 is not. Without
	 * the upper bound almost the entire number space is acceptable, and
	 * a wrap leaves the session rejecting forever. */
	case_auth_reject("auth-window-upper-edge", KS, "topsecret", 7, 109,
			 0, 100, 1);
	case_auth_reject("auth-window-past-upper", KS, "topsecret", 7, 110,
			 0, 100, 0);

	/* RFC 5880 names the local state variable bfd.DetectMult and the
	 * header field Detect Mult, and s6.7.4 asks for the latter. With a
	 * local multiplier of 1 the window would stop at 3, so a distance of
	 * 9 only passes if the packet's own Detect Mult of 3 is what sized
	 * it. */
	arm_local_mult = 1;
	case_auth_reject("auth-window-mult-from-packet", KS, "topsecret", 7, 109,
			 0, 100, 1);
	arm_local_mult = 3;

	/* Circular, not linear. A sequence far below the watermark is not
	 * "less than" in a 32-bit circular space, it is very far ahead -
	 * and still outside the window, which is what must refuse it. */
	case_auth_reject("auth-window-wrapped-far", KS, "topsecret", 7,
			 0x10000000, 0, 0xF0000000, 0);
	/* The same wrap, one step past the watermark, is inside it. */
	case_auth_reject("auth-window-wraps-cleanly", KS, "topsecret", 7,
			 0x00000002, 0, 0xFFFFFFFF, 1);
	/* A rollover leaves the peer signing with a key we have stopped
	 * transmitting under, and refusing it is the breakage the accept
	 * period exists to prevent. The session transmits under key 7 and
	 * still accepts key 9. */
	arm_extra_keyid = 9;
	arm_extra_key = "otherkey1";
	case_auth_reject("auth-rollover-old-key", KS, "otherkey1", 9, 100,
			 0, 0, 1);
	/* A key that is not in the set at all is still refused, so the
	 * lookup has not simply become permissive. */
	case_auth_reject("auth-rollover-unknown-key", KS, "otherkey1", 11, 100,
			 0, 0, 0);
	arm_extra_keyid = 0;
	arm_extra_key = "";

#undef KS
#undef MS

	case_sweep_demand();
	/* Detection is 30ms here, so the window survives 40ms of silence
	 * and is forgotten after 80ms. */
	case_sweep_auth_resync("sweep-auth-window-held", 40000000ull, 1, 0);
	case_sweep_auth_resync("sweep-auth-window-aged", 80000000ull, 0, 0);
	/* Under demand hold the sweep leaves `alive` alone, but the window
	 * must still age: a peer we asked to stop transmitting can restart
	 * inside a silence no detection timer ends, and a window that
	 * outlives it rejects every packet the peer will ever send. */
	case_sweep_auth_resync("sweep-auth-window-aged-demand", 80000000ull, 0, 1);
	case_sweep_auth_resync("sweep-auth-window-held-demand", 40000000ull, 1, 1);

	for (int i = 0; i < HMAC_NVECS; i++)
		case_hmac(&hmac_vecs[i]);

	/* One second bound throughout, the shipped default. */
#define DM_BOUND (1000ull * 1000 * 1000)
	/* Armed and the engine is current: answer as always. */
	case_deadman("deadman-fresh", DM_BOUND, mono_ns(), 1);
	/* Armed and the engine went quiet two bounds ago: withhold. */
	case_deadman("deadman-stale", DM_BOUND, mono_ns() - 2 * DM_BOUND, 0);
	/* Just inside the bound is not stale. Half a bound is 500ms of
	 * margin either side of a test that runs in microseconds. */
	case_deadman("deadman-within-bound", DM_BOUND,
		     mono_ns() - DM_BOUND / 2, 1);
	/* Bound zero is the off switch, and a heartbeat old enough to trip
	 * any armed gate must not trip this one. */
	case_deadman("deadman-disarmed", 0, mono_ns() - 60ull * DM_BOUND, 1);
	/* Heartbeat zero is the window between program load and the
	 * engine's first pass. Tripping there holds every session down at
	 * startup, so it reads as healthy. */
	case_deadman("deadman-never-beaten", DM_BOUND, 0, 1);
#undef DM_BOUND

	case_demand_bit_out(0, 0, 0, 0, "demand-bit-off-not-set");
	case_demand_bit_out(1, 0, 1, 0, "demand-bit-on-set");
	case_demand_bit_out(1, BFD_F_POLL, 1, 1, "demand-bit-rides-with-final");
	/* 50ms echo interval, mult 3: budget 150ms */
	case_echo_advisory("echo-advisory-fresh", 50000, 100000000ull, 1, 1);
	case_echo_advisory("echo-advisory-stale", 50000, 200000000ull, 1, 0);
	/* echo never seen: the branch needs echo_last_seen_ns set, so the
	 * verdict is left untouched rather than reported as dead */
	case_echo_advisory("echo-advisory-never-seen", 50000, 0, 0, 0);
	/* echo not configured: same, no verdict to make */
	case_echo_advisory("echo-advisory-off", 0, 100000000ull, 1, 0);
}
