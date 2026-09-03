// SPDX-License-Identifier: GPL-2.0
/* sweep.h - detection sweep timer.
 *
 * Include after maps.h. */
#ifndef BFD_XDP_SWEEP_H
#define BFD_XDP_SWEEP_H

/* Sweep: called for each session every sweep_interval(). */
struct bpf_map;
static long check_session(struct bpf_map *map, struct session_key *k,
			  struct session_state *st, void *ctx)
{
	__u64 now = *(__u64 *)ctx;

	/* Echo liveness. Advisory only: reported, never merged into the
	 * session verdict. With userspace echo TX a local stall looks
	 * exactly like a path fault, so this must not tear a session
	 * down. Revisit when TX moves into the TC hook. */
	{
		struct tx_cfg *ec = bpf_map_lookup_elem(&tx_config, k);
		if (ec && ec->echo_iv_us && st->echo_last_seen_ns) {
			__u64 eb = (__u64)st->detect_mult *
				   ec->echo_iv_us * 1000ull;
			__s64 ed = (__s64)(now - st->echo_last_seen_ns);
			st->echo_alive = (ed >= 0 && (__u64)ed <= eb);
		}
		/* Demand mode (RFC 5880 s6.6): the engine asked this peer to
		 * stop transmitting, so the silence the sweep would measure
		 * is the silence we requested. Leave `alive` set - clearing
		 * it would emit a DETECT-DOWN for a healthy session and make
		 * every observer of the ring report the session down. */
		if (ec && ec->demand_hold)
			return 0;
	}

	if (!st->alive)
		return 0;

	/* Effective interval is maintained by the RX path (poll-aware:
	 * advertised decreases apply only once traffic actually paces at
	 * the new rate). Fallback recompute for entries that predate the
	 * field. */
	__u64 iv_us = st->detect_iv_us;
	if (!iv_us) {
		__u32 local_rx = LOCAL_MIN_RX_US;
		struct tx_cfg *cfg = bpf_map_lookup_elem(&tx_config, k);
		if (cfg && cfg->min_rx_us)
			local_rx = cfg->min_rx_us;
		iv_us = st->min_tx_us > local_rx ?
			st->min_tx_us : local_rx;
	}
	__u64 detect_ns = (__u64)st->detect_mult * iv_us * 1000ull;

	__s64 delta = (__s64)(now - st->last_seen_ns);
	if (delta < 0)
		return 0;   /* packet raced past our now-snapshot */
	if ((__u64)delta > detect_ns &&
	    __sync_val_compare_and_swap(&st->alive, 1, 0) == 1)
		emit(k, st, now, 0);
	return 0;
}

/* The sweep interval: whatever userspace set before attach, else the
 * compiled default. Read at each arm rather than cached, so a value
 * written later would take effect on the next tick. */
static __always_inline __u64 sweep_interval(void)
{
	__u32 k = BFD_TUNE_SWEEP_NS;
	__u64 *v = bpf_map_lookup_elem(&tunables, &k);

	return (v && *v) ? *v : SWEEP_NS;
}

static int sweep_fire(void *map, __u32 *key, struct sweep *sw)
{
	__u64 now = bpf_ktime_get_ns();

	bpf_for_each_map_elem(&bfd_sessions, check_session, &now, 0);
	bpf_timer_start(&sw->timer, sweep_interval(), 0);
	return 0;
}

/* bpf_timer can only be armed from program context, not from userspace
 * at load time, so the first packet through arms the sweep and the CAS
 * makes exactly one CPU do it.
 *
 * Setting `inited` before the init is deliberate: initialising first
 * would let two CPUs call bpf_timer_init and bpf_timer_start on the same
 * timer. A losing CPU returning early is harmless, since nothing reads
 * the timer.
 *
 * These calls can fail - on a kernel without bpf_timer support they
 * always will - and `inited` is already 1 by then, so the sweep would
 * silently never arm. Record the error and count it.
 *
 * Not retried: on an unsupported kernel that runs a failing helper on
 * every packet forever.
 */
static __always_inline void ensure_sweeper(void)
{
	__u32 zero = 0;
	struct sweep *sw = bpf_map_lookup_elem(&sweep_map, &zero);
	long err;

	if (!sw)
		return;
	if (__sync_val_compare_and_swap(&sw->inited, 0, 1) != 0)
		return;

	err = bpf_timer_init(&sw->timer, &sweep_map, 0);
	if (!err)
		err = bpf_timer_set_callback(&sw->timer, sweep_fire);
	if (!err)
		err = bpf_timer_start(&sw->timer, sweep_interval(), 0);
	if (err) {
		sw->init_err = (__s32)err;
		count(BFD_STAT_SWEEP_INIT_FAIL);
	}
}

#endif /* BFD_XDP_SWEEP_H */
