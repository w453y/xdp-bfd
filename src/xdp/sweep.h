// SPDX-License-Identifier: GPL-2.0
/* sweep.h - the detection sweep timer. Include after maps.h. */
#ifndef BFD_XDP_SWEEP_H
#define BFD_XDP_SWEEP_H

struct bpf_map;
static long check_session(struct bpf_map *map, struct session_key *k, struct session_state *st,
			  void *ctx)
{
	__u64 now = *(__u64 *)ctx;

	struct tx_cfg *ec = bpf_map_lookup_elem(&tx_config, k);

	/* Echo liveness is advisory: a userspace TX stall looks like a path fault. */
	if (ec && ec->echo_iv_us && st->echo_last_seen_ns) {
		__u64 eb = (__u64)st->detect_mult * ec->echo_iv_us * 1000ull;
		__s64 ed = (__s64)(now - st->echo_last_seen_ns);

		st->echo_alive = (ed >= 0 && (__u64)ed <= eb);
	}

	/* Recomputed for entries that predate the field. */
	__u64 iv_us = st->detect_iv_us;

	if (!iv_us) {
		__u32 local_rx = LOCAL_MIN_RX_US;

		if (ec && ec->min_rx_us)
			local_rx = ec->min_rx_us;
		iv_us = st->min_tx_us > local_rx ? st->min_tx_us : local_rx;
	}
	__u64 detect_ns = (__u64)st->detect_mult * iv_us * 1000ull;

	__s64 delta = (__s64)(now - st->last_seen_ns);

	if (delta < 0)
		return 0; /* a packet raced past our snapshot */

	/* RFC 5880 s6.7: forget the window after twice the detection time, as
	 * the engine does; the program drops out-of-window packets before
	 * userspace sees them. Also under demand hold.
	 */
	if (st->auth_rx_seen && (__u64)delta > 2ull * detect_ns) {
		st->auth_rx_seen = 0;
		st->auth_rx_seq = 0;
	}

	/* RFC 5880 s6.6: requested silence; stay alive. */
	if (ec && ec->demand_hold)
		return 0;

	if (!st->alive)
		return 0;
	if ((__u64)delta > detect_ns && __sync_val_compare_and_swap(&st->alive, 1, 0) == 1)
		emit(k, st, now, BFD_EV_DOWN);
	return 0;
}

static __always_inline __u64 sweep_interval(void)
{
	__u32 k = BFD_TUNE_SWEEP_NS;
	__u64 *v = bpf_map_lookup_elem(&tunables, &k);

	return (v && *v) ? *v : SWEEP_NS;
}

/* Fails open with no bound or a zero heartbeat. Signed: the engine's store can
 * land after now was taken.
 */
static __always_inline int deadman_tripped(__u64 now)
{
	__u32 k = BFD_TUNE_DEADMAN_NS;
	__u64 *bound = bpf_map_lookup_elem(&tunables, &k);
	__u32 zero = 0;
	__u64 *hb;

	if (!bound || !*bound)
		return 0;
	hb = bpf_map_lookup_elem(&heartbeat, &zero);
	if (!hb || !*hb)
		return 0;
	return (__s64)(now - *hb) > (__s64)*bound;
}

static int sweep_fire(void *map, __u32 *key, struct sweep *sw)
{
	__u64 now = bpf_ktime_get_ns();

	bpf_for_each_map_elem(&bfd_sessions, check_session, &now, 0);
	bpf_timer_start(&sw->timer, sweep_interval(), 0);
	return 0;
}

/* bpf_timer cannot be armed from userspace, so the first packet arms it. The
 * CAS lets one CPU do it; a failure is counted, not retried.
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
