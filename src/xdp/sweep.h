// SPDX-License-Identifier: GPL-2.0
/* sweep.h - detection sweep timer.
 *
 * Split out of bfd_xdp.c; included after maps.h.
 */
#ifndef BFD_XDP_SWEEP_H
#define BFD_XDP_SWEEP_H

/* Sweep: called for each session every SWEEP_NS. */
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

static int sweep_fire(void *map, __u32 *key, struct sweep *sw)
{
	__u64 now = bpf_ktime_get_ns();

	bpf_for_each_map_elem(&bfd_sessions, check_session, &now, 0);
	bpf_timer_start(&sw->timer, SWEEP_NS, 0);
	return 0;
}

/* bpf_timer can only be initialized and armed from BPF program context,
 * not from userspace at load time, so the first packet through the
 * program arms the sweep. The CAS makes exactly one CPU do it.
 *
 * Setting `inited` BEFORE the init looks like a race and is not one, so
 * do not 'fix' it by initialising first: that would have two CPUs both
 * calling bpf_timer_init and bpf_timer_start on the same timer. A
 * losing CPU returning early is harmless, since nothing anywhere reads
 * the timer.
 *
 * What DOES matter is that these calls can fail - on a kernel without
 * bpf_timer support they always will - and `inited` is already 1 by
 * then. Without a witness the sweep would silently never arm, kernel
 * side detection would be off, and nothing would say so. So record the
 * error and count it. Slot 10 must stay flat on a healthy system.
 *
 * Deliberately not retried: on an unsupported kernel a retry would run
 * a failing helper on every packet forever.
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
		err = bpf_timer_start(&sw->timer, SWEEP_NS, 0);
	if (err) {
		sw->init_err = (__s32)err;
		count(10);
	}
}

#endif /* BFD_XDP_SWEEP_H */
