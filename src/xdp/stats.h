// SPDX-License-Identifier: GPL-2.0
/* stats.h - counters and the event ringbuf. Include after maps.h. */
#ifndef BFD_XDP_STATS_H
#define BFD_XDP_STATS_H

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&bfd_stats, &idx);

	if (v)
		/* Per-CPU slot, preemption off. */
		*v += 1;
}

static __always_inline void emit(struct session_key *k, struct session_state *st, __u64 now,
				 __u8 ev)
{
	struct bfd_event *e = bpf_ringbuf_reserve(&bfd_events, sizeof(*e), 0);

	if (!e)
		return;
	e->ts_ns = now;
	e->last_seen_ns = st->last_seen_ns;
	e->key = *k;
	e->remote_disc = st->remote_disc;
	e->event = ev;
	bpf_ringbuf_submit(e, 0);
}

/* Only the key: the engine reads the rest from bfd_sessions. */
static __always_inline void emit_change(struct session_key *k, __u64 now)
{
	struct bfd_event *e = bpf_ringbuf_reserve(&bfd_changes, sizeof(*e), 0);

	if (!e) {
		count(BFD_STAT_CHANGES_LOST);
		return;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = now;
	e->key = *k;
	e->event = BFD_EV_CHANGED;
	bpf_ringbuf_submit(e, 0);
}

#endif /* BFD_XDP_STATS_H */
