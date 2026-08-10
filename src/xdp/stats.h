// SPDX-License-Identifier: GPL-2.0
/* stats.h - counters and the event ringbuf.
 *
 * Split out of bfd_xdp.c; included after maps.h.
 */
#ifndef BFD_XDP_STATS_H
#define BFD_XDP_STATS_H

static __always_inline void count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&bfd_stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline void emit(struct session_key *k,
				 struct session_state *st,
				 __u64 now, __u8 ev)
{
	struct bfd_event *e = bpf_ringbuf_reserve(&bfd_events, sizeof(*e), 0);
	if (!e)
		return;
	e->ts_ns        = now;
	e->last_seen_ns = st->last_seen_ns;
	e->key          = *k;
	e->remote_disc  = st->remote_disc;
	e->event        = ev;
	bpf_ringbuf_submit(e, 0);
}

#endif /* BFD_XDP_STATS_H */
