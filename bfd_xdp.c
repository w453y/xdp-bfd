// SPDX-License-Identifier: GPL-2.0
/* bfd_xdp.c v2 - observer + kernel-side detection sweep. */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define BFD_PORT_1HOP   3784
#define BFD_MIN_LEN     24
#define BFD_VERSION     1

#define LOCAL_MIN_RX_US 10000        /* our configured required-min-rx */
#define SWEEP_NS        (5 * 1000 * 1000ull)   /* 5ms sweep */

struct bfdhdr {
	__u8  vers_diag;
	__u8  flags;
	__u8  detect_mult;
	__u8  len;
	__be32 my_disc;
	__be32 your_disc;
	__be32 min_tx;
	__be32 min_rx;
	__be32 min_echo_rx;
} __attribute__((packed));

#define BFD_VERS(h)   (((h)->vers_diag >> 5) & 0x7)
#define BFD_DIAG(h)   ((h)->vers_diag & 0x1f)
#define BFD_STATE(h)  (((h)->flags >> 6) & 0x3)

struct session_key {
	__be32 peer_ip;
	__be32 local_ip;
};

struct session_state {
	__u64 last_seen_ns;
	__u64 rx_pkts;
	__u32 remote_disc;
	__u32 local_disc;
	__u32 min_tx_us;
	__u32 min_rx_us;
	__u8  remote_state;
	__u8  remote_diag;
	__u8  detect_mult;
	__u8  alive;          /* our sweep's verdict: 1 = hearing peer */
};

/* Event pushed to userspace on liveness transitions. */
struct bfd_event {
	__u64 ts_ns;          /* when we noticed             */
	__u64 last_seen_ns;   /* last packet before verdict  */
	struct session_key key;
	__u32 remote_disc;
	__u8  event;          /* 0 = DETECT-DOWN, 1 = ALIVE  */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct session_key);
	__type(value, struct session_state);
} bfd_sessions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} bfd_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} bfd_events SEC(".maps");

struct sweep {
	struct bpf_timer timer;
	__u32 inited;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sweep);
} sweep_map SEC(".maps");

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

/* Sweep: called for each session every SWEEP_NS. */
static long check_session(struct bpf_map *map, struct session_key *k,
			  struct session_state *st, void *ctx)
{
	__u64 now = *(__u64 *)ctx;

	if (!st->alive)
		return 0;

	__u64 iv_us = st->min_tx_us > LOCAL_MIN_RX_US ?
		      st->min_tx_us : LOCAL_MIN_RX_US;
	__u64 detect_ns = (__u64)st->detect_mult * iv_us * 1000ull;

	__s64 delta = (__s64)(now - st->last_seen_ns);
	if (delta < 0)
		return 0;   /* packet raced past our now-snapshot */
	if ((__u64)delta > detect_ns) {
		st->alive = 0;
		emit(k, st, now, 0);
	}
	return 0;
}

static int sweep_fire(void *map, __u32 *key, struct sweep *sw)
{
	__u64 now = bpf_ktime_get_ns();

	bpf_for_each_map_elem(&bfd_sessions, check_session, &now, 0);
	bpf_timer_start(&sw->timer, SWEEP_NS, 0);
	return 0;
}

static __always_inline void ensure_sweeper(void)
{
	__u32 zero = 0;
	struct sweep *sw = bpf_map_lookup_elem(&sweep_map, &zero);

	if (!sw)
		return;
	if (__sync_val_compare_and_swap(&sw->inited, 0, 1) != 0)
		return;
	bpf_timer_init(&sw->timer, &sweep_map, 0);
	bpf_timer_set_callback(&sw->timer, sweep_fire);
	bpf_timer_start(&sw->timer, SWEEP_NS, 0);
}

SEC("xdp")
int bfd_observer(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	count(0);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	if (iph->protocol != IPPROTO_UDP || iph->ihl != 5)
		return XDP_PASS;

	struct udphdr *udp = (void *)(iph + 1);
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (udp->dest != bpf_htons(BFD_PORT_1HOP))
		return XDP_PASS;

	struct bfdhdr *bfd = (void *)(udp + 1);
	if ((void *)(bfd + 1) > data_end) {
		count(2);
		return XDP_PASS;
	}
	if (BFD_VERS(bfd) != BFD_VERSION || bfd->len < BFD_MIN_LEN ||
	    bfd->detect_mult == 0 || bfd->my_disc == 0) {
		count(2);
		return XDP_PASS;
	}
	if (bfd->len > bpf_ntohs(udp->len) - sizeof(*udp)) {
		count(2);
		return XDP_PASS;
	}

	count(1);
	ensure_sweeper();

	struct session_key key = {
		.peer_ip  = iph->saddr,
		.local_ip = iph->daddr,
	};

	struct session_state *st = bpf_map_lookup_elem(&bfd_sessions, &key);
	if (!st) {
		struct session_state init = {};
		bpf_map_update_elem(&bfd_sessions, &key, &init, BPF_NOEXIST);
		st = bpf_map_lookup_elem(&bfd_sessions, &key);
		if (!st)
			return XDP_PASS;
	}

	__u64 now = bpf_ktime_get_ns();

	st->last_seen_ns = now;
	st->rx_pkts++;
	st->remote_disc  = bpf_ntohl(bfd->my_disc);
	st->local_disc   = bpf_ntohl(bfd->your_disc);
	st->min_tx_us    = bpf_ntohl(bfd->min_tx);
	st->min_rx_us    = bpf_ntohl(bfd->min_rx);
	st->remote_state = BFD_STATE(bfd);
	st->remote_diag  = BFD_DIAG(bfd);
	st->detect_mult  = bfd->detect_mult;

	if (!st->alive) {
		st->alive = 1;
		emit(&key, st, now, 1);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
