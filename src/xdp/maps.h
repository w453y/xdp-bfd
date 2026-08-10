// SPDX-License-Identifier: GPL-2.0
/* maps.h - BPF map definitions.
 *
 * Must be included before any other src/xdp header whose helpers
 * reference a map by symbol.
 */
#ifndef BFD_XDP_MAPS_H
#define BFD_XDP_MAPS_H

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, struct session_key);
	__type(value, struct session_state);
} bfd_sessions SEC(".maps");

/* stats: 0=pkts 1=bfd 2=malformed 3=rejects 4=echo-reflected
 *        5=echo-returns 6=echo-declined 7=echo-not-self 8=echo-ttl
 * 7 is not an error counter: FRR sources its own v6 echoes at the
 * peer rather than self-addressed, so it climbs in normal use. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 9);
	__type(key, __u32);
	__type(value, __u64);
} bfd_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} bfd_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, struct session_key);
	__type(value, struct tx_cfg);
} tx_config SEC(".maps");

/* echo_peers: peer address (v4 stored v4-mapped) -> 1 for every session
 * active. Populated by the userspace shim on SESSION_ECHO accept, cleared
 * on delete / echo-off. The reflector consults it so only echoes from a
 * peer of an echo-active session are returned (not arbitrary 3785 traffic). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, struct bfd_addr);
	__type(value, __u8);
} echo_peers SEC(".maps");

/* echo_disc: our my_disc -> session key, for demuxing our own echoes
 * on return. The returning frame is self-addressed to our local
 * address and never carries Your Disc, so the discriminator we wrote
 * into the payload is the only thing that names the session. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, __u32);
	__type(value, struct session_key);
} echo_disc SEC(".maps");

/* bit 0: promiscuous observe - track sessions with no tx_config entry.
 * Set by the standalone loader; bfd_tx leaves it 0 so only configured
 * sessions can create map state. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} prog_flags SEC(".maps");

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

#endif /* BFD_XDP_MAPS_H */
