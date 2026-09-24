// SPDX-License-Identifier: GPL-2.0
/* maps.h - map definitions; include before any header that references a map. */
#ifndef BFD_XDP_MAPS_H
#define BFD_XDP_MAPS_H

#include "hmac_sha1.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, struct session_key);
	__type(value, struct session_state);
} bfd_sessions SEC(".maps");

/* Slots are BFD_STAT_LIST in bfd_shared.h. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, BFD_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} bfd_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} bfd_events SEC(".maps");

/* Apart from bfd_events, so a forger changing fields cannot crowd out a
 * detection.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16);
} bfd_changes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, struct session_key);
	__type(value, struct tx_cfg);
} tx_config SEC(".maps");

/* The copy of tx_config one packet works from. Bytes, since a per-CPU value
 * cannot hold a spin lock.
 */
struct tx_snap {
	__u8 b[sizeof(struct tx_cfg)];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tx_snap);
} tx_snap SEC(".maps");

/* All zero, never written: a new bfd_sessions entry is copied from it, not
 * from a session_state on the stack.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct session_state);
} state_zero SEC(".maps");

/* Peers of echo-active sessions; the reflector returns only their echoes. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, struct bfd_addr);
	__type(value, struct echo_peer);
} echo_peers SEC(".maps");

/* Our my_discs, so a peer whose address moved still reaches userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, __u32);
	__type(value, __u8);
} our_discs SEC(".maps");

struct moved_budget {
	__u64 win_ns;
	__u64 n;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct moved_budget);
} moved_budget SEC(".maps");

/* Our my_disc to session key, for our returning echoes, which carry no Your Disc. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, __u32);
	__type(value, struct session_key);
} echo_disc SEC(".maps");

/* bit 0: promiscuous (bfd_loader). bit 1: a multihop session exists. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} prog_flags SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BFD_TUNE_MAX);
	__type(key, __u32);
	__type(value, __u64);
} tunables SEC(".maps");

/* Shared structs no map carries, declared by value so BTF records their sizes
 * for ktx_abi_check.
 */
static const struct {
	struct bfd_event ev;
	struct bfd_ctrl_pkt pkt;
} bfd_abi_witness SEC(".rodata") __attribute__((used));

/* CLOCK_MONOTONIC ns at each engine pass, mmapable. Zero reads as healthy. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u64);
} heartbeat SEC(".maps");

struct sweep {
	struct bpf_timer timer;
	__u64 inited; /* 64-bit for the CAS; see alive */
	/* negative errno from a failed arm */
	__s32 init_err;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sweep);
} sweep_map SEC(".maps");

/* The auth TX sequence per session slot, mmapped by the engine so both planes
 * draw from one counter and never reuse a number. 64-bit for the atomic add.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u64);
} auth_seq SEC(".maps");

/* Per-CPU, since the 512-byte stack budget covers the whole call chain and the
 * digest uses most of it.
 */
struct auth_scratch {
	__u8 blk[SHA1_BLOCK_LEN];
	__u8 dig[SHA1_DIGEST_LEN];
	/* the digest as it arrived; blk's copy is zeroed */
	__u8 rcv[SHA1_DIGEST_LEN];
	__u8 tmp[SHA1_BLOCK_LEN]; /* hmac_sha1_blocks' working block */
	/* fixed offset; a variable one makes the verifier re-walk the digest */
	__u8 kpad[SHA1_BLOCK_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct auth_scratch);
} auth_scratch SEC(".maps");

#endif /* BFD_XDP_MAPS_H */
