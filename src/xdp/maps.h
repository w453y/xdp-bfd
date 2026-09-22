// SPDX-License-Identifier: GPL-2.0
/* maps.h - BPF map definitions.
 *
 * Must be included before any other src/xdp header whose helpers
 * reference a map by symbol.
 */
#ifndef BFD_XDP_MAPS_H
#define BFD_XDP_MAPS_H

#include "hmac_sha1.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, struct session_key);
	__type(value, struct session_state);
} bfd_sessions SEC(".maps");

/* Slots and their meanings are defined once by BFD_STAT_LIST in
 * include/bfd_shared.h; the size follows from it. */
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, struct session_key);
	__type(value, struct tx_cfg);
} tx_config SEC(".maps");

/* echo_peers: peer address (v4-mapped) -> 1 for each echo-active session's
 * peer. The reflector returns only these echoes. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, struct bfd_addr);
	__type(value, __u8);
} echo_peers SEC(".maps");

/* echo_disc: our my_disc -> session key, to demux our own returning echoes,
 * which carry no Your Disc. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BFD_MAX_SESSIONS);
	__type(key, __u32);
	__type(value, struct session_key);
} echo_disc SEC(".maps");

/* bit 0: promiscuous, track sessions with no tx_config (bfd_loader only). bit
 * 1: a multihop session exists; see parse_l3. */
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

/* Structs that cross to the engine but belong to no map, recorded in BTF for
 * ktx_abi_check. BTF keeps only types reachable from maps and program
 * signatures; declared by value so their sizes are recorded. */
static const struct {
	struct bfd_event ev;
	struct bfd_ctrl_pkt pkt;
} bfd_abi_witness SEC(".rodata") __attribute__((used));

/* Engine heartbeat: CLOCK_MONOTONIC in ns at each loop pass, comparable to
 * bpf_ktime_get_ns. Mmapable so the engine writes it without a syscall. Zero
 * means not written yet and reads as healthy. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, __u64);
} heartbeat SEC(".maps");

struct sweep {
	struct bpf_timer timer;
	__u64 inited;   /* 64-bit for the CAS: see alive in bfd_shared.h */
	/* Negative errno from the arming call that failed; 0 when healthy. */
	__s32 init_err;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sweep);
} sweep_map SEC(".maps");

/* Scratch space for authentication. A per-CPU map rather than the stack: the
 * verifier's 512-byte budget covers the whole call chain and the digest uses
 * most of it. */
struct auth_scratch {
	__u8 blk[SHA1_BLOCK_LEN];
	__u8 dig[SHA1_DIGEST_LEN];
	__u8 rcv[SHA1_DIGEST_LEN];   /* the digest as it arrived, kept
	                              * while blk's copy is zeroed to
	                              * recompute over the same bytes */
	__u8 tmp[SHA1_BLOCK_LEN];    /* hmac_sha1_blocks' working block.
	                              * Its own local once, which made it the
	                              * largest thing on a call chain the
	                              * verifier charges against one 512-byte
	                              * budget. Per-CPU here, so it costs no
	                              * stack and the chain gained the margin
	                              * it was missing. */
	__u8 kpad[SHA1_BLOCK_LEN];   /* the chosen key, copied here so the
	                              * digest is handed a pointer at a
	                              * fixed offset. Reading it straight
	                              * out of the map array instead means
	                              * a variable offset, and the verifier
	                              * then walks the whole compression
	                              * again for every state that pointer
	                              * could be in, which is millions of
	                              * instructions rather than thousands. */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct auth_scratch);
} auth_scratch SEC(".maps");

#endif /* BFD_XDP_MAPS_H */
