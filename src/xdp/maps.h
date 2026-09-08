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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BFD_TUNE_MAX);
	__type(key, __u32);
	__type(value, __u64);
} tunables SEC(".maps");

struct sweep {
	struct bpf_timer timer;
	__u32 inited;
	/* Negative errno from whichever arming call failed, so the value
	 * says WHICH one rather than only that something did. Zero on a
	 * healthy sweeper. */
	__s32 init_err;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sweep);
} sweep_map SEC(".maps");

/* Working space for authentication.
 *
 * Not on the stack: the verifier charges an entire call chain against
 * one 512-byte budget, and the digest already spends most of it below
 * this point. A block and a digest per CPU costs nothing and takes 84
 * bytes out of the packet path's frame.
 *
 * Per-CPU because XDP runs concurrently on every queue. One entry is
 * enough - a packet finishes with it before the next one starts, and
 * verification is done before a reply is built.
 */
struct auth_scratch {
	__u8 blk[SHA1_BLOCK_LEN];
	__u8 dig[SHA1_DIGEST_LEN];
	__u8 rcv[SHA1_DIGEST_LEN];   /* the digest as it arrived, kept
	                              * while blk's copy is zeroed to
	                              * recompute over the same bytes */
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
