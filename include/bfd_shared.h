// SPDX-License-Identifier: GPL-2.0
/*
 * bfd_shared.h - kernel/userspace shared wire ABI.
 *
 * Included by bfd_xdp.c (BPF), bfd_tx.c and loader.c. The struct
 * layouts here ARE the BPF map value formats: any change must be made
 * here and nowhere else, or the userspace mirrors silently misread the
 * maps.
 */
#ifndef BFD_SHARED_H
#define BFD_SHARED_H

#include <linux/types.h>

#define BFD_PORT_1HOP    3784
#define BFD_SRC_PORT     65472  /* Per-session TX source port = base +
                                 * slot; 64 slots end at 65535, the top
                                 * of the RFC 5881 s4 range. Top-down
                                 * because stock bfdd allocates its own
                                 * per-session sockets bottom-up from
                                 * 49152 even in dplane mode and those
                                 * binds collide with ours. */
#define BFD_MIN_LEN      24
#define BFD_VERSION      1
#define BFD_MAX_SESSIONS 64

/* Control packet flag bits (RFC 5880 s4.1) */
#define BFD_F_POLL  0x20
#define BFD_F_FINAL 0x10

struct bfd_addr {
	__u8 b[16];
};

struct session_key {
	struct bfd_addr peer;
	struct bfd_addr local;
};

/* v4-mapped encoder: ::ffff:a.b.c.d. Shared by BPF and userspace so
 * both sides produce byte-identical map keys. */
static inline void key_set_v4(struct bfd_addr *a, __be32 v4)
{
	__builtin_memset(a, 0, sizeof(*a));
	a->b[10] = 0xff;
	a->b[11] = 0xff;
	__builtin_memcpy(&a->b[12], &v4, 4);
}

/* Native v6: copy the 16-byte address verbatim. */
static inline void key_set_v6(struct bfd_addr *a, const void *v6)
{
	__builtin_memcpy(a->b, v6, 16);
}

struct session_state {
	__u64 last_seen_ns;
	__u64 rx_pkts;
	__u64 tx_pkts;        /* kernel XDP_TX replies */
	__u32 remote_disc;
	__u32 local_disc;
	__u32 min_tx_us;
	__u32 min_rx_us;
	__u32 detect_iv_us;   /* effective detect basis: lags advertised
	                       * decreases until peer paces at new rate */
	__u8  remote_state;
	__u8  remote_diag;
	__u8  detect_mult;
	__u8  pad;
	__u32 alive;          /* our sweep's verdict: 1 = hearing peer.
	                       * 32-bit: BPF atomics need 32/64-bit; RX
	                       * set and sweep clear race across CPUs. */
	__u32 final_seq;      /* kernel ack of a Poll sequence: set to
	                       * cfg->poll_seq on the peer's F */
};

/* Event pushed to userspace on liveness transitions. */
struct bfd_event {
	__u64 ts_ns;          /* when we noticed             */
	__u64 last_seen_ns;   /* last packet before verdict  */
	struct session_key key;
	__u32 remote_disc;
	__u8  event;          /* 0 = DETECT-DOWN, 1 = ALIVE  */
};

/* What to say when we speak: written by userspace FSM. */
struct tx_cfg {
	__u32 enable;        /* 1 = kernel replies to each RX (Up only) */
	__u32 my_disc;
	__u32 your_disc;
	__u32 min_tx_us;
	__u32 min_rx_us;
	__u16 src_port;      /* kernel echo TX source port; 0 = BFD_SRC_PORT */
	__u8  state;
	__u8  diag;
	__u8  mult;
	__u8  poll;          /* userspace-initiated Poll sequence active:
	                      * echo sets P until final_seq == poll_seq */
	__u8  pad[3];
	__u32 poll_seq;      /* increments per Poll sequence; kernel acks
	                      * the peer's F via session_state.final_seq
	                      * (tx_cfg stays userspace-owned) */
};

#endif /* BFD_SHARED_H */
