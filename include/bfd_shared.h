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
#define BFD_SRC_PORT     49152  /* RFC 5881 s4 range base. Per-session
                                 * TX source port = base + session slot
                                 * (SHOULD be unique per session). */
#define BFD_MIN_LEN      24
#define BFD_VERSION      1
#define BFD_MAX_SESSIONS 64

/* Control packet flag bits (RFC 5880 s4.1) */
#define BFD_F_POLL  0x20
#define BFD_F_FINAL 0x10

struct session_key {
	__be32 peer_ip;
	__be32 local_ip;
};

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
