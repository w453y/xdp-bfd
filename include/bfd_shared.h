// SPDX-License-Identifier: GPL-2.0
/*
 * bfd_shared.h - kernel/userspace shared wire ABI.
 *
 * Included by src/xdp/ (BPF), src/engine/ and src/loader/. The struct
 * layouts here ARE the BPF map value formats: any change must be made
 * here and nowhere else, or the userspace mirrors silently misread the
 * maps.
 */
#ifndef BFD_SHARED_H
#define BFD_SHARED_H

#include <linux/types.h>

#define BFD_PORT_1HOP    3784
#define BFD_PORT_MHOP    4784   /* RFC 5883 multihop */
#define BFD_ECHO_PORT    3785
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
#define BFD_F_CPI    0x08   /* Control Plane Independent */
#define BFD_F_AUTH   0x04   /* Authentication Present */
#define BFD_F_DEMAND 0x02   /* Demand mode */
#define BFD_F_MP     0x01   /* Multipoint */

/* Session state (RFC 5880 s6.8.1). The ordering IS the wire encoding:
 * the XDP parser stores BFD_STATE(bfd) straight into
 * session_state.remote_state and userspace compares that against these
 * names, so the two agree only as long as this order is the wire order. */
enum bfd_state { ST_ADMINDOWN, ST_DOWN, ST_INIT, ST_UP };

static inline const char *bfd_state_str(int st)
{
        switch (st) {
        case ST_ADMINDOWN: return "AdminDown";
        case ST_DOWN:      return "Down";
        case ST_INIT:      return "Init";
        case ST_UP:        return "Up";
        default:           return "?";
        }
}

/* Control packet, the 24-byte mandatory section (RFC 5880 s4.1).
 * One definition for both halves: the XDP parser and the userspace
 * FSM read and write these same bytes, and two descriptions of one
 * wire format is how they drift. */
struct bfd_ctrl_pkt {
	__u8   vers_diag;
	__u8   flags;
	__u8   detect_mult;
	__u8   len;
	__be32 my_disc;
	__be32 your_disc;
	__be32 min_tx;
	__be32 min_rx;
	__be32 min_echo_rx;
} __attribute__((packed));

#define BFD_VERS(h)   (((h)->vers_diag >> 5) & 0x7)
#define BFD_DIAG(h)   ((h)->vers_diag & 0x1f)
#define BFD_STATE(h)  (((h)->flags >> 6) & 0x3)

/* Why a control packet was not accepted (RFC 5880 s6.8.6). */
enum bfd_ctrl_verdict {
	BFD_CTRL_ACCEPT = 0,
	BFD_CTRL_MALFORMED,     /* header does not parse */
	BFD_CTRL_UNSUPPORTED,   /* well formed, carries a flag we cannot honour */
};

/* The acceptance rule, shared so the kernel fast path and the userspace
 * establishment path cannot drift. They had already drifted: userspace
 * never looked at bfd->len, so a packet claiming 200 bytes inside a
 * 24-byte datagram was accepted there and rejected in XDP.
 *
 * Every argument is in HOST order and passed explicitly, because the two
 * planes byte-swap with different helpers (bpf_ntohs vs ntohs) and this
 * header is compiled by both. payload_len is how many bytes actually
 * follow the UDP header - udp->len - 8 in the kernel, the recvmsg return
 * in userspace - which is what makes the overread guard expressible
 * once instead of twice.
 *
 * Caller counts and decides the disposition; this only classifies.
 */
static inline int bfd_ctrl_check(__u8 vers_diag, __u8 flags, __u8 mult,
				 __u8 len, __u32 my_disc, __u32 payload_len)
{
	if (((vers_diag >> 5) & 0x7) != BFD_VERSION)
		return BFD_CTRL_MALFORMED;
	if (len < BFD_MIN_LEN || len > payload_len)
		return BFD_CTRL_MALFORMED;
	if (mult == 0 || my_disc == 0)
		return BFD_CTRL_MALFORMED;
	if (flags & (BFD_F_AUTH | BFD_F_MP))
		return BFD_CTRL_UNSUPPORTED;

	return BFD_CTRL_ACCEPT;
}

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
	__u8  remote_flags;  /* peer's last control packet flags,
	                      * masked to the six non-state bits */
	__u32 alive;          /* our sweep's verdict: 1 = hearing peer.
	                       * 32-bit: BPF atomics need 32/64-bit; RX
	                       * set and sweep clear race across CPUs. */
	__u32 final_seq;      /* kernel ack of a Poll sequence: set to
	                       * cfg->poll_seq on the peer's F */
	__u8  peer_mac[6];    /* neighbour's source MAC, learned on every RX.
	                       * Echo TX needs an L2 destination and must not
	                       * depend on the neighbour table. */
	__u8  mac_valid;
	__u8  pad2;
	__u64 echo_rx_pkts;   /* our own echoes seen returning */
	__u64 echo_last_seen_ns;
	__u32 echo_last_nonce;
	__u32 pad3;
	__u32 echo_alive;     /* advisory echo verdict, kernel-owned */
	__u32 pad4;
	__u32 remote_min_echo_us; /* peer's advertised Required Min Echo RX.
	                           * Reported up to bfdd so it can run the
	                           * RFC 5880 s6.8.9 echo negotiation. */
	__u32 pad5;
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
	__u32 echo_iv_us;    /* echo interval; 0 = echo off. Static per
	                      * session, so the mirror dirty-check still
	                      * elides pushes. */
	__u32 min_echo_rx_us; /* what we advertise as Required Min Echo RX.
	                       * 0 means we cannot receive echo (RFC 5880
	                       * s4.1); set only when the session has echo
	                       * enabled, so it tracks whether the reflector
	                       * will actually answer. */
	__u32 min_ttl;       /* lowest acceptable TTL / hop_limit for this
	                      * session. bfdd sends 255 for single-hop and
	                      * the configured minimum-ttl for multihop, so
	                      * one comparison covers both. 0 means unset
	                      * and is treated as 255. */
};

#endif /* BFD_SHARED_H */
