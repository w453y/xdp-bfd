// SPDX-License-Identifier: GPL-2.0
/* bfd_shared.h - ABI shared by the BPF program, engine and loader. These
 * structs are the BPF map formats; change them only here. */
#ifndef BFD_SHARED_H
#define BFD_SHARED_H

#include <linux/types.h>

#define BFD_PORT_1HOP    3784
#define BFD_PORT_MHOP    4784   /* RFC 5883 multihop */
#define BFD_ECHO_PORT    3785
#define BFD_SRC_PORT     65472  /* TX source port = base + slot; 64 slots
                                 * end at 65535, the top of the RFC 5881
                                 * s4 range, away from bfdd's own sockets
                                 * allocated upward from 49152 */
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

/* Session state (RFC 5880 s6.8.1), in wire order: the parser stores the wire
 * value directly. */
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

/* Control packet, the 24-byte mandatory section (RFC 5880 s4.1), shared by
 * both planes. */
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

/* Stat slots, defined once: the enum, loader names and test harnesses all
 * expand this list.
 *
 * MALFORMED, REJECTED, UNSUPPORTED_FLAGS and SWEEP_INIT_FAIL should stay flat
 * on a healthy system. NOT_SELF does not: FRR sources its v6 echoes at the
 * peer. ECHO_TTL always reads zero, since parse.h rejects everything that
 * would reach it; it stays to keep the numbering. */
#define BFD_STAT_LIST(X)                                              \
	X(SEEN,              "seen")               /* every packet seen */ \
	X(WELL_FORMED,       "well-formed")        /* parses as BFD */     \
	X(MALFORMED,         "malformed")          /* header does not */   \
	X(REJECTED,          "rejected")           /* GTSM, demux, frag */ \
	X(REFLECTED,         "reflected")          /* echo bounced */      \
	X(ECHO_RETURNS,      "echo-returns")       /* our echo came back */\
	X(DECLINED,          "declined")           /* echo, peer unknown */\
	X(NOT_SELF,          "not-self")           /* echo, not self-addr */\
	X(ECHO_TTL,          "echo-ttl")           /* unreachable, see above */ \
	X(UNSUPPORTED_FLAGS, "unsupported-flags")  /* M bit */             \
	X(SWEEP_INIT_FAIL,   "sweep-init-fail")    /* sweeper never armed */ \
	X(IP_OPTIONS,        "ip-options")         /* BFD port, IP options */ \
	X(AUTH_MISMATCH,     "auth-mismatch")      /* A bit vs session */   \
	X(AUTH_BAD,          "auth-bad")           /* key, digest or seq */ \
	X(DEADMAN_HOLD,      "deadman-hold")       /* reply withheld, engine stalled */ \
	X(UNKNOWN_SESSION,   "unknown-session")    /* no session for the pair */ \
	X(V6_EXTHDR,         "v6-exthdr")          /* BFD behind a v6 ext hdr */ \
	X(AUTH_RATELIMITED,  "auth-ratelimited")   /* A-bit drop before digest */

/* Load-time tunables, written by userspace between load and attach. A map of
 * their own: .rodata would have to be rewritten whole, and sweep_map holds a
 * bpf_timer. */
enum bfd_tunable {
	BFD_TUNE_SWEEP_NS,   /* 0 means use the compiled default */
	BFD_TUNE_DEADMAN_NS, /* max heartbeat age before the fast path stops
	                      * answering; 0 disables the gate */
	BFD_TUNE_MAX
};

/* Compiled sweep interval, shared so the engine can report overrides. */
#define BFD_SWEEP_NS_DEFAULT (5ull * 1000 * 1000)

/* Dead-man bound: how stale the heartbeat may get before the fast path stops
 * answering. 1s is some thirty times the worst loop gap seen on a 64-session
 * mesh, yet catches a wedged engine within a second. */
#define BFD_DEADMAN_NS_DEFAULT (1000ull * 1000 * 1000)

/* How long a demanding session may go without verifying its path. A floor: the
 * effective interval is at least the session's detect budget. */
#define BFD_DEMAND_POLL_US_DEFAULT 1000000ull

enum bfd_stat {
#define BFD_STAT_ENUM(n, s) BFD_STAT_##n,
	BFD_STAT_LIST(BFD_STAT_ENUM)
#undef BFD_STAT_ENUM
	BFD_STAT_MAX
};

/* Authentication types (RFC 5880 s6.7) that FRR can produce. bfdd maps no
 * keychain algorithm to keyed MD5 (2, 3). */
#define BFD_AUTH_NONE            0
#define BFD_AUTH_SIMPLE          1
#define BFD_AUTH_KEYED_SHA1      4
#define BFD_AUTH_METICULOUS_SHA1 5

/* type, length, key id, then the key itself. */
#define BFD_AUTH_SIMPLE_HDR   3
#define BFD_AUTH_SIMPLE_MAXKEY 16

/* type, length, key id, reserved, 4-byte sequence, 20-byte digest. */
#define BFD_AUTH_SHA1_LEN     28

/* Digest failures a session tolerates per detect interval before it
 * rate-limits A-bit packets before the digest. Generous: a key rollover
 * costs at most a handful. */
#define BFD_AUTH_FAIL_MAX     8
#define BFD_AUTH_SHA1_SEQ_OFF 4
#define BFD_AUTH_SHA1_DIG_OFF 8

/* Longest control packet either plane handles: the mandatory section plus a
 * keyed-SHA1 section, 52 bytes and one digest block. */
#define BFD_MAX_LEN (BFD_MIN_LEN + BFD_AUTH_SHA1_LEN)

/* Why a control packet was not accepted (RFC 5880 s6.8.6). */
enum bfd_ctrl_verdict {
	BFD_CTRL_ACCEPT = 0,
	BFD_CTRL_MALFORMED,     /* header does not parse */
	BFD_CTRL_UNSUPPORTED,   /* well formed, carries a flag we cannot honour */
	BFD_CTRL_AUTH_MISMATCH, /* the A bit and the session disagree */
};

/* The acceptance rule, shared by both planes. Arguments are in host order.
 * payload_len is the bytes after the UDP header: udp->len - 8 in the kernel,
 * the recvmsg length in userspace. Classifies only; the caller decides. */
static inline int bfd_ctrl_check(__u8 vers_diag, __u8 flags, __u8 mult,
				 __u8 len, __u32 my_disc, __u32 payload_len,
				 __u8 auth_expected)
{
	if (((vers_diag >> 5) & 0x7) != BFD_VERSION)
		return BFD_CTRL_MALFORMED;
	if (len < BFD_MIN_LEN || len > payload_len)
		return BFD_CTRL_MALFORMED;
	if (mult == 0 || my_disc == 0)
		return BFD_CTRL_MALFORMED;
	if (flags & BFD_F_MP)
		return BFD_CTRL_UNSUPPORTED;

	/* RFC 5880 s6.8.6: discard on an A-bit mismatch either way, so a peer
	 * cannot strip authentication. */
	if (!!(flags & BFD_F_AUTH) != !!auth_expected)
		return BFD_CTRL_AUTH_MISMATCH;

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
	__u64 alive;          /* sweep verdict, 1 = hearing peer. 64-bit: clang
	                       * < 20 has no 32-bit BPF cmpxchg. Atomic since
	                       * RX and the sweep race */
	__u32 final_seq;      /* kernel ack of a Poll sequence: set to
	                       * cfg->poll_seq on the peer's F */
	__u8  peer_mac[6];    /* neighbour's source MAC, learned on RX, for
	                       * echo TX */
	__u8  mac_valid;
	__u8  pad2;
	__u64 echo_rx_pkts;   /* our own echoes seen returning */
	__u64 echo_last_seen_ns;
	__u32 echo_last_nonce;
	__u32 pad3;
	__u32 echo_alive;     /* advisory echo verdict, kernel-owned */
	__u32 pad4;
	__u32 remote_min_echo_us; /* peer's Required Min Echo RX, for bfdd's
	                           * echo negotiation (s6.8.9) */
	__u32 auth_tx_seq;    /* RFC 5880 s6.7.3. Kernel-owned while the fast
	                       * path answers; userspace seeds it and reads it
	                       * back */
	__u32 auth_rx_seq;    /* highest sequence accepted from the peer */
	__u32 auth_rx_seen;   /* whether auth_rx_seq means anything yet */
	__u32 auth_fail_n;    /* digest failures this interval; kernel-owned */
	__u32 pad5;
	__u64 auth_fail_ts;   /* When the current interval began, ns. */
};

/* Event pushed to userspace on liveness transitions. */
struct bfd_event {
	__u64 ts_ns;          /* when we noticed             */
	__u64 last_seen_ns;   /* last packet before verdict  */
	struct session_key key;
	__u32 remote_disc;
	__u8  event;          /* 0 = DETECT-DOWN, 1 = ALIVE  */
};

/* Most keys the program holds per session. A power of two so a searched index
 * can be masked for the verifier. */
#define BFD_AUTH_ACCEPT_MAX 16

/* One acceptable key, in the shape the digest wants it. */
struct xdp_auth_key {
	__u8 type;
	__u8 key_id;
	__u8 keylen;
	__u8 pad;
	__u8 kpad[64];
};

/* What the program sends for a session; written by the engine. */
struct tx_cfg {
	__u32 enable;        /* 1 = kernel replies to each RX (Up only) */
	__u32 my_disc;
	__u32 your_disc;
	__u32 min_tx_us;
	__u32 min_rx_us;
	__u16 src_port;      /* source port of kernel replies; 0 = BFD_SRC_PORT */
	__u8  state;
	__u8  diag;
	__u8  mult;
	__u8  poll;          /* userspace-initiated Poll sequence active:
	                      * replies set P until final_seq == poll_seq */
	__u8  demand;        /* set the D bit on kernel replies */
	__u8  demand_hold;   /* demand steady state: the sweep must not treat
	                      * the peer's silence as a fault. Precomputed by
	                      * the engine, which sees the remote state */
	__u8  pad[1];
	__u32 poll_seq;      /* increments per Poll; the kernel acks via
	                      * session_state.final_seq */
	__u32 echo_iv_us;    /* echo interval; 0 = echo off */
	__u32 min_echo_rx_us; /* Required Min Echo RX; 0 (no echo) unless echo
	                       * is enabled */
	__u32 min_ttl;       /* lowest acceptable TTL or hop limit: 255
	                      * single-hop, minimum-ttl for multihop; 0 = 255 */
	__u8  auth_type;     /* BFD_AUTH_* of the current transmit key; 0 if
	                      * none is sendable */
	__u8  auth_keyid;
	__u8  auth_keylen;
	__u8  auth_present;  /* the session authenticates at all. Differs from
	                      * auth_type when no key is sendable; received A
	                      * bits are checked against this, as in rx_auth_ok */
	__u8  auth_kpad[64]; /* key zero-padded to one HMAC block by the
	                      * engine; the program cannot pad from a runtime
	                      * length */

	/* Every key a received packet may be signed with now; the engine
	 * applies the lifetimes. */
	__u8  auth_nkeys;
	__u8  auth_nkeys_pad[3];
	struct xdp_auth_key auth_accept[BFD_AUTH_ACCEPT_MAX];
};

#endif /* BFD_SHARED_H */
