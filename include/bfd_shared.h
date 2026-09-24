// SPDX-License-Identifier: GPL-2.0
/* bfd_shared.h - the map formats shared by the program, engine and loader. */
#ifndef BFD_SHARED_H
#define BFD_SHARED_H

#include <linux/types.h>
#include <linux/bpf.h>

#define BFD_PORT_1HOP 3784
#define BFD_PORT_MHOP 4784 /* RFC 5883 multihop */
#define BFD_ECHO_PORT 3785
/* Source port = base + slot, up to 65535, away from bfdd's sockets from 49152 up. */
#define BFD_SRC_PORT	 (65536 - BFD_MAX_SESSIONS)
#define BFD_MIN_LEN	 24
#define BFD_VERSION	 1
#define BFD_MAX_SESSIONS 1024

/* RFC 5880 s4.1 */
#define BFD_F_POLL   0x20
#define BFD_F_FINAL  0x10
#define BFD_F_CPI    0x08 /* Control Plane Independent */
#define BFD_F_AUTH   0x04 /* Authentication Present */
#define BFD_F_DEMAND 0x02 /* Demand mode */
#define BFD_F_MP     0x01 /* Multipoint */

/* RFC 5880 s6.8.1, in wire order. */
enum bfd_state { ST_ADMINDOWN, ST_DOWN, ST_INIT, ST_UP };

static inline const char *bfd_state_str(int st)
{
	switch (st) {
	case ST_ADMINDOWN:
		return "AdminDown";
	case ST_DOWN:
		return "Down";
	case ST_INIT:
		return "Init";
	case ST_UP:
		return "Up";
	default:
		return "?";
	}
}

/* RFC 5880 s4.1, the 24-byte mandatory section. */
struct bfd_ctrl_pkt {
	__u8 vers_diag;
	__u8 flags;
	__u8 detect_mult;
	__u8 len;
	__be32 my_disc;
	__be32 your_disc;
	__be32 min_tx;
	__be32 min_rx;
	__be32 min_echo_rx;
} __attribute__((packed));

#define BFD_VERS(h)  (((h)->vers_diag >> 5) & 0x7)
#define BFD_DIAG(h)  ((h)->vers_diag & 0x1f)
#define BFD_STATE(h) (((h)->flags >> 6) & 0x3)

/* Stat slots, defined once. MALFORMED, REJECTED, UNSUPPORTED_FLAGS and
 * SWEEP_INIT_FAIL stay flat on a healthy system; NOT_SELF does not, as FRR
 * sources v6 echoes at the peer. ECHO_TTL is unreachable and keeps the
 * numbering.
 */
#define BFD_STAT_LIST(X)                                                                          \
	X(SEEN, "seen")				  /* every packet seen */                         \
	X(WELL_FORMED, "well-formed")		  /* parses as BFD */                             \
	X(MALFORMED, "malformed")		  /* header does not */                           \
	X(REJECTED, "rejected")			  /* GTSM, demux, frag */                         \
	X(REFLECTED, "reflected")		  /* echo bounced */                              \
	X(ECHO_RETURNS, "echo-returns")		  /* our echo came back */                        \
	X(DECLINED, "declined")			  /* echo, peer unknown */                        \
	X(NOT_SELF, "not-self")			  /* echo, not self-addr */                       \
	X(ECHO_TTL, "echo-ttl")			  /* unreachable, see above */                    \
	X(UNSUPPORTED_FLAGS, "unsupported-flags") /* M bit */                                     \
	X(SWEEP_INIT_FAIL, "sweep-init-fail")	  /* sweeper never armed */                       \
	X(IP_OPTIONS, "ip-options")		  /* BFD port, IP options */                      \
	X(AUTH_MISMATCH, "auth-mismatch")	  /* A bit vs session */                          \
	X(AUTH_BAD, "auth-bad")			  /* key, digest or seq */                        \
	X(DEADMAN_HOLD, "deadman-hold")		  /* reply withheld, engine stalled */            \
	X(UNKNOWN_SESSION, "unknown-session")	  /* no session for the pair */                   \
	X(V6_EXTHDR, "v6-exthdr")		  /* BFD behind a v6 ext hdr */                   \
	X(AUTH_RATELIMITED, "auth-ratelimited")	  /* A-bit drop before digest */                  \
	X(MOVED_RATELIMITED, "moved-ratelimited") /* over the moved-address budget */             \
	X(ECHO_RATELIMITED, "echo-ratelimited")	  /* over a peer's echo budget */                 \
	X(CHANGES_LOST, "changes-lost")		  /* change ring full; engine resyncs */

/* Written between load and attach. Their own map: .rodata would need rewriting
 * whole, and sweep_map holds a bpf_timer.
 */
enum bfd_tunable {
	BFD_TUNE_SWEEP_NS, /* 0 = compiled default */
	/* max heartbeat age before the fast path stops answering; 0 = off */
	BFD_TUNE_DEADMAN_NS,
	BFD_TUNE_MAX
};

#define BFD_SWEEP_NS_DEFAULT (5ull * 1000 * 1000)

/* 1s: some thirty times the worst loop gap on a 64-session mesh. */
#define BFD_DEADMAN_NS_DEFAULT (1000ull * 1000 * 1000)

/* A floor; the detect budget raises it. */
#define BFD_DEMAND_POLL_US_DEFAULT 1000000ull

enum bfd_stat {
#define BFD_STAT_ENUM(n, s) BFD_STAT_##n,
	BFD_STAT_LIST(BFD_STAT_ENUM)
#undef BFD_STAT_ENUM
		BFD_STAT_MAX
};

/* RFC 5880 s6.7, the types FRR produces; no keychain algorithm maps to keyed MD5. */
#define BFD_AUTH_NONE		 0
#define BFD_AUTH_SIMPLE		 1
#define BFD_AUTH_KEYED_SHA1	 4
#define BFD_AUTH_METICULOUS_SHA1 5

/* type, length, key id */
#define BFD_AUTH_SIMPLE_HDR    3
#define BFD_AUTH_SIMPLE_MAXKEY 16

/* type, length, key id, reserved, sequence, digest */
#define BFD_AUTH_SHA1_LEN 28

/* Digest failures per detect interval before A-bit packets are dropped
 * unhashed. A rollover costs a handful.
 */
#define BFD_AUTH_FAIL_MAX     8
#define BFD_AUTH_SHA1_SEQ_OFF 4
#define BFD_AUTH_SHA1_DIG_OFF 8

/* Mandatory section plus keyed SHA1: 52 bytes. */
#define BFD_MAX_LEN (BFD_MIN_LEN + BFD_AUTH_SHA1_LEN)

/* RFC 5880 s6.8.6. */
enum bfd_ctrl_verdict {
	BFD_CTRL_ACCEPT = 0,
	BFD_CTRL_MALFORMED,	/* header does not parse */
	BFD_CTRL_UNSUPPORTED,	/* well formed, carries a flag we cannot honour */
	BFD_CTRL_AUTH_MISMATCH, /* the A bit and the session disagree */
};

/* Shared by both planes, host order. payload_len is what follows the UDP
 * header. Classifies only.
 */
static inline int bfd_ctrl_check(__u8 vers_diag, __u8 flags, __u8 mult, __u8 len, __u32 my_disc,
				 __u32 payload_len, __u8 auth_expected)
{
	if (((vers_diag >> 5) & 0x7) != BFD_VERSION)
		return BFD_CTRL_MALFORMED;
	if (len < BFD_MIN_LEN || len > payload_len)
		return BFD_CTRL_MALFORMED;
	if (mult == 0 || my_disc == 0)
		return BFD_CTRL_MALFORMED;
	if (flags & BFD_F_MP)
		return BFD_CTRL_UNSUPPORTED;

	/* Either way, so a peer cannot strip authentication. */
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

/* ::ffff:a.b.c.d, identical in both planes. */
static inline void key_set_v4(struct bfd_addr *a, __be32 v4)
{
	__builtin_memset(a, 0, sizeof(*a));
	a->b[10] = 0xff;
	a->b[11] = 0xff;
	__builtin_memcpy(&a->b[12], &v4, 4);
}

static inline void key_set_v6(struct bfd_addr *a, const void *v6)
{
	__builtin_memcpy(a->b, v6, 16);
}

struct session_state {
	__u64 last_seen_ns;
	__u64 rx_pkts;
	__u64 tx_pkts; /* kernel XDP_TX replies */
	__u32 remote_disc;
	__u32 local_disc;
	__u32 min_tx_us;
	__u32 min_rx_us;
	/* lags advertised decreases until the peer paces at them */
	__u32 detect_iv_us;
	__u8 remote_state;
	__u8 remote_diag;
	__u8 detect_mult;
	__u8 remote_flags; /* last flags, less the state bits */
	/* sweep verdict. 64-bit: clang < 20 has no 32-bit BPF cmpxchg */
	__u64 alive;
	__u32 final_seq;  /* the peer's F acked cfg->poll_seq */
	__u8 peer_mac[6]; /* learned on RX, for echo TX */
	__u8 mac_valid;
	__u8 pad2;
	__u64 echo_rx_pkts; /* our own echoes seen returning */
	__u64 echo_last_seen_ns;
	__u32 echo_last_nonce;
	__u32 pad3;
	__u32 echo_alive; /* advisory echo verdict, kernel-owned */
	__u32 pad4;
	/* for bfdd's echo negotiation (s6.8.9) */
	__u32 remote_min_echo_us;
	__u32 auth_rx_seq;  /* highest sequence accepted from the peer */
	__u32 auth_rx_seen; /* auth_rx_seq is valid */
	__u32 auth_fail_n;  /* digest failures this interval; kernel-owned */
	__u32 chg_pending;  /* a change not yet announced on bfd_changes */
	__u64 auth_fail_ts; /* start of the current interval, ns */
	__u64 chg_emit_ns;  /* the last announcement */
};

/* DOWN and ALIVE on bfd_events; CHANGED on bfd_changes, when something the
 * engine mirrors from the peer's packets moved.
 */
enum { BFD_EV_DOWN, BFD_EV_ALIVE, BFD_EV_CHANGED };

/* Liveness transitions for userspace. */
struct bfd_event {
	__u64 ts_ns;	    /* when we noticed             */
	__u64 last_seen_ns; /* last packet before verdict  */
	struct session_key key;
	__u32 remote_disc;
	__u8 event; /* BFD_EV_* */
};

/* A power of two, so a searched index can be masked. */
#define BFD_AUTH_ACCEPT_MAX 16

/* Shaped for the digest. */
struct xdp_auth_key {
	__u8 type;
	__u8 key_id;
	__u8 keylen;
	__u8 pad;
	__u8 kpad[64];
};

/* echo_peers' value. RFC 5880 s6.8.9: a peer sends echo no faster than our
 * Required Min Echo RX, so past a few times that the reflector drops, and a
 * forger spoofing the peer cannot fill our transmit ring. The engine writes
 * max; the program counts.
 */
#define BFD_ECHO_WIN_US 100000
struct echo_peer {
	__u64 win_ns;
	__u32 n;
	__u32 max; /* per BFD_ECHO_WIN_US */
};

/* Written by the engine in place under lock (BPF_F_LOCK); the program copies
 * it out under the same lock, so a reply never mixes two versions or sessions.
 */
struct tx_cfg {
	struct bpf_spin_lock lock;
	/* the entry's own key, checked after the copy */
	struct session_key key;
	__u32 enable; /* reply to each RX; Up only */
	__u32 my_disc;
	__u32 your_disc;
	__u32 min_tx_us;
	__u32 min_rx_us;
	__u16 src_port; /* userspace sends from it too; 0 = BFD_SRC_PORT */
	__u8 state;
	__u8 diag;
	__u8 mult;
	/* our Poll is active: set P until final_seq == poll_seq */
	__u8 poll;
	__u8 demand; /* D bit on replies */
	/* the peer's silence is requested; the engine sees the remote state */
	__u8 demand_hold;
	__u8 mhop;	      /* 4784 (RFC 5883), else 3784 */
	__u16 slot;	      /* the session's slot, indexing auth_seq */
	__u32 poll_seq;	      /* acked through session_state.final_seq */
	__u32 echo_iv_us;     /* echo interval; 0 = echo off */
	__u32 min_echo_rx_us; /* 0 unless echo is on */
	/* lowest TTL or hop limit accepted; 0 = 255 */
	__u32 min_ttl;
	__u8 auth_type; /* current send key; 0 if none is sendable */
	__u8 auth_keyid;
	__u8 auth_keylen;
	/* authenticates at all, even with no sendable key; A bits are checked against this */
	__u8 auth_present;
	/* padded by the engine; the program cannot pad a runtime length */
	__u8 auth_kpad[64];

	/* every key a packet may be signed with now */
	__u8 auth_nkeys;
	__u8 auth_nkeys_pad[3];
	struct xdp_auth_key auth_accept[BFD_AUTH_ACCEPT_MAX];
};

#endif /* BFD_SHARED_H */
