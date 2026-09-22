// SPDX-License-Identifier: GPL-2.0
/* session.h - session table and engine-wide constants. struct session holds
 * all per-peer state; dplane, ktx and fsm all work on this table.
 */
#ifndef BFD_ENGINE_SESSION_H
#define BFD_ENGINE_SESSION_H

#include <stdint.h>
#include <netinet/in.h>

#include "bfd_shared.h"
#include "bfddp.h"

#define PORT_CTRL    BFD_PORT_1HOP
#define SRC_PORT     BFD_SRC_PORT
#define DEF_MIN_TX   10000
#define DEF_MIN_RX   10000
#define DEF_MULT     3
#define SLOW_TX_US   1000000ull
#define MAX_SESSIONS BFD_MAX_SESSIONS


/* ---------- session ---------- */
/* One key as the control plane sent it. `send` bounds signing and `accept`
 * bounds verification; they overlap during a rollover.
 */
struct auth_key {
	uint8_t type;
	uint8_t key_id;
	uint8_t keylen;
	uint8_t kpad[64];
	int64_t send_start;
	int64_t send_end;
	int64_t accept_start;
	int64_t accept_end;
};

/* Is `now` inside the period? A start of 0 means always valid and an end of -1
 * never expires, as bfdd sends a key without lifetimes.
 */
static inline int auth_within(int64_t start, int64_t end, int64_t now)
{
	if (start == 0)
		return 1;
	if (start > now)
		return 0;
	return end == -1 || end >= now;
}

static inline int auth_key_sendable(const struct auth_key *k, int64_t now)
{
	return auth_within(k->send_start, k->send_end, now);
}

static inline int auth_key_acceptable(const struct auth_key *k, int64_t now)
{
	return auth_within(k->accept_start, k->accept_end, now);
}

struct session {
	int used;
	uint32_t lid;
	struct bfd_addr local, peer; /* v4 stored v4-mapped */
	int family;		     /* AF_INET / AF_INET6 */
	/* bfdd sent no local address; resolved from the route and re-resolved
	 * if it moves
	 */
	uint8_t local_wildcard;
	uint64_t last_reresolve_us; /* rate-limits the re-resolve probe */
	uint32_t min_tx_us, min_rx_us;
	uint8_t detect_mult;
	int passive;
	int admin_down; /* SESSION_SHUTDOWN */

	int state, diag;
	/* bfddp_counters has no field for these, so they cannot travel over
	 * the dplane socket; they come out of the stats dump instead.
	 */
	uint32_t up_events, down_events;
	uint64_t last_transition_us;
	/* Recorded when detection fires, since state_transition clears
	 * detect_iv_us on the way into Down. Detect timeouts only.
	 */
	uint32_t last_detect_us;    /* silence before we declared Down */
	uint32_t last_overshoot_us; /* that, minus the negotiated budget */
	char last_reason[24];	    /* copied, not aliased */
	uint32_t rdisc;
	uint32_t r_min_tx, r_min_rx;
	uint32_t r_min_echo;	 /* peer's Required Min Echo RX */
	uint8_t r_mult, r_flags; /* r_flags: last rx flags & 0x3f */
	int r_state;
	uint32_t detect_iv_us; /* poll-aware effective detect basis */
	int send_final, just_up;
	int polling;	       /* our Poll sequence in flight */
	uint32_t demand_polls; /* Polls started to verify an idle demanding session */
	uint32_t poll_seq;     /* id of current/last Poll sequence */
	uint32_t wire_disc; /* my_disc on the wire; survives bfdd restarts even when lid changes */
	int orphaned;	    /* held across a bfdd disconnect */
	uint64_t orphan_deadline_us;
	/* actual TX pace; lags an advertised min_tx increase until poll ends */
	uint32_t applied_tx_us;
	int pushed_valid;
	struct tx_cfg pushed_cfg;
	/* Map key the cached config was pushed under, so an address move is
	 * noticed.
	 */
	struct session_key pushed_key;
	uint64_t last_rx_us, next_tx_us;
	uint64_t last_ktx_us;	     /* when the fast path last transmitted; see fsm_tx */
	uint64_t ktx_tx_pkts;	     /* kernel reply count at the previous poll */
	uint64_t tx_pkts;	     /* userspace-sent control packets */
	uint32_t last_detect_lag_us; /* from the sweep's verdict to the loop acting on it */
	uint32_t kernel_detects;     /* verdicts taken from the sweep */
	uint64_t tx_fail;	     /* sends refused by sendto(2) */
	uint64_t rx_pkts;	     /* userspace-received; the kernel counts its own */
	uint64_t rx_bytes;	     /* exact, from the validated len field */
	uint8_t echo_on;	     /* SESSION_ECHO from the ADD */
	uint32_t echo_tx_us;	     /* echo interval from the ADD; 0 = off */
	uint32_t min_echo_rx_us;     /* advertised Required Min Echo RX */
	uint8_t min_ttl;	     /* from the ADD; 255 = single-hop */
	int is_mhop;		     /* RFC 5883: control port 4784 */
	uint32_t ifindex;    /* where bfdd placed the session; 0 if unresolved or multihop */
	uint8_t echo_mac[6]; /* that interface's MAC, for echo TX */
	uint8_t echo_mac_valid;
	/* SESSION_DEMAND: we ask the peer to stop sending. The peer's own
	 * request is the D bit in r_flags
	 */
	int demand;
	uint8_t demand_announced; /* D bits sent since entering Up */
	/* Authentication (RFC 5880 s6.7). The chain arrives in
	 * DP_SESSION_AUTH; key selection follows the clock here.
	 */
	uint8_t auth_present; /* the session is meant to authenticate */
	uint8_t auth_nkeys;
	struct auth_key auth_keys[BFDDP_AUTH_KEY_COUNT_MAX];
	/* soonest a lifetime boundary passes, 0 when none of them ever will */
	int64_t auth_next_change;

	/* Key in use for transmission, refreshed as periods pass. A zero type
	 * on a session that must authenticate means send nothing.
	 */
	uint8_t auth_type; /* BFD_AUTH_*, 0 = unauthenticated */
	uint8_t auth_keyid;
	uint8_t auth_keylen;
	uint8_t auth_key[BFDDP_AUTH_KEY_MAX];
	/* key zero-padded to one SHA1 block, as the digest and fast path use
	 * it
	 */
	uint8_t auth_kpad[64];
	/* the kernel's transmit sequence has been handed over; see ktx_mirror */
	uint8_t auth_seeded;
	uint32_t auth_tx_seq; /* ours, per transmission; random start (s6.7.3) */
	uint32_t auth_rx_seq; /* highest accepted from the peer */
	int auth_rx_seen;     /* auth_rx_seq is valid */
	/* deadline for DP_SESSION_AUTH after the ADD; 0 = not waiting */
	uint64_t auth_keys_deadline_us;
	uint8_t auth_nokeys_warned; /* the old-bfdd diagnosis, said once */
	/* "no sendable key" logged for this gap; cleared when a key becomes
	 * sendable
	 */
	uint8_t auth_gap_warned;
	uint8_t iface_warned; /* once per session; bfdd re-sends the ADD on every config change */
	/* single-hop session on an interface without the fast path; fsm_tx
	 * keeps sending
	 */
	uint8_t ktx_uncovered;
	uint8_t peer_mac[6]; /* synced from the map, learned by XDP */
	int mac_valid;
	uint8_t notify_pending;	 /* state change deferred while the dplane queue was full */
	uint64_t log_win_us;	 /* start of this session's 1s log window */
	uint16_t log_n;		 /* transitions logged in the window */
	uint16_t log_suppressed; /* transitions suppressed in it */
	uint64_t next_echo_tx_us;
	uint32_t echo_nonce;   /* nonce of the outstanding echo */
	uint64_t echo_sent_us; /* 0 = none outstanding */
	uint64_t echo_tx_pkts;
	int echo_disc_done;
	uint64_t echo_rx_pkts, echo_lost;
	uint64_t echo_rtt_last_us, echo_rtt_min_us, echo_rtt_max_us;
	uint64_t echo_rtt_sum_us, echo_rtt_n;
	int echo_alive_k;	      /* kernel's advisory verdict */
	uint64_t echo_last_send_us;   /* for inter-send gap tracking */
	uint64_t echo_gap_max_us;     /* windowed, reset each report */
	uint64_t echo_rtt_max_win_us; /* windowed, reset each report */
};

/* ---------- demand mode (RFC 5880 s6.6) ----------
 *
 * Shared by fsm and ktx_mirror so both paths agree. They match bfdd's own
 * gates.
 */

/* RFC 5880 s6.8.6: the D bit goes out only once both ends are Up. */
static inline int demand_bit_out(const struct session *s)
{
	return s->demand && s->state == ST_UP && s->r_state == ST_UP;
}

/* How many D-marked packets to get out before honouring a peer's own
 * demand. One would do if nothing were ever lost.
 */
#define DEMAND_ANNOUNCE_N 3

/* Configured to demand but not yet said so. Send DEMAND_ANNOUNCE_N D-marked
 * packets before honouring the peer's demand, or two demanding peers could go
 * quiet with only one having sent D.
 */
static inline int demand_announce_due(const struct session *s)
{
	return demand_bit_out(s) && s->demand_announced < DEMAND_ANNOUNCE_N;
}

/* RFC 5880 s6.8.7: no periodic TX while bfd.RemoteMinRxInterval is zero, with
 * the same exemptions as demand. last_rx_us stands in for the s6.8.1 initial
 * value of 1, so a session that has heard nothing is never held.
 */
static inline int zero_rx_tx_held(const struct session *s)
{
	return s->last_rx_us && s->r_min_rx == 0 && !s->polling && !s->send_final &&
	       !demand_announce_due(s);
}

/* RFC 5880 s6.8.7: no periodic TX while the peer is demanding. A Poll, a
 * pending Final and an unsent D are exempt.
 */
static inline int demand_tx_held(const struct session *s)
{
	return (s->r_flags & BFD_F_DEMAND) && s->state == ST_UP && s->r_state == ST_UP &&
	       !s->polling && !s->send_final && !demand_announce_due(s);
}

/* RFC 5880 s6.8.4: detection does not run while we are demanding. Our own Poll
 * re-arms it, so a lost Final still takes the session down.
 */
static inline int demand_detect_held(const struct session *s)
{
	return s->demand && s->state == ST_UP && s->r_state == ST_UP && !s->polling;
}

/* The sweep's hold: demand_detect_held without the poll exemption. The program
 * measures from the peer's last real arrival, a poll interval old on a
 * demanding session, so it would declare Down on every poll. A poll's timeout
 * is left to fsm_detect, which measures from when the poll started.
 */
static inline int demand_sweep_held(const struct session *s)
{
	return s->demand && s->state == ST_UP && s->r_state == ST_UP;
}

/* The fast path supports every authentication type. Must agree with the
 * program's xdp_auth_fast.
 */
static inline int auth_fast_capable(const struct session *s)
{
	/* Must authenticate but has no sendable key: the program would bounce
	 * an unauthenticated reply.
	 */
	if (s->auth_present && !s->auth_type)
		return 0;

	return !s->auth_type || s->auth_type == BFD_AUTH_SIMPLE ||
	       s->auth_type == BFD_AUTH_KEYED_SHA1 || s->auth_type == BFD_AUTH_METICULOUS_SHA1;
}

/* Whether the fast path answers for this session: exactly what ktx_mirror
 * pushes as tx_cfg.enable. fsm_tx asks the same before going quiet.
 */
static inline int ktx_answers(const struct session *s)
{
	/* Disarm under zero_rx_tx_held too; userspace honours the same
	 * exemptions.
	 */
	return s->state == ST_UP && auth_fast_capable(s) && !demand_tx_held(s) &&
	       !zero_rx_tx_held(s);
}

/* Does the program still hold what this session last pushed? The key is
 * compared too, since an address move leaves tx_cfg unchanged. Here rather
 * than in ktx_mirror so it can be tested without a loaded program.
 */
static inline int ktx_push_needed(const struct session *s, const struct tx_cfg *c,
				  const struct session_key *k)
{
	return !s->pushed_valid || memcmp(c, &s->pushed_cfg, sizeof(*c)) != 0 ||
	       memcmp(k, &s->pushed_key, sizeof(*k)) != 0;
}

extern struct session sessions[MAX_SESSIONS];

struct session *sess_alloc(void);
int session_auth_evaluate(struct session *s, int64_t now);
const struct auth_key *session_auth_key_for(const struct session *s, uint8_t key_id, int64_t now);
struct session *sess_by_lid(uint32_t lid);
struct session *sess_by_wire(uint32_t disc);
void sm_addrs(const struct bfddp_session_msg *sm, struct bfd_addr *l, struct bfd_addr *p,
	      int *family);
struct session *sess_by_addr_pair_local(const struct bfddp_session_msg *sm);
struct session *sess_by_addr(const struct bfd_addr *peer, const struct bfd_addr *local);

#endif /* BFD_ENGINE_SESSION_H */
