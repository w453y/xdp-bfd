// SPDX-License-Identifier: GPL-2.0
/* session.h - the session table, shared by dplane, ktx and fsm. */
#ifndef BFD_ENGINE_SESSION_H
#define BFD_ENGINE_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
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


/* One key as bfdd sent it. send and accept overlap during a rollover. */
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

/* A start of 0 is always valid; an end of -1 never expires. */
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
	/* bfdd sent no local address; resolved from the route */
	uint8_t local_wildcard;
	uint64_t last_reresolve_us; /* rate-limits the re-resolve probe */
	uint32_t min_tx_us, min_rx_us;
	uint8_t detect_mult;
	int passive;
	int admin_down; /* SESSION_SHUTDOWN */

	int state, diag;
	/* Not in bfddp_counters; the stats dump reports them. */
	uint32_t up_events, down_events;
	uint64_t last_transition_us;
	/* Taken when detection fires; state_transition clears detect_iv_us. */
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
	uint32_t wire_disc;    /* my_disc on the wire; survives a bfdd restart */
	int orphaned;	       /* held across a bfdd disconnect */
	uint64_t orphan_deadline_us;
	/* lags a min_tx increase until the Poll ends */
	uint32_t applied_tx_us;
	int pushed_valid;
	struct tx_cfg pushed_cfg;
	uint64_t last_rx_us, next_tx_us;
	uint64_t last_ktx_us;	     /* last fast-path reply; see fsm_tx */
	uint64_t ktx_seen_us;	     /* last packet the kernel saw; 0 if never */
	uint64_t ktx_tx_pkts;	     /* kernel reply count at the previous poll */
	uint64_t tx_pkts;	     /* userspace-sent control packets */
	uint32_t last_detect_lag_us; /* sweep verdict to the loop acting on it */
	uint32_t kernel_detects;     /* verdicts taken from the sweep */
	uint64_t tx_fail;	     /* sends refused by sendto(2) */
	uint64_t rx_pkts;	     /* userspace-received; the kernel counts its own */
	uint64_t rx_bytes;	     /* exact, from the validated len field */
	uint8_t echo_on;	     /* SESSION_ECHO from the ADD */
	uint32_t echo_tx_us;	     /* echo interval from the ADD; 0 = off */
	uint32_t min_echo_rx_us;     /* advertised Required Min Echo RX */
	uint8_t min_ttl;	     /* from the ADD; 255 = single-hop */
	int is_mhop;		     /* RFC 5883: control port 4784 */
	uint16_t tx_port;	     /* source port of our sends; 0 before the first */
	uint32_t ifindex;	     /* 0 if unresolved or multihop */
	uint8_t echo_mac[6];	     /* that interface's MAC, for echo TX */
	uint8_t echo_mac_valid;
	/* We ask the peer to stop sending; its own ask is the D bit in r_flags. */
	int demand;
	uint8_t demand_announced; /* D bits sent since entering Up */
	/* RFC 5880 s6.7; the chain arrives in DP_SESSION_AUTH. */
	uint8_t auth_present; /* the session is meant to authenticate */
	uint8_t auth_nkeys;
	struct auth_key auth_keys[BFDDP_AUTH_KEY_COUNT_MAX];
	/* soonest lifetime boundary, 0 if none */
	int64_t auth_next_change;

	/* Send key, refreshed as periods pass; type 0 with auth_present means
	 * send nothing.
	 */
	uint8_t auth_type; /* BFD_AUTH_*, 0 = unauthenticated */
	uint8_t auth_keyid;
	uint8_t auth_keylen;
	uint8_t auth_key[BFDDP_AUTH_KEY_MAX];
	/* the key zero-padded to one SHA1 block */
	uint8_t auth_kpad[64];
	uint32_t auth_tx_seq; /* without the program; else ktx_seq_mem (s6.7.3) */
	uint32_t auth_rx_seq; /* highest accepted from the peer */
	int auth_rx_seen;     /* auth_rx_seq is valid */
	/* DP_SESSION_AUTH deadline after the ADD; 0 = not waiting */
	uint64_t auth_keys_deadline_us;
	uint8_t auth_nokeys_warned; /* said once */
	/* no-sendable-key logged for this gap */
	uint8_t auth_gap_warned;
	uint8_t iface_warned; /* once; bfdd re-sends the ADD on every change */
	/* single-hop on an interface without the fast path */
	uint8_t ktx_uncovered;
	uint8_t peer_mac[6]; /* synced from the map, learned by XDP */
	int mac_valid;
	uint8_t notify_pending;	 /* deferred while the dplane queue was full */
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

/* Demand mode (RFC 5880 s6.6), shared by fsm and ktx_mirror; the same gates as
 * bfdd.
 */

/* RFC 5880 s6.8.6: the D bit goes out only once both ends are Up. */
static inline int demand_bit_out(const struct session *s)
{
	return s->demand && s->state == ST_UP && s->r_state == ST_UP;
}

/* D-marked packets before honouring the peer's demand. */
#define DEMAND_ANNOUNCE_N 3

/* Without it two demanding peers could go quiet with only one having sent D. */
static inline int demand_announce_due(const struct session *s)
{
	return demand_bit_out(s) && s->demand_announced < DEMAND_ANNOUNCE_N;
}

/* RFC 5880 s6.8.7: no periodic TX while bfd.RemoteMinRxInterval is zero, with
 * the demand exemptions. A session that has heard nothing is never held
 * (s6.8.1).
 */
static inline int zero_rx_tx_held(const struct session *s)
{
	return s->last_rx_us && s->r_min_rx == 0 && !s->polling && !s->send_final &&
	       !demand_announce_due(s);
}

/* RFC 5880 s6.8.7: no periodic TX while the peer demands. A Poll, a pending
 * Final and an unsent D are exempt.
 */
static inline int demand_tx_held(const struct session *s)
{
	return (s->r_flags & BFD_F_DEMAND) && s->state == ST_UP && s->r_state == ST_UP &&
	       !s->polling && !s->send_final && !demand_announce_due(s);
}

/* RFC 5880 s6.8.4: no detection while we demand. Our own Poll re-arms it, so a
 * lost Final still takes the session down.
 */
static inline int demand_detect_held(const struct session *s)
{
	return s->demand && s->state == ST_UP && s->r_state == ST_UP && !s->polling;
}

/* The sweep's hold, without the Poll exemption: the program measures from the
 * last real arrival and would fire on every Poll. fsm_detect times the Poll.
 */
static inline int demand_sweep_held(const struct session *s)
{
	return s->demand && s->state == ST_UP && s->r_state == ST_UP;
}

/* RFC 5880 s6.8.9: only while Up, only if the peer's Required Min Echo RX is
 * nonzero, and no faster than it; never over multiple hops (RFC 5883). 0 when
 * no echo may be sent.
 */
static inline uint32_t echo_interval(const struct session *s)
{
	if (!s->echo_tx_us || s->is_mhop || s->state != ST_UP || !s->r_min_echo)
		return 0;
	return s->echo_tx_us > s->r_min_echo ? s->echo_tx_us : s->r_min_echo;
}

/* Must agree with the program's xdp_auth_fast. */
static inline int auth_fast_capable(const struct session *s)
{
	/* Otherwise the program would bounce an unauthenticated reply. */
	if (s->auth_present && !s->auth_type)
		return 0;

	return !s->auth_type || s->auth_type == BFD_AUTH_SIMPLE ||
	       s->auth_type == BFD_AUTH_KEYED_SHA1 || s->auth_type == BFD_AUTH_METICULOUS_SHA1;
}

/* The program answers each packet, so at the peer's pace: max(its Desired Min
 * TX, our Required Min RX). That must not be faster than we may send (RFC 5880
 * s6.8.7); if it is, userspace keeps our own rate.
 */
static inline int ktx_pace_ok(const struct session *s)
{
	uint32_t peer = s->r_min_tx > s->min_rx_us ? s->r_min_tx : s->min_rx_us;
	uint32_t ours = s->applied_tx_us > s->r_min_rx ? s->applied_tx_us : s->r_min_rx;

	return peer >= ours;
}

/* Exactly what ktx_mirror pushes as tx_cfg.enable. */
static inline int ktx_answers(const struct session *s)
{
	return s->state == ST_UP && auth_fast_capable(s) && !demand_tx_held(s) &&
	       !zero_rx_tx_held(s) && ktx_pace_ok(s);
}

/* tx_cfg carries its key, so an address move is a change too. Accept keys
 * past auth_nkeys are zero in both, so the compare stops at the last in use:
 * this runs per session per pass.
 */
static inline int ktx_push_needed(const struct session *s, const struct tx_cfg *c)
{
	size_t n = offsetof(struct tx_cfg, auth_accept) +
		   (size_t)c->auth_nkeys * sizeof(c->auth_accept[0]);

	return !s->pushed_valid || c->auth_nkeys != s->pushed_cfg.auth_nkeys ||
	       memcmp(c, &s->pushed_cfg, n) != 0;
}

extern struct session sessions[MAX_SESSIONS];

/* The program's per-slot auth TX counters, mmapped; NULL without it. */
extern uint64_t *ktx_seq_mem;

/* RFC 5880 s6.7.3: one counter per session for both planes, so neither reuses
 * a number the other sent.
 */
static inline void auth_seq_seed(struct session *s, uint32_t v)
{
	s->auth_tx_seq = v;
	if (ktx_seq_mem)
		__atomic_store_n(&ktx_seq_mem[s - sessions], v, __ATOMIC_RELAXED);
}

static inline uint32_t auth_seq_next(struct session *s)
{
	if (ktx_seq_mem)
		return (uint32_t)__atomic_add_fetch(&ktx_seq_mem[s - sessions], 1,
						    __ATOMIC_RELAXED);
	return ++s->auth_tx_seq;
}

/* When the loop next visits each slot; 0 is the next pass. Set by whatever
 * touches a session, so the pass visits only those and the ones that are due.
 */
extern uint64_t sess_wake_at[MAX_SESSIONS];

static inline void sess_wake(const struct session *s)
{
	sess_wake_at[s - sessions] = 0;
}

void sess_wake_all(void);
struct session *sess_alloc(void);
/* After setting a session's lid, wire_disc or addresses. */
void sess_reindex(const struct session *s);
int session_auth_evaluate(struct session *s, int64_t now);
const struct auth_key *session_auth_key_for(const struct session *s, uint8_t key_id, int64_t now);
struct session *sess_by_lid(uint32_t lid);
struct session *sess_by_wire(uint32_t disc);
void sm_addrs(const struct bfddp_session_msg *sm, struct bfd_addr *l, struct bfd_addr *p,
	      int *family);
struct session *sess_by_addr_pair_local(const struct bfddp_session_msg *sm);
struct session *sess_by_addr(const struct bfd_addr *peer, const struct bfd_addr *local);

#endif /* BFD_ENGINE_SESSION_H */
