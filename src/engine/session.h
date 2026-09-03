// SPDX-License-Identifier: GPL-2.0
/* session.h - the session table and engine-wide constants.
 *
 * struct session is the engine's whole per-peer state; the dplane,
 * kernel-TX mirror and FSM modules are peers over this table rather
 * than layers, so they all include this header.
 */
#ifndef BFD_ENGINE_SESSION_H
#define BFD_ENGINE_SESSION_H

#include <stdint.h>
#include <netinet/in.h>

#include "bfd_shared.h"
#include "bffdp.h"

#define PORT_CTRL    BFD_PORT_1HOP
#define SRC_PORT     BFD_SRC_PORT
#define DEF_MIN_TX   10000
#define DEF_MIN_RX   10000
#define DEF_MULT     3
#define SLOW_TX_US   1000000ull
#define MAX_SESSIONS BFD_MAX_SESSIONS


/* ---------- session ---------- */
struct session {
	int      used;
	uint32_t lid;
	struct bfd_addr local, peer;  /* v4 stored v4-mapped */
	int      family;              /* AF_INET / AF_INET6 */
	uint32_t min_tx_us, min_rx_us;
	uint8_t  detect_mult;
	int      passive;
	int      admin_down;          /* SESSION_SHUTDOWN */

	int      state, diag;
	/* Transitions were logged and never counted, so nothing could
	 * answer "how often has this session bounced". bfdd counts it
	 * separately and bfddp_counters has no field for it, so it cannot
	 * travel over the dplane socket - it comes out of the stats dump. */
	uint32_t up_events, down_events;
	uint64_t last_transition_us;
	/* What the last detection actually cost, captured at the moment it
	 * fired. Cannot be recomputed later: state_transition clears
	 * detect_iv_us on the way into Down, so the budget the overshoot is
	 * measured against is gone by the time anything reads the session.
	 * Detect-timeout transitions only - a peer-signalled Down has no
	 * overshoot, and mixing the two puts a false spike at zero. */
	uint32_t last_detect_us;     /* silence before we declared Down */
	uint32_t last_overshoot_us;  /* that, minus the negotiated budget */
	char     last_reason[24];    /* copied, not aliased: every caller
	                              * passes a literal today and nothing
	                              * should have to keep doing so */
	uint32_t rdisc;
	uint32_t r_min_tx, r_min_rx;
	uint32_t r_min_echo;          /* peer's Required Min Echo RX */
	uint8_t  r_mult, r_flags;     /* r_flags: last rx flags & 0x3f */
	int      r_state;
	uint32_t detect_iv_us;        /* poll-aware effective detect basis */
	int      send_final, just_up;
	int      polling;             /* our Poll sequence in flight */
	uint32_t poll_seq;            /* id of current/last Poll sequence */
	uint32_t wire_disc;           /* my_disc on the wire; survives bfdd
	                               * restarts even when lid changes */
	int      orphaned;            /* held across a bfdd disconnect */
	uint64_t orphan_deadline_us;
	uint32_t applied_tx_us;       /* actual TX pace; lags an advertised
	                               * min_tx increase until poll ends */
	int      pushed_valid;
	struct tx_cfg pushed_cfg;
	uint64_t last_rx_us, next_tx_us;
	uint64_t tx_pkts;             /* userspace-sent control packets */
	uint64_t rx_pkts;             /* userspace-received control packets;
	                               * the kernel keeps its own in
	                               * session_state.rx_pkts and the two are
	                               * summed for the counters reply */
	uint64_t rx_bytes;            /* exact, from the validated len field */
	uint8_t  echo_on;             /* SESSION_ECHO from the ADD. Explicit
	                               * rather than inferred from echo_tx_us,
	                               * which is 0 for an echo-enabled
	                               * session whose peer asked for 0 */
	uint32_t echo_tx_us;          /* echo interval from the ADD; 0 = off */
	uint32_t min_echo_rx_us;      /* advertised Required Min Echo RX */
	uint8_t  min_ttl;             /* from the ADD; 255 = single-hop */
	int      is_mhop;             /* RFC 5883: control port 4784 */
	int      demand;              /* SESSION_DEMAND from the ADD: we ask
	                               * the peer to stop transmitting. The
	                               * peer's own request is not mirrored
	                               * here - it is the D bit in r_flags,
	                               * already latched from every packet,
	                               * and a second copy would only drift */
	uint8_t  demand_announced;    /* D bits actually put on the wire
	                               * since entering Up; see
	                               * demand_announce_due */
	uint8_t  iface_warned;        /* the off-interface notice is once per
	                               * session, not once per ADD - bfdd
	                               * re-sends one on every config touch */
	uint8_t  ktx_uncovered;       /* single-hop session on an
	                              * interface the fast path is not
	                              * attached to. --kernel-tx is
	                              * global but coverage is not, and
	                              * fsm_tx must not stay silent
	                              * waiting for a bounce that no
	                              * XDP program will make. */
	uint8_t  peer_mac[6];         /* synced from the map, learned by XDP */
	int      mac_valid;
	uint64_t next_echo_tx_us;
	uint32_t echo_nonce;          /* nonce of the outstanding echo */
	uint64_t echo_sent_us;        /* 0 = none outstanding */
	uint64_t echo_tx_pkts;
	int      echo_disc_done;
	uint64_t echo_rx_pkts, echo_lost;
	uint64_t echo_rtt_last_us, echo_rtt_min_us, echo_rtt_max_us;
	uint64_t echo_rtt_sum_us, echo_rtt_n;
	int      echo_alive_k;        /* kernel's advisory verdict */
	uint64_t echo_last_send_us;   /* for inter-send gap tracking */
	uint64_t echo_gap_max_us;     /* windowed, reset each report */
	uint64_t echo_rtt_max_win_us; /* windowed, reset each report */
};

/* ---------- demand mode (RFC 5880 s6.6) ----------
 *
 * Three predicates, each gating a different thing, and the asymmetry
 * between them is the whole of demand mode: the D bit travels one way
 * per direction, so who asked decides what stops.
 *
 * They are here rather than in fsm.c because the kernel mirror has to
 * compute the same answers for tx_cfg - the XDP program cannot, it sees
 * no remote state - and two spellings of one predicate is how the fast
 * and slow paths drift.
 *
 * Deliberately matched line for line against bfdd's own gates so a
 * session behaves identically whether or not it is delegated here:
 * bfd_packet.c:465 (D bit), bfd.c:693 (transmission), and
 * bfd_packet.c:1473 (detection).
 */

/* RFC 5880 s6.8.6: the D bit goes out only once both ends are Up. */
static inline int demand_bit_out(const struct session *s)
{
	return s->demand && s->state == ST_UP && s->r_state == ST_UP;
}

/* How many D-marked packets to get out before honouring a peer's own
 * demand. One would do if nothing were ever lost; three is what
 * fsm_announce_down already uses for the same reason, and the cost is
 * three 24-byte packets once per session coming up. */
#define DEMAND_ANNOUNCE_N 3

/* We are configured to demand but have not yet said so on the wire.
 *
 * This exists because the two conditions arrive together. r_state only
 * reaches Up when the peer's first Up-state packet lands, and if the
 * peer is also demanding then that very packet carries its D bit - so
 * demand_bit_out and the peer's request become true in the same sync,
 * and a session that ceased on the spot would go quiet having never
 * once set D. The peer would then keep transmitting forever, waiting
 * for a request that is never coming, and a config asking for demand in
 * both directions would only ever get it in one.
 *
 * bfdd does not need this: it evaluates the hold at each transmit timer
 * expiry, so it has already sent several D-marked packets by the time
 * it stops. Announcing explicitly is how a dataplane that can cease
 * within a microsecond of the flag flipping keeps bfdd's behaviour.
 */
static inline int demand_announce_due(const struct session *s)
{
	return demand_bit_out(s) && s->demand_announced < DEMAND_ANNOUNCE_N;
}

/* RFC 5880 s6.8.7: periodic transmission ceases while the PEER is
 * demanding - it asked, not us. A Poll sequence, a pending Final and an
 * unsent D are exempt: they are the only things that still have to
 * reach a peer that has stopped listening on a schedule. */
static inline int demand_tx_held(const struct session *s)
{
	return (s->r_flags & BFD_F_DEMAND) && s->state == ST_UP &&
	       s->r_state == ST_UP && !s->polling && !s->send_final &&
	       !demand_announce_due(s);
}

/* RFC 5880 s6.8.4: the detection timer does not run while WE are
 * demanding - we told the peer to go quiet, so silence is what we asked
 * for and not a fault. Our own Poll re-arms it, which is what bounds the
 * poll: a lost Final then brings the session down instead of leaving it
 * outstanding forever. */
static inline int demand_detect_held(const struct session *s)
{
	return s->demand && s->state == ST_UP && s->r_state == ST_UP &&
	       !s->polling;
}

extern struct session sessions[MAX_SESSIONS];

struct session *sess_alloc(void);
struct session *sess_by_lid(uint32_t lid);
struct session *sess_by_wire(uint32_t disc);
void sm_addrs(const struct bfddp_session_msg *sm,
              struct bfd_addr *l, struct bfd_addr *p, int *family);
struct session *sess_by_addr_pair_local(
        const struct bfddp_session_msg *sm);
struct session *sess_by_addr(const struct bfd_addr *peer,
                             const struct bfd_addr *local);

#endif /* BFD_ENGINE_SESSION_H */
