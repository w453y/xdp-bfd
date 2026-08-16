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
	uint32_t echo_tx_us;          /* echo interval from the ADD; 0 = off */
	uint32_t min_echo_rx_us;      /* advertised Required Min Echo RX */
	uint8_t  min_ttl;             /* from the ADD; 255 = single-hop */
	int      is_mhop;             /* RFC 5883: control port 4784 */
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
