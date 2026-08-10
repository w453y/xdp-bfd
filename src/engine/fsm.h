// SPDX-License-Identifier: GPL-2.0
/* fsm.h - RFC 5880 state machine and control-packet TX. */
#ifndef BFD_ENGINE_FSM_H
#define BFD_ENGINE_FSM_H

#include <stdint.h>

#include "session.h"

/* ---------- BFD wire format ---------- */
struct bfdpkt {
	uint8_t  vers_diag, flags, mult, len;
	uint32_t my_disc, your_disc, min_tx, min_rx, min_echo;
} __attribute__((packed));

#define F_P BFD_F_POLL
#define F_F BFD_F_FINAL

extern int tx_sock;
extern int tx6_sock;

void state_transition(struct session *s, int newstate, int diag,
                      uint64_t t, const char *why);
void fsm_rx(struct session *s, const struct bfdpkt *p, uint64_t t);
void fsm_detect(struct session *s, uint64_t t);
void fsm_tx(struct session *s, uint64_t t);

#endif /* BFD_ENGINE_FSM_H */
