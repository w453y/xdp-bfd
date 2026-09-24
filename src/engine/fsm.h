// SPDX-License-Identifier: GPL-2.0
/* fsm.h - RFC 5880 state machine and control-packet TX. */
#ifndef BFD_ENGINE_FSM_H
#define BFD_ENGINE_FSM_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "session.h"


#define F_P BFD_F_POLL
#define F_F BFD_F_FINAL
#define F_D BFD_F_DEMAND

extern int tx_sock;
extern int tx6_sock;
/* the fallback sockets' ports */
extern uint16_t tx_sock_port, tx6_sock_port;

uint16_t tx_bind(int fd, int family, const struct bfd_addr *local, uint16_t port);

void state_transition(struct session *s, int newstate, int diag, uint64_t t, const char *why);
void fsm_rx(struct session *s, const struct bfd_ctrl_pkt *p, uint64_t t);
void fsm_detect(struct session *s, uint64_t t);
void fsm_tx(struct session *s, uint64_t t);
uint64_t fsm_tx_next_at(const struct session *s, uint64_t t);
void fsm_start_poll(struct session *s, uint64_t t);
extern uint64_t demand_poll_us;

/* Test seam; NULL in production. */
extern ssize_t (*fsm_send_hook)(int fd, const void *buf, size_t len, const struct sockaddr *dst,
				socklen_t dlen);
void fsm_announce_down(struct session *s);

#endif /* BFD_ENGINE_FSM_H */
