// SPDX-License-Identifier: GPL-2.0
/* echo_tx.h - m8b echo originator: raw L2 self-addressed probes. */
#ifndef BFD_ENGINE_ECHO_TX_H
#define BFD_ENGINE_ECHO_TX_H

#include <stdint.h>

#include "session.h"

extern int echo_sock;
extern int echo_ifindex;
extern uint8_t echo_src_mac[6];

void echo_tx_init(const char *ifname);
void echo_tx_maybe(struct session *s, uint64_t t);

#endif /* BFD_ENGINE_ECHO_TX_H */
