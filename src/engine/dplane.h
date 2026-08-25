// SPDX-License-Identifier: GPL-2.0
/* dplane.h - bfddp control-plane socket: framing, handlers, lifecycle. */
#ifndef BFD_ENGINE_DPLANE_H
#define BFD_ENGINE_DPLANE_H

#include <stdint.h>

#include "session.h"

extern uint64_t dp_hold_us;
extern uint64_t dp_reconcile_us;

void dp_notify_state(struct session *s);
void sess_teardown_one(struct session *s, const char *why);
void dp_read(void);
void dp_flush(void);
void dp_accept(void);
void dp_fds(int *listen_fd, int *conn_fd);
int dp_listen_init(const char *arg);

#endif /* BFD_ENGINE_DPLANE_H */
