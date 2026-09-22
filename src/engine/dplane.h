// SPDX-License-Identifier: GPL-2.0
/* dplane.h - bfddp control-plane socket: framing, handlers, lifecycle. */
#ifndef BFD_ENGINE_DPLANE_H
#define BFD_ENGINE_DPLANE_H

#include <stdint.h>
#include <sys/types.h>

#include "session.h"

extern uint64_t dp_hold_us;
extern uint64_t dp_reconcile_us;

void dp_notify_state(struct session *s);
void dp_notify_flush_pending(void);
void sess_teardown_one(struct session *s, const char *why);
void dp_reresolve_wildcard(struct session *s, uint64_t now);
void dp_read(void);
/* Test seam: when set, dp_read takes bytes from here instead of
 * recv(2). NULL in production. Return 0 for EOF, -1 with errno
 * EAGAIN for "nothing right now", like the syscall it replaces.
 */
extern ssize_t (*dp_recv_hook)(int fd, void *buf, size_t len);
void dp_set_conn_for_test(int fd);
void dp_flush(void);
void dp_accept(void);
void dp_fds(int *listen_fd, int *conn_fd);
int dp_listen_init(const char *arg);
void dp_set_peer_uid(uid_t uid);

#endif /* BFD_ENGINE_DPLANE_H */
