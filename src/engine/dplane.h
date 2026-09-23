// SPDX-License-Identifier: GPL-2.0
/* dplane.h - bfddp: connection (dplane_conn.c), messages (dplane.c). */
#ifndef BFD_ENGINE_DPLANE_H
#define BFD_ENGINE_DPLANE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "session.h"

/* dplane.c */
extern uint64_t dp_hold_us;
extern uint64_t dp_reconcile_us;

void dp_notify_state(struct session *s);
void dp_notify_flush_pending(void);
void sess_teardown_one(struct session *s, const char *why);
void dp_reresolve_wildcard(struct session *s, uint64_t now);
/* Header included. */
void dp_process(const uint8_t *buf, size_t len);
void dp_sessions_orphan(const char *why);
void dp_sessions_reclaim(void);

/* dplane_conn.c */
void dp_read(void);
/* Test seam for dp_read; returns like recv(2). */
extern ssize_t (*dp_recv_hook)(int fd, void *buf, size_t len);
void dp_set_conn_for_test(int fd);
void dp_flush(void);
void dp_accept(void);
void dp_fds(int *listen_fd, int *conn_fd);
int dp_listen_init(const char *arg);
void dp_set_peer_uid(uid_t uid);
int dp_connected(void);
/* A full queue drops the connection. */
void dp_send(const void *msg, size_t len);
size_t dp_out_room(void);

#endif /* BFD_ENGINE_DPLANE_H */
