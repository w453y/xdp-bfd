// SPDX-License-Identifier: GPL-2.0
/* ktx.h - kernel-TX mirror: XDP attach and the BPF map fds. */
#ifndef BFD_ENGINE_KTX_H
#define BFD_ENGINE_KTX_H

#include "session.h"

extern int use_ktx;
extern const char *ktx_obj_path;
extern int sess_fd;
extern int echo_peers_fd;
extern int echo_disc_fd;

int ktx_attach(const char *ifname);
void ktx_update_mhop_flag(void);
void ktx_mirror(struct session *s);
void ktx_clear(struct session *s);
void ktx_poll_map(struct session *s, uint64_t t);

#endif /* BFD_ENGINE_KTX_H */
