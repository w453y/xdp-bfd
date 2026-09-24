// SPDX-License-Identifier: GPL-2.0
/* ktx.h - the kernel fast path: load (ktx_load.c), mirror (ktx.c), config
 * (ktx_cfg.c), and across a restart pin (ktx_pin.c).
 */
#ifndef BFD_ENGINE_KTX_H
#define BFD_ENGINE_KTX_H

#include "session.h"

struct bpf_object;

/* ktx_load.c */
extern const char *ktx_obj_path;
extern unsigned int ktx_xdp_flags;
extern int ktx_ifindex;
extern __u64 ktx_sweep_ns;
extern __u64 ktx_deadman_ns;
extern int ktx_cfg_fd;
extern int ktx_flags_fd;
extern int sess_fd;
extern int echo_peers_fd;
extern int echo_disc_fd;
extern int disc_fd;
extern int stats_fd;

int ktx_load(void);

/* ktx_pin.c */
extern const char *ktx_pin_dir;
extern int ktx_reused;
int ktx_pin_prepare(struct bpf_object *o);
void ktx_pin_discard(void);
int ktx_pin_take_link(int ifindex, int prog_fd);
void ktx_pin_link(int ifindex, int link_fd);
void ktx_unpin(void);
int ktx_attach(const char *ifname);
int ktx_attach_if(int ifindex, const char *ifname);
int ktx_covers(int ifindex);
void ktx_heartbeat(uint64_t now);

/* ktx.c */
extern int use_ktx;

void ktx_events_init(int map_fd, int changes_fd);
int ktx_events_fd(void);
void ktx_drain_events(void);
void ktx_mirror(struct session *s);
void ktx_clear(struct session *s);
void ktx_clear_key(const struct bfd_addr *peer, const struct bfd_addr *local, uint32_t wire_disc);
void echo_peer_refresh(const struct bfd_addr *peer, struct session *skip);

/* Echoes the reflector returns per BFD_ECHO_WIN_US for a peer whose fastest
 * session wants one per iv_us: four times the RFC's rate, and room for a
 * burst.
 */
#define ECHO_IV_FLOOR_US 10000
static inline uint32_t echo_budget_for(uint32_t iv_us)
{
	if (iv_us < ECHO_IV_FLOOR_US)
		iv_us = ECHO_IV_FLOOR_US;
	return 4 * ((BFD_ECHO_WIN_US + iv_us - 1) / iv_us) + 16;
}
void ktx_update_mhop_flag(void);
void ktx_poll_all(void);
const char *ktx_poll_mode(void);
void ktx_sync(struct session *s, uint64_t t);
void ktx_sync_all(uint64_t t);
void ktx_sync_due(uint64_t t);
void ktx_session_counters(const struct session *s, uint64_t *rx, uint64_t *tx);

/* ktx_cfg.c */
void ktx_cfg_for(const struct session *s, int64_t now, struct tx_cfg *c, struct session_key *k);

#endif /* BFD_ENGINE_KTX_H */
