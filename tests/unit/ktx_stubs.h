// SPDX-License-Identifier: GPL-2.0
/* ktx_stubs.h - kernel TX stubbed for dp_run and dp_fuzz. Defined, not
 * declared: each is one translation unit.
 */
#ifndef BFD_TEST_KTX_STUBS_H
#define BFD_TEST_KTX_STUBS_H

#include <stdint.h>

#include "bfd_shared.h"
#include "session.h"

int use_ktx;
uint64_t *ktx_seq_mem;

/* dp_run wants failure for the uncovered path; dp_fuzz sets success. */
int ktx_stub_attach_rc = -1;

int ktx_covers(int ifindex)
{
	(void)ifindex;
	return 0;
}
int ktx_attach_if(int ifindex, const char *ifname)
{
	(void)ifindex;
	(void)ifname;
	return ktx_stub_attach_rc;
}
void ktx_clear(struct session *s)
{
	(void)s;
}
void ktx_sync(struct session *s, uint64_t t)
{
	(void)s;
	(void)t;
}
void ktx_clear_key(const struct bfd_addr *peer, const struct bfd_addr *local, uint32_t wire_disc)
{
	(void)peer;
	(void)local;
	(void)wire_disc;
}
void ktx_update_mhop_flag(void)
{
}
void ktx_mirror(struct session *s)
{
	(void)s;
}
void ktx_poll_map(struct session *s, uint64_t t)
{
	(void)s;
	(void)t;
}
/* No program, no sweep, no ring; fsm_detect keeps the whole budget. */
int ktx_events_fd(void)
{
	return -1;
}
/* No map: userspace's counts are all of them. */
void ktx_session_counters(const struct session *s, uint64_t *rx, uint64_t *tx)
{
	(void)s;
	*rx = 0;
	*tx = 0;
}
void echo_peer_refresh(const struct bfd_addr *peer, struct session *skip)
{
	(void)peer;
	(void)skip;
}

#endif /* BFD_TEST_KTX_STUBS_H */
