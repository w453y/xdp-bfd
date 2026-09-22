// SPDX-License-Identifier: GPL-2.0
/* ktx_stubs.h - the kernel-TX side, stubbed for dp_run and dp_fuzz, which link
 * only dplane.c, session.c and fsm.c. Defined, not declared: each harness is a
 * single translation unit.
 */
#ifndef BFD_TEST_KTX_STUBS_H
#define BFD_TEST_KTX_STUBS_H

#include <stdint.h>

#include "bfd_shared.h"
#include "session.h"

int use_ktx;

/* What ktx_attach_if returns: dp_run wants failure, to exercise the uncovered
 * path; dp_fuzz sets success.
 */
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
/* No map to read, so a session reports only what userspace sent and
 * received, which is all of it when the fast path is not running.
 */
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
