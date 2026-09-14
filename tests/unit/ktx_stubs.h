// SPDX-License-Identifier: GPL-2.0
/* ktx_stubs.h - the kernel-TX side, absent.
 *
 * dp_run and dp_fuzz link dplane.c, session.c and fsm.c and nothing else,
 * so every ktx_ reference has to be answered. Both harnesses used to carry
 * their own copy of this list and the copies drifted: fsm.c gained a call
 * to ktx_events_fd, dp_run.c was given the stub, dp_fuzz.c was not, and the
 * fuzz target stopped linking. Nothing caught it until the first pull
 * request, because `check` builds dp_run and not dp_fuzz.
 *
 * One copy, then. The harnesses disagreed about exactly one value, so that
 * one is a variable rather than a reason to keep two files.
 *
 * Defined, not declared: each harness is a single translation unit, so
 * there is no second definition to collide with.
 */
#ifndef BFD_TEST_KTX_STUBS_H
#define BFD_TEST_KTX_STUBS_H

#include <stdint.h>

#include "bfd_shared.h"
#include "session.h"

int use_ktx;

/* What ktx_attach_if returns. dp_run wants failure, so an ADD naming an
 * interface the fast path does not cover takes the uncovered path it is
 * there to exercise; dp_fuzz wants success, so the parser under libFuzzer
 * is not steered down one branch by a stub. The only thing the two ever
 * disagreed about.
 */
int ktx_stub_attach_rc = -1;

int ktx_covers(int ifindex) { (void)ifindex; return 0; }
int ktx_attach_if(int ifindex, const char *ifname)
{
	(void)ifindex; (void)ifname;
	return ktx_stub_attach_rc;
}
void ktx_clear(struct session *s) { (void)s; }
void ktx_clear_key(const struct bfd_addr *peer, const struct bfd_addr *local,
		   uint32_t wire_disc)
{
	(void)peer; (void)local; (void)wire_disc;
}
void ktx_update_mhop_flag(void) { }
void ktx_mirror(struct session *s) { (void)s; }
void ktx_poll_map(struct session *s, uint64_t t) { (void)s; (void)t; }
/* No program, no sweep, no ring; fsm_detect keeps the whole budget. */
int ktx_events_fd(void) { return -1; }
/* No map to read, so a session reports only what userspace sent and
 * received, which is all of it when the fast path is not running. */
void ktx_session_counters(const struct session *s, uint64_t *rx, uint64_t *tx)
{
	(void)s;
	*rx = 0;
	*tx = 0;
}
void echo_peer_refresh(const struct bfd_addr *peer, struct session *skip)
{
	(void)peer; (void)skip;
}

#endif /* BFD_TEST_KTX_STUBS_H */
