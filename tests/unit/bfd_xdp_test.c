// SPDX-License-Identifier: GPL-2.0
/* bfd_xdp_test.c - test-only entry point into the detection sweep.
 *
 * check_session() is a pure function of (map state, now), but it only ever
 * runs from a bpf_timer, and bpf_timer does not fire under
 * BPF_PROG_TEST_RUN. So the sweep - detect arithmetic, the echo advisory
 * verdict, the alive compare-and-swap - has no coverage at all.
 *
 * This object exists to give the harness a way in. It is NOT built into
 * bfd_xdp.o and is never loaded in production: putting a test entry point
 * in the shipped bytecode would mean a loader could attach it by mistake,
 * and one more program for the verifier to accept on every supported
 * kernel.
 *
 * The include list below must match src/xdp/bfd_xdp.c exactly, in the same
 * order - maps.h before anything referencing a map by symbol, sweep.h
 * before tx.h. Same headers, same clang flags, so the only thing that can
 * differ between this object and the real one is the entry point itself.
 * If you change the include block in bfd_xdp.c, change it here too.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "bfd_shared.h"

#include "tunables.h"
#include "maps.h"
#include "stats.h"
#include "parse.h"
#include "validate.h"
#include "sweep.h"
#include "csum.h"
#include "echo.h"
#include "tx.h"

/* Drive one sweep pass over bfd_sessions at a caller-supplied time.
 *
 * The frame carries nothing but a __u64 nanosecond timestamp, which stands
 * in for the bpf_ktime_get_ns() that sweep_fire() would have read. That is
 * the whole reason this is testable: check_session takes its clock through
 * ctx rather than reading it, so a test can place "now" wherever it needs
 * relative to last_seen_ns.
 *
 * Going through bpf_for_each_map_elem rather than calling check_session
 * directly is deliberate. It is the same helper the real sweep uses, so a
 * verifier objection or a callback-convention change shows up here too,
 * and the test is not exercising a path that only exists for the test.
 */
SEC("xdp")
int sweep_once(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	/* test_run wants a plausible frame, so the timestamp sits after a
	 * dummy Ethernet header rather than at offset 0. */
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;

	__u64 *now = (void *)(eth + 1);

	if ((void *)(now + 1) > data_end)
		return XDP_ABORTED;

	__u64 t = *now;

	bpf_for_each_map_elem(&bfd_sessions, check_session, &t, 0);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
