// SPDX-License-Identifier: GPL-2.0
/* bfd_xdp_test.c - test-only entry point into the detection sweep.
 *
 * check_session() is a pure function of (map state, now), but it runs
 * only from a bpf_timer, and bpf_timer does not fire under
 * BPF_PROG_TEST_RUN. This gives the harness a way in.
 *
 * Not built into bfd_xdp.o and never loaded in production: a test entry
 * point in shipped bytecode is one a loader could attach by mistake, and
 * one more program for the verifier to accept.
 *
 * The include list below must match src/xdp/bfd_xdp.c exactly and in the
 * same order - maps.h before anything referencing a map by symbol,
 * sweep.h before tx.h - so the entry point is the only difference
 * between this object and the real one. Change one, change both.
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
#include "hmac_sha1.h"

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

/* The shared HMAC-SHA1, run through the kernel.
 *
 * Same header the engine compiles, same vectors hmac_run checks on the
 * host. Worth its own entry point rather than trusting the host result:
 * the BPF build is a different compilation with different inlining and
 * its own stack and verifier constraints, and it is the one that decides
 * whether an authenticated packet is accepted on the wire.
 *
 * Input and output live in a map because a BFD auth key is not packet
 * data - on the fast path it comes from the session's configuration, and
 * the message block is scratch the reflector assembles.
 */
struct hmac_scratch {
	__u8  kpad[SHA1_BLOCK_LEN];
	__u8  mblk[SHA1_BLOCK_LEN];
	__u8  out[SHA1_DIGEST_LEN];
	__u32 msglen;
	__u32 ok;
	__u8 tmp[SHA1_BLOCK_LEN];   /* hmac_sha1_blocks' working block */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct hmac_scratch);
} hmac_scratch SEC(".maps");

SEC("xdp")
int hmac_once(struct xdp_md *ctx)
{
	__u32 zero = 0;
	struct hmac_scratch *s = bpf_map_lookup_elem(&hmac_scratch, &zero);

	if (!s)
		return XDP_ABORTED;
	s->ok = hmac_sha1_blocks(s->kpad, s->mblk, s->msglen, s->out, s->tmp);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
