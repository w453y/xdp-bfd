// SPDX-License-Identifier: GPL-2.0
/* bfd_xdp_test.c - test-only entry points: one sweep pass, and the shared
 * HMAC.
 *
 * check_session only runs from a bpf_timer, which does not fire under
 * BPF_PROG_TEST_RUN. Never part of bfd_xdp.o. The include list must match
 * src/xdp/bfd_xdp.c exactly, in order. */

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

/* One sweep pass at the time carried in the frame, a __u64 after a dummy
 * Ethernet header, through bpf_for_each_map_elem like the real sweep. */
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

/* The shared HMAC-SHA1 compiled for BPF, checked on the host vectors. Input
 * and output go through a map, since keys are not packet data. */
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
