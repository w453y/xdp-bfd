// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_run.c - run the XDP program in the kernel with no NIC and no testbed.
 *
 * BPF_PROG_TEST_RUN hands bfd_observer a synthetic frame and returns the
 * verdict plus the (possibly rewritten) frame, so the program can be tested
 * as what it is: a pure function of (frame bytes, map state) to (verdict,
 * frame bytes, map state). The injection matrix in tests/ reaches the same
 * program only through the wire and cannot set map state directly.
 *
 * This is the skeleton: object load, frame builder, two cases. The case
 * table it exists to carry is 03-testing.md Layer 1.
 *
 * Needs root. Build with `make tests/unit/xdp_run` and run from the repo
 * root so the default object path resolves.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bfd_shared.h"

static struct bpf_object *obj;
static int prog_fd = -1;
static int fails;

/* ---------- frame building ---------- */

/* Enough for an Ethernet + IPv4 + UDP + BFD control packet with room for
 * the trailing bytes some cases append. */
#define FRAME_MAX 256

struct frame {
	unsigned char b[FRAME_MAX];
	unsigned int len;
};

static uint16_t csum16(const void *p, int len, uint32_t seed)
{
	const uint16_t *w = p;
	uint32_t sum = seed;

	for (; len > 1; len -= 2)
		sum += *w++;
	if (len == 1)
		sum += *(const uint8_t *)w;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* A single-hop IPv4 BFD control packet. ttl is a parameter because GTSM is
 * the first thing worth asserting and the whole point is to vary it. */
static void build_v4(struct frame *f, uint8_t ttl, uint16_t dport,
		     const struct bfd_ctrl_pkt *bfd, unsigned int extra)
{
	static const unsigned char dmac[6] = { 0x02, 0, 0, 0, 0, 1 };
	static const unsigned char smac[6] = { 0x02, 0, 0, 0, 0, 2 };
	unsigned int payload = sizeof(*bfd) + extra;

	memset(f, 0, sizeof(*f));

	struct ethhdr *eth = (void *)f->b;
	memcpy(eth->h_dest, dmac, 6);
	memcpy(eth->h_source, smac, 6);
	eth->h_proto = htons(ETH_P_IP);

	struct iphdr *ip = (void *)(eth + 1);
	ip->version = 4;
	ip->ihl     = 5;
	ip->tot_len = htons(sizeof(*ip) + sizeof(struct udphdr) + payload);
	ip->ttl     = ttl;
	ip->protocol = IPPROTO_UDP;
	ip->saddr   = inet_addr("10.0.0.2");
	ip->daddr   = inet_addr("10.0.0.1");
	ip->check   = csum16(ip, sizeof(*ip), 0);

	struct udphdr *udp = (void *)(ip + 1);
	udp->source = htons(49152);
	udp->dest   = htons(dport);
	udp->len    = htons(sizeof(*udp) + payload);
	udp->check  = 0;   /* v4 UDP checksum is optional */

	memcpy(udp + 1, bfd, sizeof(*bfd));

	f->len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + payload;
}

/* A well-formed Up control packet. Cases mutate the copy they get. */
static struct bfd_ctrl_pkt ctrl_up(void)
{
	struct bfd_ctrl_pkt p = {0};

	p.vers_diag   = 1 << 5;
	p.flags       = ST_UP << 6;
	p.detect_mult = 3;
	p.len         = 24;
	p.my_disc     = htonl(0x11111111);
	p.your_disc   = htonl(0x22222222);
	p.min_tx      = htonl(10000);
	p.min_rx      = htonl(10000);
	p.min_echo_rx = 0;
	return p;
}

/* ---------- running ---------- */

static const char *verdict_str(int v)
{
	switch (v) {
	case XDP_ABORTED:  return "ABORTED";
	case XDP_DROP:     return "DROP";
	case XDP_PASS:     return "PASS";
	case XDP_TX:       return "TX";
	case XDP_REDIRECT: return "REDIRECT";
	default:           return "?";
	}
}

/* Returns the verdict, or -1 if the syscall itself failed. out/out_len
 * receive the returned frame when out is non-NULL. */
static int run_frame(const struct frame *f, unsigned char *out,
		     unsigned int *out_len)
{
	unsigned char buf[FRAME_MAX * 2] = {0};
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .data_in    = f->b,
		    .data_size_in = f->len,
		    .data_out   = buf,
		    .data_size_out = sizeof(buf),
		    .repeat     = 1);

	if (bpf_prog_test_run_opts(prog_fd, &topts)) {
		fprintf(stderr, "  test_run failed: %s\n", strerror(errno));
		return -1;
	}
	if (out) {
		unsigned int n = topts.data_size_out;

		if (n > FRAME_MAX)
			n = FRAME_MAX;
		memcpy(out, buf, n);
		*out_len = n;
	}
	return topts.retval;
}

static void expect(const char *name, int got, int want)
{
	if (got == want) {
		printf("ok   %-40s %s\n", name, verdict_str(want));
		return;
	}
	printf("FAIL %-40s want %s got %s\n", name, verdict_str(want),
	       got < 0 ? "syscall-error" : verdict_str(got));
	fails++;
}

/* ---------- cases ---------- */

/* Nothing to do with BFD. The program must not claim it. */
static void case_not_bfd(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	build_v4(&f, 255, 1234, &p, 0);
	expect("non-bfd-port-passes", run_frame(&f, NULL, NULL), XDP_PASS);
}

/* RFC 5881 s5: a single-hop control packet must arrive at TTL 255. The
 * reject must be XDP_DROP specifically, not XDP_PASS - that distinction is
 * the bug class the lab suite's m5 run found. */
static void case_gtsm_v4(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	build_v4(&f, 200, BFD_PORT_1HOP, &p, 0);
	expect("gtsm-v4-low-ttl-drops", run_frame(&f, NULL, NULL), XDP_DROP);
}

int main(void)
{
	const char *path = getenv("BFD_OBJ") ?: "bfd_xdp.o";

	obj = bpf_object__open_file(path, NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "load %s failed: %s\n", path, strerror(errno));
		fprintf(stderr, "(run as root, from the repo root)\n");
		return 1;
	}

	struct bpf_program *pr =
		bpf_object__find_program_by_name(obj, "bfd_observer");
	if (!pr) {
		fprintf(stderr, "bfd_observer not found in %s\n", path);
		return 1;
	}
	prog_fd = bpf_program__fd(pr);

	case_not_bfd();
	case_gtsm_v4();

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
