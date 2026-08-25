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
#include <linux/ipv6.h>
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

/* A single-hop IPv6 BFD control packet. */
static void build_v6(struct frame *f, uint8_t hlim, uint16_t dport,
		     const struct bfd_ctrl_pkt *bfd, unsigned int extra)
{
	static const unsigned char dmac[6] = { 0x02, 0, 0, 0, 0, 1 };
	static const unsigned char smac[6] = { 0x02, 0, 0, 0, 0, 2 };
	unsigned int payload = sizeof(*bfd) + extra;

	memset(f, 0, sizeof(*f));

	struct ethhdr *eth = (void *)f->b;
	memcpy(eth->h_dest, dmac, 6);
	memcpy(eth->h_source, smac, 6);
	eth->h_proto = htons(ETH_P_IPV6);

	struct ipv6hdr *ip6 = (void *)(eth + 1);
	ip6->version     = 6;
	ip6->payload_len = htons(sizeof(struct udphdr) + payload);
	ip6->nexthdr     = IPPROTO_UDP;
	ip6->hop_limit   = hlim;
	inet_pton(AF_INET6, "fd00::2", &ip6->saddr);
	inet_pton(AF_INET6, "fd00::1", &ip6->daddr);

	struct udphdr *udp = (void *)(ip6 + 1);
	udp->source = htons(49152);
	udp->dest   = htons(dport);
	udp->len    = htons(sizeof(*udp) + payload);
	udp->check  = 0xffff;   /* v6 requires one; the program rewrites it */

	memcpy(udp + 1, bfd, sizeof(*bfd));

	f->len = sizeof(*eth) + sizeof(*ip6) + sizeof(*udp) + payload;
}

/* Verify rather than recompute. Summing the pseudo-header, the UDP header
 * with its checksum field in place, and the payload must fold to 0xffff.
 * That property is independent of how tx.h produced the value, which is
 * the point: reimplementing the same 34-word fold here would only prove
 * the test agrees with itself. */
static int v6_udp_csum_ok(const unsigned char *frm, unsigned int len)
{
	const struct ethhdr *eth = (const void *)frm;
	const struct ipv6hdr *ip6 = (const void *)(eth + 1);
	const struct udphdr *udp = (const void *)(ip6 + 1);
	unsigned int ulen = ntohs(udp->len);
	uint32_t sum = 0;

	if (len < sizeof(*eth) + sizeof(*ip6) + ulen)
		return 0;

	const uint16_t *w = (const uint16_t *)&ip6->saddr;
	for (int i = 0; i < 16; i++)
		sum += w[i];
	sum += udp->len;
	sum += htons(IPPROTO_UDP);

	w = (const uint16_t *)udp;
	for (unsigned int i = 0; i < ulen / 2; i++)
		sum += w[i];
	if (ulen & 1)
		sum += ((const unsigned char *)udp)[ulen - 1];

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum == 0xffff;
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

/* ---------- map state ---------- */

static int cfg_fd = -1, sess_fd = -1;

/* Keys are built from the arriving frame's point of view: peer is the
 * source, local is the destination. Getting this backwards produces a
 * silent XDP_PASS rather than an error, so it is worth stating. */
static struct session_key key_v4(const char *peer, const char *local)
{
	struct session_key k = {0};
	__u32 p = inet_addr(peer), l = inet_addr(local);

	k.peer.b[10] = 0xff;  k.peer.b[11] = 0xff;
	k.local.b[10] = 0xff; k.local.b[11] = 0xff;
	memcpy(&k.peer.b[12], &p, 4);
	memcpy(&k.local.b[12], &l, 4);
	return k;
}

static void map_reset(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");

	bpf_map_delete_elem(cfg_fd, &k);
	bpf_map_delete_elem(sess_fd, &k);
}

/* A session the kernel is allowed to answer for. */
static void arm_session(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg = {0};
	struct session_state st = {0};

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = 255;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* v6 keys carry the address as-is; only v4 goes through the mapped
 * encoder. Same orientation: peer is the frame source. */
static struct session_key key_v6(const char *peer, const char *local)
{
	struct session_key k = {0};

	inet_pton(AF_INET6, peer, k.peer.b);
	inet_pton(AF_INET6, local, k.local.b);
	return k;
}

static void map_reset_v6(void)
{
	struct session_key k = key_v6("fd00::2", "fd00::1");

	bpf_map_delete_elem(cfg_fd, &k);
	bpf_map_delete_elem(sess_fd, &k);
}

static void arm_session_v6(void)
{
	struct session_key k = key_v6("fd00::2", "fd00::1");
	struct tx_cfg cfg = {0};
	struct session_state st = {0};

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = 255;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  v6 map update failed: %s\n", strerror(errno));
		fails++;
	}
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

/* An Up packet from an armed peer must be bounced, not passed. This is
 * the gate in bfd_xdp.c: cfg->enable and the peer at Init or better. */
static void case_bounce_v4(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	expect("bounce-v4-up", run_frame(&f, NULL, NULL), XDP_TX);
	map_reset();
}

/* The verdict says the program chose to bounce. This says the frame it
 * produced is the one tx.h describes. Checked field by field rather than
 * memcmp against a whole expected frame, so a failure names what moved. */
static void case_bounce_v4_frame(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned char out[FRAME_MAX];
	unsigned int out_len = 0;
	struct frame f;
	int v;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	v = run_frame(&f, out, &out_len);
	if (v != XDP_TX) {
		printf("FAIL %-40s no bounce to inspect\n", "bounce-v4-frame");
		fails++;
		map_reset();
		return;
	}

	const struct ethhdr *ie = (const void *)f.b;
	const struct ethhdr *oe = (const void *)out;
	const struct iphdr *ii = (const void *)(ie + 1);
	const struct iphdr *oi = (const void *)(oe + 1);
	const struct udphdr *ou = (const void *)(oi + 1);
	const struct bfd_ctrl_pkt *ob = (const void *)(ou + 1);
	unsigned int want_len = sizeof(*oe) + sizeof(*oi) + sizeof(*ou) + 24;
	int bad = 0;

#define CHK(cond, what) do { if (!(cond)) { \
	printf("     %s\n", what); bad = 1; } } while (0)

	CHK(out_len == want_len, "frame length not eth+ip+udp+24");
	CHK(!memcmp(oe->h_dest, ie->h_source, 6), "dest MAC is not the arriving source");
	CHK(!memcmp(oe->h_source, ie->h_dest, 6), "source MAC is not the arriving dest");
	CHK(oi->saddr == ii->daddr, "source IP is not the arriving dest");
	CHK(oi->daddr == ii->saddr, "dest IP is not the arriving source");
	CHK(oi->ttl == 255, "TTL is not 255");
	CHK(ntohs(oi->tot_len) == want_len - sizeof(*oe), "tot_len not updated");
	CHK(csum16(oi, sizeof(*oi), 0) == 0, "IP checksum does not verify");
	CHK(ntohs(ou->source) == BFD_SRC_PORT, "source port is not BFD_SRC_PORT");
	CHK(ntohs(ou->dest) == BFD_PORT_1HOP, "dest port is not the arriving port");
	CHK(ntohs(ou->len) == (int)(sizeof(*ou) + 24), "udp len not updated");
	CHK(ob->len == 24, "bfd len field is not 24");
	CHK((ob->flags >> 6) == ST_UP, "state is not Up");
	CHK(!(ob->flags & (BFD_F_POLL | BFD_F_FINAL)), "P or F set on a plain reply");
	CHK(ntohl(ob->my_disc) == 0x22222222, "my_disc not from tx_cfg");
	CHK(ntohl(ob->your_disc) == 0x11111111, "your_disc not from tx_cfg");
	CHK(ob->detect_mult == 3, "detect_mult not from tx_cfg");
#undef CHK

	if (bad) {
		printf("FAIL %-40s\n", "bounce-v4-frame");
		fails++;
	} else {
		printf("ok   %-40s %u bytes\n", "bounce-v4-frame", out_len);
	}
	map_reset();
}

/* The v6 bounce, and the only independent check the hand-rolled fold in
 * tx.h has ever had. */
static void case_bounce_v6_frame(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned char out[FRAME_MAX];
	unsigned int out_len = 0;
	struct frame f;
	int v;

	map_reset_v6();
	arm_session_v6();
	build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	v = run_frame(&f, out, &out_len);
	if (v != XDP_TX) {
		printf("FAIL %-40s want TX got %s\n", "bounce-v6-frame",
		       v < 0 ? "syscall-error" : verdict_str(v));
		fails++;
		map_reset_v6();
		return;
	}

	const struct ipv6hdr *oi = (const void *)(out + sizeof(struct ethhdr));
	const struct udphdr *ou = (const void *)(oi + 1);
	unsigned int want_len = sizeof(struct ethhdr) + sizeof(*oi) +
				sizeof(*ou) + 24;
	int bad = 0;

	if (out_len != want_len) {
		printf("     frame is %u bytes, want %u\n", out_len, want_len);
		bad = 1;
	}
	if (oi->hop_limit != 255) {
		printf("     hop limit is not 255\n");
		bad = 1;
	}
	if (ntohs(oi->payload_len) != (int)(sizeof(*ou) + 24)) {
		printf("     payload_len not updated\n");
		bad = 1;
	}
	if (ou->check == 0) {
		printf("     UDP checksum is zero, illegal in v6\n");
		bad = 1;
	}
	if (!v6_udp_csum_ok(out, out_len)) {
		printf("     UDP checksum does not verify\n");
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", "bounce-v6-frame");
		fails++;
	} else {
		printf("ok   %-40s %u bytes, csum 0x%04x\n", "bounce-v6-frame",
		       out_len, ntohs(ou->check));
	}
	map_reset_v6();
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

	cfg_fd  = bpf_object__find_map_fd_by_name(obj, "tx_config");
	sess_fd = bpf_object__find_map_fd_by_name(obj, "bfd_sessions");
	if (cfg_fd < 0 || sess_fd < 0) {
		fprintf(stderr, "maps not found in %s\n", path);
		return 1;
	}

	case_not_bfd();
	case_gtsm_v4();
	case_bounce_v4();
	case_bounce_v4_frame();
	case_bounce_v6_frame();

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
