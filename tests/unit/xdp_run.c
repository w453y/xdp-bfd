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

/* Read a session's kernel-owned state back after a run. Everything above
 * asserts on the returned frame; the map side is the other half of what
 * the program does, and nothing has checked it yet. */
static int read_state(const struct session_key *k, struct session_state *out)
{
	if (bpf_map_lookup_elem(sess_fd, k, out)) {
		printf("     no session_state for that key: %s\n", strerror(errno));
		return 0;
	}
	return 1;
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

/* A peer frame carrying more than 24 bytes of BFD (auth section, trailer)
 * must not go back out with the extra bytes attached. tx.h trims with
 * bpf_xdp_adjust_tail after rewriting.
 *
 * The v6 arm is the one worth having. The checksum fold runs BEFORE the
 * trim, because adjust_tail invalidates the pointers it reads, so the
 * fold's claim that it "never reads past payload byte 24, which survives
 * the trim" is only true if the trim removes exactly the excess. This is
 * the only input that can tell. */
static void case_trim(int v6, unsigned int extra)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned char out[FRAME_MAX];
	unsigned int out_len = 0;
	char name[64];
	struct frame f;
	int v, bad = 0;

	snprintf(name, sizeof(name), "trim-%s-plus-%u", v6 ? "v6" : "v4", extra);

	if (v6) {
		map_reset_v6();
		arm_session_v6();
		build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	} else {
		map_reset();
		arm_session();
		build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	}

	v = run_frame(&f, out, &out_len);
	if (v != XDP_TX) {
		printf("FAIL %-40s want TX got %s\n", name,
		       v < 0 ? "syscall-error" : verdict_str(v));
		fails++;
		goto out;
	}

	unsigned int l3 = v6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
	unsigned int want_len = sizeof(struct ethhdr) + l3 +
				sizeof(struct udphdr) + 24;
	const struct udphdr *ou =
		(const void *)(out + sizeof(struct ethhdr) + l3);

	if (out_len != want_len) {
		printf("     frame is %u bytes, want %u (not trimmed)\n",
		       out_len, want_len);
		bad = 1;
	}
	if (ntohs(ou->len) != (int)(sizeof(*ou) + 24)) {
		printf("     udp len is %u, want %zu\n", ntohs(ou->len),
		       sizeof(*ou) + 24);
		bad = 1;
	}
	if (v6) {
		const struct ipv6hdr *oi =
			(const void *)(out + sizeof(struct ethhdr));

		if (ntohs(oi->payload_len) != (int)(sizeof(*ou) + 24)) {
			printf("     payload_len is %u, want %zu\n",
			       ntohs(oi->payload_len), sizeof(*ou) + 24);
			bad = 1;
		}
		if (!v6_udp_csum_ok(out, out_len)) {
			printf("     UDP checksum does not verify after trim\n");
			bad = 1;
		}
	} else {
		const struct iphdr *oi =
			(const void *)(out + sizeof(struct ethhdr));

		if (ntohs(oi->tot_len) != (int)(l3 + sizeof(*ou) + 24)) {
			printf("     tot_len is %u, want %zu\n", ntohs(oi->tot_len),
			       l3 + sizeof(*ou) + 24);
			bad = 1;
		}
		if (csum16(oi, sizeof(*oi), 0) != 0) {
			printf("     IP checksum does not verify after trim\n");
			bad = 1;
		}
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s %u bytes\n", name, out_len);
	}
out:
	if (v6)
		map_reset_v6();
	else
		map_reset();
}

/* RFC 5880 s6.8.4 poll termination. tx_cfg is userspace-owned, so the
 * kernel acks the peer's F by writing the sequence into kernel-owned
 * final_seq rather than clearing cfg->poll in place. Guard is
 * cfg->poll && incoming F, so all three arms below are reachable. */
static void case_poll_final(uint8_t in_flags, uint32_t cfg_poll,
			    uint32_t poll_seq, uint32_t want_seq,
			    const char *name)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state st = {0};
	struct tx_cfg cfg = {0};
	struct frame f;

	map_reset();

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = 255;
	cfg.poll      = cfg_poll;
	cfg.poll_seq  = poll_seq;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		printf("FAIL %-40s map setup: %s\n", name, strerror(errno));
		fails++;
		return;
	}

	p.flags |= in_flags;
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	run_frame(&f, NULL, NULL);

	struct session_state after = {0};
	if (!read_state(&k, &after)) {
		printf("FAIL %-40s\n", name);
		fails++;
		map_reset();
		return;
	}

	if (after.final_seq != want_seq) {
		printf("     final_seq is %u, want %u\n", after.final_seq,
		       want_seq);
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s final_seq %u\n", name, after.final_seq);
	}
	map_reset();
}

/* Liveness and the RX counter are map-side effects nothing has checked. */
static void case_rx_state(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after = {0};
	struct frame f;
	int bad = 0;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	run_frame(&f, NULL, NULL);

	if (!read_state(&k, &after)) {
		printf("FAIL %-40s\n", "rx-updates-state");
		fails++;
		map_reset();
		return;
	}

	if (!after.last_seen_ns) {
		printf("     last_seen_ns not set\n");
		bad = 1;
	}
	if (after.rx_pkts != 1) {
		printf("     rx_pkts is %llu, want 1\n",
		       (unsigned long long)after.rx_pkts);
		bad = 1;
	}
	if (after.alive != 1) {
		printf("     alive is %u, want 1\n", after.alive);
		bad = 1;
	}
	if (after.remote_disc != 0x11111111) {
		printf("     remote_disc is %08x\n", after.remote_disc);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", "rx-updates-state");
		fails++;
	} else {
		printf("ok   %-40s rx %llu alive %u\n", "rx-updates-state",
		       (unsigned long long)after.rx_pkts, after.alive);
	}
	map_reset();
}

/* bfd_ctrl_check's reject conditions, one case each, both families.
 *
 * Two assertions per case, not one. The verdict must be XDP_DROP
 * specifically: a reject that returns XDP_PASS leaks the packet to the
 * userspace socket, which is the class the lab suite's m5 run found and
 * this pins permanently. And the session's rx_pkts must not move, because
 * a rejected packet must not refresh liveness - a peer sending garbage
 * would otherwise hold the session up forever. */
static void case_malformed(int v6, const char *name,
			   void (*mutate)(struct bfd_ctrl_pkt *), int want_v)
{
	struct session_key k = v6 ? key_v6("fd00::2", "fd00::1")
			  : key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after = {0};
	char full[80];
	struct frame f;
	int v, bad = 0;

	snprintf(full, sizeof(full), "%s-%s", name, v6 ? "v6" : "v4");

	if (v6) { map_reset_v6(); arm_session_v6(); }
	else    { map_reset();    arm_session();    }

	mutate(&p);
	if (v6)
		build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	else
		build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);

	v = run_frame(&f, NULL, NULL);
	if (v != want_v) {
		printf("     verdict %s, want %s\n",
		       v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want_v));
		bad = 1;
	}
	if (read_state(&k, &after) && after.rx_pkts != 0) {
		printf("     rx_pkts is %llu, a reject refreshed liveness\n",
		       (unsigned long long)after.rx_pkts);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", full);
		fails++;
	} else {
		printf("ok   %-40s %s, no state write\n", full,
		       verdict_str(want_v));
	}

	if (v6) map_reset_v6(); else map_reset();
}

static void mut_version(struct bfd_ctrl_pkt *p)  { p->vers_diag = (2 << 5); }
static void mut_len_short(struct bfd_ctrl_pkt *p){ p->len = 23; }
static void mut_len_long(struct bfd_ctrl_pkt *p) { p->len = 200; }
static void mut_mult_zero(struct bfd_ctrl_pkt *p){ p->detect_mult = 0; }
static void mut_disc_zero(struct bfd_ctrl_pkt *p){ p->my_disc = 0; }
static void mut_auth(struct bfd_ctrl_pkt *p)     { p->flags |= BFD_F_AUTH; }
static void mut_mp(struct bfd_ctrl_pkt *p)       { p->flags |= BFD_F_MP; }

static void run_malformed_matrix(void)
{
	for (int v6 = 0; v6 < 2; v6++) {
		case_malformed(v6, "malformed-version",   mut_version, XDP_PASS);
		case_malformed(v6, "malformed-len-short", mut_len_short, XDP_PASS);
		case_malformed(v6, "malformed-len-long",  mut_len_long, XDP_PASS);
		case_malformed(v6, "malformed-mult-zero", mut_mult_zero, XDP_PASS);
		case_malformed(v6, "malformed-disc-zero", mut_disc_zero, XDP_PASS);
		case_malformed(v6, "unsupported-auth",    mut_auth, XDP_DROP);
		case_malformed(v6, "unsupported-mp",      mut_mp, XDP_DROP);
	}
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
	case_trim(0, 8);
	case_trim(1, 8);
	case_trim(0, 64);
	case_trim(1, 64);
	case_rx_state();
	case_poll_final(BFD_F_FINAL, 1, 7, 7, "poll-final-acks");
	case_poll_final(BFD_F_FINAL, 0, 7, 0, "poll-final-no-poll-no-ack");
	case_poll_final(0, 1, 7, 0, "poll-plain-packet-no-ack");
	run_malformed_matrix();

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
