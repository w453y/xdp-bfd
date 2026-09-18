// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_fuzz.c - libFuzzer target for the XDP program.
 *
 * xdp_run.c covers the frames a person can enumerate. This targets what
 * nobody does: an arbitrary control payload over a valid envelope for a
 * configured session, so the fuzzer explores the header validation, the
 * demux, the auth section and the reply builder.
 *
 * The verifier already guarantees the program cannot crash or read out of
 * bounds in the kernel; ASAN here catches the harness reading a reply the
 * program built wrong. So the value is the invariants asserted after every
 * run, not a signal:
 *
 *   - a DROP leaves no trace: it must not refresh liveness (rx_pkts) or
 *     set the alive flag. That is the property spoofed traffic must not
 *     break.
 *   - an XDP_TX reply is a well-formed BFD control packet carrying our own
 *     discriminator, at TTL 255. That is the class the envelope bug
 *     (a frame going back out with a length that lied) fell in.
 *
 * Needs root: it loads bfd_xdp.o and drives it with BPF_PROG_TEST_RUN.
 *
 *     make FUZZ_CC=clang-21 tests/unit/xdp_fuzz
 *     sudo ./tests/unit/xdp_fuzz -runs=200000 corpus/
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bfd_shared.h"

#ifndef ST_UP
#define ST_UP 3
#endif

/* The BPF object is loaded once and kept for the whole run, so
 * LeakSanitizer would flag libbpf's allocations at exit. By design. */
const char *__lsan_default_options(void) { return "detect_leaks=0"; }

static int prog_fd = -1, cfg_fd = -1, sess_fd = -1, flags_fd = -1;

/* Our discriminator and the peer's, as configured below. */
#define MY_DISC   0x22222222u
#define PEER_DISC 0x11111111u

static struct session_key key_v4(const char *peer, const char *local)
{
	struct session_key k = {0};
	uint32_t p = inet_addr(peer), l = inet_addr(local);

	k.peer.b[10] = 0xff;  k.peer.b[11] = 0xff;
	k.local.b[10] = 0xff; k.local.b[11] = 0xff;
	memcpy(&k.peer.b[12], &p, 4);
	memcpy(&k.local.b[12], &l, 4);
	return k;
}

static struct session_key g_key;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const char *path = getenv("BFD_OBJ") ?: "bfd_xdp.o";
	struct bpf_object *obj;
	struct bpf_program *pr;
	(void)argc; (void)argv;

	obj = bpf_object__open_file(path, NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "load %s failed (run as root, repo root)\n", path);
		exit(1);
	}
	pr = bpf_object__find_program_by_name(obj, "bfd_observer");
	prog_fd = pr ? bpf_program__fd(pr) : -1;
	cfg_fd  = bpf_object__find_map_fd_by_name(obj, "tx_config");
	sess_fd = bpf_object__find_map_fd_by_name(obj, "bfd_sessions");
	flags_fd = bpf_object__find_map_fd_by_name(obj, "prog_flags");
	if (prog_fd < 0 || cfg_fd < 0 || sess_fd < 0 || flags_fd < 0) {
		fprintf(stderr, "prog/maps not found in %s\n", path);
		exit(1);
	}

	/* Not promiscuous: a configured session, engine mode. */
	uint32_t zero = 0, flags = 0;
	bpf_map_update_elem(flags_fd, &zero, &flags, BPF_ANY);

	g_key = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg = {0};
	cfg.enable = 1;
	cfg.my_disc = MY_DISC;
	cfg.your_disc = PEER_DISC;
	cfg.min_tx_us = 50000;
	cfg.min_rx_us = 50000;
	cfg.state = ST_UP;
	cfg.mult = 3;
	cfg.min_ttl = 255;
	if (bpf_map_update_elem(cfg_fd, &g_key, &cfg, BPF_ANY)) {
		fprintf(stderr, "cfg install failed\n");
		exit(1);
	}
	return 0;
}

/* A valid v4 envelope to the single-hop BFD port for the configured pair,
 * at TTL 255. The fuzzer's bytes become the BFD payload. */
#define ETH 14
#define IPH 20
#define UDPH 8
#define HDRS (ETH + IPH + UDPH)
#define PAYMAX 256

static void build_envelope(unsigned char *f, const uint8_t *pl, size_t pn)
{
	struct ethhdr *eth = (void *)f;
	struct iphdr *ip = (void *)(f + ETH);
	struct udphdr *udp = (void *)(f + ETH + IPH);
	static const unsigned char dmac[6] = { 0x02, 0, 0, 0, 0, 1 };
	static const unsigned char smac[6] = { 0x02, 0, 0, 0, 0, 2 };

	memset(f, 0, HDRS);
	memcpy(eth->h_dest, dmac, 6);
	memcpy(eth->h_source, smac, 6);
	eth->h_proto = htons(ETH_P_IP);

	ip->version = 4; ip->ihl = 5; ip->ttl = 255; ip->protocol = IPPROTO_UDP;
	ip->tot_len = htons(IPH + UDPH + pn);
	ip->saddr = inet_addr("10.0.0.2");   /* peer -> us */
	ip->daddr = inet_addr("10.0.0.1");

	udp->source = htons(49152);
	udp->dest = htons(BFD_PORT_1HOP);
	udp->len = htons(UDPH + pn);

	memcpy(f + HDRS, pl, pn);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned char frame[HDRS + PAYMAX];
	unsigned char out[HDRS + PAYMAX + 64];
	struct session_state st = {0};
	size_t pn = size > PAYMAX ? PAYMAX : size;

	if (prog_fd < 0)
		return 0;

	/* A known baseline every run: a live Up session with no packet yet
	 * counted, so rx_pkts and alive read zero and a trace is visible. */
	st.remote_state = ST_UP;
	st.remote_disc = PEER_DISC;
	st.local_disc = MY_DISC;
	st.detect_mult = 3;
	bpf_map_update_elem(sess_fd, &g_key, &st, BPF_ANY);

	build_envelope(frame, data, pn);

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = frame,
		.data_size_in = (uint32_t)(HDRS + pn),
		.data_out = out,
		.data_size_out = sizeof(out),
		.repeat = 1,
	);
	if (bpf_prog_test_run_opts(prog_fd, &topts))
		return 0;               /* a run error is not a program bug */

	if (bpf_map_lookup_elem(sess_fd, &g_key, &st))
		return 0;

	if (topts.retval == 1 /* XDP_DROP */) {
		/* A dropped frame must leave no trace of having arrived. */
		if (st.rx_pkts != 0 || st.alive != 0) {
			fprintf(stderr, "INVARIANT: DROP refreshed liveness "
				"(rx_pkts=%llu alive=%llu)\n",
				(unsigned long long)st.rx_pkts,
				(unsigned long long)st.alive);
			abort();
		}
	} else if (topts.retval == 3 /* XDP_TX */) {
		/* The reply must be a control packet carrying our own
		 * discriminator, at TTL 255, that our own receive path would
		 * accept. */
		if (topts.data_size_out < HDRS + BFD_MIN_LEN) {
			fprintf(stderr, "INVARIANT: XDP_TX reply too short (%u)\n",
				topts.data_size_out);
			abort();
		}
		struct iphdr *oi = (void *)(out + ETH);
		struct udphdr *ou = (void *)(out + ETH + IPH);
		struct bfd_ctrl_pkt *ob = (void *)(out + HDRS);

		if ((ob->vers_diag >> 5) != 1 || ob->len < BFD_MIN_LEN) {
			fprintf(stderr, "INVARIANT: XDP_TX reply not BFD "
				"(vers_diag=0x%02x len=%u)\n",
				ob->vers_diag, ob->len);
			abort();
		}
		if (ntohl(ob->my_disc) != MY_DISC) {
			fprintf(stderr, "INVARIANT: XDP_TX reply my_disc=0x%08x, "
				"want 0x%08x\n", ntohl(ob->my_disc), MY_DISC);
			abort();
		}
		if (oi->ttl != 255) {
			fprintf(stderr, "INVARIANT: XDP_TX reply ttl=%u\n", oi->ttl);
			abort();
		}
		if (ntohs(ou->len) != UDPH + ob->len) {
			fprintf(stderr, "INVARIANT: XDP_TX udp->len %u != %u\n",
				ntohs(ou->len), UDPH + ob->len);
			abort();
		}
	}
	return 0;
}
