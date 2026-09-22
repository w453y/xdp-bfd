// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_run.c - the XDP program under BPF_PROG_TEST_RUN, as a function of
 * (frame, map state) to (verdict, frame, map state). No NIC or testbed.
 *
 * Needs root. Run from the repo root so the default object path resolves.
 *
 *     make test-xdp
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
#include <time.h>
#include "detect_vectors.h"
#include "hmac_sha1.h"
#include "bfd_auth.h"
#include "hmac_vectors.h"

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


static int cfg_fd = -1, sess_fd = -1, stats_fd = -1;
static int tune_fd = -1, hb_fd = -1;
static int flags_fd = -1;
static int echo_peers_fd = -1, echo_disc_fd = -1;
static struct bpf_object *sweep_obj;
static int sweep_prog_fd = -1, sweep_sess_fd = -1, sweep_cfg_fd = -1;
static int hmac_prog_fd = -1, hmac_map_fd = -1;
#define FLAG_PROMISC	1u
#define FLAG_MHOP	2u
/* Local detect multiplier for the next armed session; cases vary it to
 * show the replay window uses the packet's Detect Mult. */
static __u8 arm_local_mult = 3;
/* Second key in the accept set, as a rollover leaves; 0 means none. */
static __u8 arm_extra_keyid;
static const char *arm_extra_key = "";

#include "xdp/harness.c"
#include "xdp/t_parse.c"
#include "xdp/t_tx.c"
#include "xdp/t_echo.c"
#include "xdp/t_auth.c"
#include "xdp/t_sweep.c"

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
	stats_fd = bpf_object__find_map_fd_by_name(obj, "bfd_stats");
	tune_fd = bpf_object__find_map_fd_by_name(obj, "tunables");
	hb_fd = bpf_object__find_map_fd_by_name(obj, "heartbeat");
	flags_fd = bpf_object__find_map_fd_by_name(obj, "prog_flags");
	echo_peers_fd = bpf_object__find_map_fd_by_name(obj, "echo_peers");
	echo_disc_fd = bpf_object__find_map_fd_by_name(obj, "echo_disc");
	if (cfg_fd < 0 || sess_fd < 0) {
		fprintf(stderr, "maps not found in %s\n", path);
		return 1;
	}

	sweep_obj = bpf_object__open_file("tests/unit/bfd_xdp_test.o", NULL);
	if (sweep_obj && !bpf_object__load(sweep_obj)) {
		struct bpf_program *sp =
			bpf_object__find_program_by_name(sweep_obj, "sweep_once");

		if (sp) {
			sweep_prog_fd = bpf_program__fd(sp);
			sweep_sess_fd = bpf_object__find_map_fd_by_name(sweep_obj,
								"bfd_sessions");
			sweep_cfg_fd = bpf_object__find_map_fd_by_name(sweep_obj,
							       "tx_config");
			sp = bpf_object__find_program_by_name(sweep_obj,
							      "hmac_once");
			if (sp) {
				hmac_prog_fd = bpf_program__fd(sp);
				hmac_map_fd = bpf_object__find_map_fd_by_name(
						sweep_obj, "hmac_scratch");
			}
		}
	} else {
		fprintf(stderr, "sweep object not loaded: %s\n", strerror(errno));
	}

	case_not_bfd();
	case_gtsm_v4();
	case_detect_vectors();
	case_gtsm_v6();
	case_deferred_gtsm();
	case_unknown_session();
	case_v6_exthdr();
	case_auth_ratelimit();
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
	run_demux_matrix();
	run_frag_matrix();
	run_echo_matrix();
	run_echo_v6_matrix();
	case_bad_envelope("envelope-udp-len-overruns-frame", 0);
	case_bad_envelope("envelope-ip-len-overruns-frame", 1);
	case_bounce_envelope_is_ours();
	case_ip_options("ip-options-bfd-port", BFD_PORT_1HOP, XDP_DROP, 1);
	case_ip_options("ip-options-other-port", 1234, XDP_PASS, 0);
	case_ip_options_lying();
	case_not_bfd_ttl(1);
	case_not_bfd_ttl(64);
	case_not_bfd_ttl(128);
	case_not_bfd_ttl(255);
	case_not_bfd_v6_hlim(1);
	case_not_bfd_v6_hlim(64);
	case_not_bfd_v6_hlim(255);
	run_sweep_matrix();

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
