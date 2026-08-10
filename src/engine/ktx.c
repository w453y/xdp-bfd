// SPDX-License-Identifier: GPL-2.0
/* ktx.c - kernel-TX mirror: XDP attach, BPF map fds, tx_cfg push.
 *
 * tx_cfg has a single writer (us). The kernel acks a Poll sequence
 * through session_state.final_seq rather than touching tx_cfg.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bfd_shared.h"
#include "util.h"
#include "session.h"
#include "ktx.h"
#include "dplane.h"
#include "fsm.h"
#include "echo_tx.h"

int use_ktx = 0;
int cfg_fd = -1, sess_fd = -1, echo_peers_fd = -1;
int echo_disc_fd = -1;
static int flags_fd = -1;
static struct bpf_object *bpf_obj;

/* ---------- BPF plumbing ---------- */
int ktx_attach(const char *ifname)
{
	int ifindex = if_nametoindex(ifname);
	if (!ifindex) { perror("ifname"); return -1; }

	bpf_obj = bpf_object__open_file("bfd_xdp.o", NULL);
	if (!bpf_obj || bpf_object__load(bpf_obj)) {
		fprintf(stderr, "bfd_xdp.o load failed\n");
		return -1;
	}
	struct bpf_program *pr =
		bpf_object__find_program_by_name(bpf_obj, "bfd_observer");
	if (bpf_xdp_attach(ifindex, bpf_program__fd(pr),
			   XDP_FLAGS_DRV_MODE, NULL)) {
		fprintf(stderr, "native XDP attach failed on %s\n", ifname);
		return -1;
	}
	cfg_fd  = bpf_object__find_map_fd_by_name(bpf_obj, "tx_config");
	sess_fd = bpf_object__find_map_fd_by_name(bpf_obj, "bfd_sessions");
	echo_peers_fd = bpf_object__find_map_fd_by_name(bpf_obj, "echo_peers");
	echo_disc_fd = bpf_object__find_map_fd_by_name(bpf_obj, "echo_disc");
	flags_fd = bpf_object__find_map_fd_by_name(bpf_obj, "prog_flags");
	printf("kernel-tx: XDP attached to %s\n", ifname);

	return 0;
}

/* prog_flags bit 1 tells the XDP parser that at least one multihop
 * session exists, so it must defer the TTL verdict instead of dropping
 * everything below 255 outright. Clearing it again restores the cheap
 * early filter for single-hop-only deployments. */
void ktx_update_mhop_flag(void)
{
	if (flags_fd < 0)
		return;

	int mhop = 0;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].min_ttl &&
		    sessions[i].min_ttl < 255) {
			mhop = 1;
			break;
		}

	__u32 zero = 0, fl = 0;
	bpf_map_lookup_elem(flags_fd, &zero, &fl);
	__u32 want = mhop ? (fl | 2u) : (fl & ~2u);
	if (want != fl)
		bpf_map_update_elem(flags_fd, &zero, &want, 0);
}

void ktx_mirror(struct session *s)
{
	if (!use_ktx)
		return;
	struct tx_cfg c = {
		.echo_iv_us = s->echo_tx_us,
		.min_echo_rx_us = s->min_echo_rx_us,
		.min_ttl   = s->min_ttl,
		.enable    = (s->state == ST_UP),
		.my_disc   = s->wire_disc,
		.your_disc = s->rdisc,
		.min_tx_us = s->min_tx_us,
		.min_rx_us = s->min_rx_us,
		.src_port  = (__u16)(SRC_PORT + (s - sessions)),
		.state     = s->state,
		.diag      = s->diag,
		.mult      = s->detect_mult,
		.poll      = (s->polling && s->state == ST_UP) ? 1 : 0,
		.poll_seq  = s->poll_seq,
	};
	if (s->pushed_valid && !memcmp(&c, &s->pushed_cfg, sizeof(c)))
		return;
	struct session_key k = {};
	k.peer  = s->peer;
	k.local = s->local;
	bpf_map_update_elem(cfg_fd, &k, &c, 0);
	s->pushed_cfg = c;
	s->pushed_valid = 1;
}

void ktx_clear(struct session *s)
{
	if (!use_ktx)
		return;
	struct session_key k = {};
	k.peer  = s->peer;
	k.local = s->local;
	bpf_map_delete_elem(cfg_fd, &k);
	bpf_map_delete_elem(sess_fd, &k);
	if (echo_peers_fd >= 0)
		bpf_map_delete_elem(echo_peers_fd, &s->peer);
	if (echo_disc_fd >= 0 && s->wire_disc)
		bpf_map_delete_elem(echo_disc_fd, &s->wire_disc);
	s->min_ttl = 0;
	ktx_update_mhop_flag();
}


void ktx_poll_map(struct session *s, uint64_t t)
{
	if (!use_ktx || s->state != ST_UP)
		return;
	struct session_key k = {};
	k.peer  = s->peer;
	k.local = s->local;
	struct session_state ms;
	if (bpf_map_lookup_elem(sess_fd, &k, &ms))
		return;
	if (ms.last_seen_ns / 1000 > s->last_rx_us)
		s->last_rx_us = ms.last_seen_ns / 1000;
	if (ms.detect_iv_us)
		s->detect_iv_us = ms.detect_iv_us;
	if (ms.mac_valid) {
		memcpy(s->peer_mac, ms.peer_mac, 6);
		s->mac_valid = 1;
	}
	/* Our echo returned. The arrival stamp is the kernel's, taken in
	 * softirq at RX, so this is wire RTT and not poll latency. */
	if (s->echo_sent_us && ms.echo_last_nonce == s->echo_nonce &&
	    ms.echo_last_seen_ns) {
		uint64_t arr = ms.echo_last_seen_ns / 1000;
		if (arr > s->echo_sent_us) {
			uint64_t rtt = arr - s->echo_sent_us;
			s->echo_rtt_last_us = rtt;
			if (!s->echo_rtt_min_us || rtt < s->echo_rtt_min_us)
				s->echo_rtt_min_us = rtt;
			if (rtt > s->echo_rtt_max_win_us)
				s->echo_rtt_max_win_us = rtt;
			if (rtt > s->echo_rtt_max_us)
				s->echo_rtt_max_us = rtt;
			s->echo_rtt_sum_us += rtt;
			s->echo_rtt_n++;
		}
		s->echo_rx_pkts++;
		s->echo_sent_us = 0;   /* no longer outstanding */
	}
	s->echo_alive_k = ms.echo_alive;
	if (s->polling && ms.final_seq == s->poll_seq) {
		/* Kernel acked the peer's F for this Poll sequence via
		 * final_seq; end the poll and mirror poll=0 down. tx_cfg
		 * has a single writer (us), so the old read-back dance
		 * and the pushed_cfg fixup are gone. */
		s->polling = 0;
		s->applied_tx_us = s->min_tx_us;
		ktx_mirror(s);
	}
	if (ms.min_tx_us && (ms.min_tx_us != s->r_min_tx ||
			     ms.min_rx_us != s->r_min_rx ||
			     ms.remote_min_echo_us != s->r_min_echo)) {
		s->r_min_tx = ms.min_tx_us;
		s->r_min_rx = ms.min_rx_us;
		s->r_min_echo = ms.remote_min_echo_us;
		dp_notify_state(s);
	}
	if (ms.remote_state == ST_DOWN)
		state_transition(s, ST_DOWN, 3, t, "map: peer sent Down");
}
