// SPDX-License-Identifier: GPL-2.0
/* ktx.c - mirror sessions into the program's maps and read them back. tx_cfg
 * has one writer, us; the kernel acks a Poll through session_state.final_seq.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bfd_shared.h"
#include "util.h"
#include "log.h"
#include "session.h"
#include "ktx.h"
#include "dplane.h"
#include "fsm.h"
#include "echo_tx.h"

static struct ring_buffer *sweep_rb;

int use_ktx;
/* bfd_sessions, batch-fetched once per pass. */
static struct session_key poll_keys[MAX_SESSIONS];
static struct session_state poll_vals[MAX_SESSIONS];
static __u32 poll_n;
static int poll_batch_unsupported;

/* For the stats dump. */
const char *ktx_poll_mode(void)
{
	return poll_batch_unsupported ? "single" : "batch";
}

/* A detection verdict from the sweep, stamped with the kernel's time.
 * fsm_detect still covers sessions the fast path does not carry.
 */
static int on_sweep_event(void *ctx, void *data, size_t len)
{
	const struct bfd_event *ev = data;
	struct session *s;
	uint64_t decided_us, now;

	(void)ctx;
	if (len < sizeof(*ev) || ev->event != 0)
		return 0; /* ALIVE is in the map already */

	s = sess_by_addr(&ev->key.peer, &ev->key.local);
	if (!s || !s->used)
		return 0;
	if (s->state != ST_UP && s->state != ST_INIT)
		return 0; /* already down, or never up */

	/* A packet arrived after the sweep looked. */
	decided_us = ev->last_seen_ns / 1000;
	if (s->last_rx_us > decided_us)
		return 0;

	now = now_us();
	decided_us = ev->ts_ns / 1000;
	s->last_detect_lag_us = now > decided_us ? (uint32_t)(now - decided_us) : 0;
	s->kernel_detects++;

	state_transition(s, ST_DOWN, 1, decided_us, "detect timeout (sweep)");
	return 0;
}

void ktx_events_init(int map_fd)
{
	if (map_fd >= 0)
		sweep_rb = ring_buffer__new(map_fd, on_sweep_event, NULL, NULL);
	if (!sweep_rb)
		log_err("kernel-tx: no sweep event ring, detection falls back to the loop\n");
}

int ktx_events_fd(void)
{
	return sweep_rb ? ring_buffer__epoll_fd(sweep_rb) : -1;
}

void ktx_drain_events(void)
{
	if (sweep_rb)
		ring_buffer__consume(sweep_rb);
}


void ktx_poll_all(void)
{
	poll_n = 0;
	if (!use_ktx || sess_fd < 0)
		return;

	__u32 count = MAX_SESSIONS;
	void *in = NULL, *out = NULL;

	LIBBPF_OPTS(bpf_map_batch_opts, bopts);

	if (poll_batch_unsupported)
		return;
	if (bpf_map_lookup_batch(sess_fd, &in, &out, poll_keys, poll_vals, &count, &bopts) &&
	    errno != ENOENT) {
		if (errno == EINVAL || errno == EOPNOTSUPP) {
			poll_batch_unsupported = 1;
			log_err("kernel-tx: batch map lookup unavailable (%s), falling back to one lookup per session\n",
				strerror(errno));
		}
		return;
	}
	poll_n = count;
}

static const struct session_state *poll_find(const struct session *s)
{
	for (__u32 i = 0; i < poll_n; i++)
		if (!memcmp(&poll_keys[i].peer, &s->peer, sizeof(s->peer)) &&
		    !memcmp(&poll_keys[i].local, &s->local, sizeof(s->local)))
			return &poll_vals[i];
	return NULL;
}

/* prog_flags bit 1: a multihop session exists, so the parser defers the TTL
 * check.
 */
void ktx_update_mhop_flag(void)
{
	if (ktx_flags_fd < 0)
		return;

	int mhop = 0;

	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].min_ttl && sessions[i].min_ttl < 255) {
			mhop = 1;
			break;
		}

	__u32 zero = 0, fl = 0;

	bpf_map_lookup_elem(ktx_flags_fd, &zero, &fl);
	__u32 want = mhop ? (fl | 2u) : (fl & ~2u);

	if (want != fl)
		bpf_map_update_elem(ktx_flags_fd, &zero, &want, 0);
}

void ktx_mirror(struct session *s)
{
	if (!use_ktx)
		return;
	struct tx_cfg c;
	struct session_key k;

	ktx_cfg_for(s, (int64_t)time(NULL), &c, &k);

	if (!ktx_push_needed(s, &c, &k))
		return;

	/* Cache it only if the update landed. */
	if (bpf_map_update_elem(ktx_cfg_fd, &k, &c, 0)) {
		log_err("ktx: lid=%u tx_config push failed: %s\n", s->lid, strerror(errno));
		s->pushed_valid = 0;
		return;
	}
	s->pushed_cfg = c;
	s->pushed_key = k;
	s->pushed_valid = 1;
}

/* Keyed on peer alone, so sessions share entries; recomputed, not refcounted.
 * skip is the session being torn down.
 */
void echo_peer_refresh(const struct bfd_addr *peer, struct session *skip)
{
	__u8 one = 1;
	int wanted = 0;

	if (echo_peers_fd < 0)
		return;
	for (int i = 0; i < MAX_SESSIONS; i++) {
		struct session *o = &sessions[i];

		if (!o->used || o == skip || !o->echo_on)
			continue;
		if (!memcmp(&o->peer, peer, sizeof(*peer))) {
			wanted = 1;
			break;
		}
	}
	if (wanted)
		bpf_map_update_elem(echo_peers_fd, peer, &one, 0);
	else
		bpf_map_delete_elem(echo_peers_fd, peer);
}

/* Separate from ktx_clear so an address change can drop the old key. */
void ktx_clear_key(const struct bfd_addr *peer, const struct bfd_addr *local, uint32_t wire_disc)
{
	if (!use_ktx)
		return;
	struct session_key k = {};

	k.peer = *peer;
	k.local = *local;
	bpf_map_delete_elem(ktx_cfg_fd, &k);
	bpf_map_delete_elem(sess_fd, &k);
	if (echo_disc_fd >= 0 && wire_disc)
		bpf_map_delete_elem(echo_disc_fd, &wire_disc);
}

void ktx_clear(struct session *s)
{
	if (!use_ktx)
		return;
	ktx_clear_key(&s->peer, &s->local, s->wire_disc);
	echo_peer_refresh(&s->peer, s);
	s->min_ttl = 0;
	ktx_update_mhop_flag();
}


/* 0 if unavailable. */
void ktx_session_counters(const struct session *s, uint64_t *rx, uint64_t *tx)
{
	struct session_key k = {};
	struct session_state ms;

	*rx = 0;
	*tx = 0;
	if (!use_ktx || sess_fd < 0)
		return;

	k.peer = s->peer;
	k.local = s->local;
	if (!bpf_map_lookup_elem(sess_fd, &k, &ms)) {
		*rx = ms.rx_pkts;
		*tx = ms.tx_pkts;
	}
}

void ktx_poll_map(struct session *s, uint64_t t)
{
	struct session_state ms;

	if (!use_ktx)
		return;

	if (poll_batch_unsupported) {
		struct session_key k = {};

		k.peer = s->peer;
		k.local = s->local;
		if (bpf_map_lookup_elem(sess_fd, &k, &ms))
			return;
	} else {
		const struct session_state *msp = poll_find(s);

		if (!msp)
			return;
		ms = *msp;
	}
	s->ktx_seen_us = ms.last_seen_ns / 1000;
	if (s->state != ST_UP)
		return;
	if (ms.last_seen_ns / 1000 > s->last_rx_us)
		s->last_rx_us = ms.last_seen_ns / 1000;
	/* The program cannot store a TX time, but a reply leaves in the softirq
	 * of the packet that caused it.
	 */
	if (ms.tx_pkts != s->ktx_tx_pkts) {
		s->ktx_tx_pkts = ms.tx_pkts;
		s->last_ktx_us = s->last_rx_us;
	}
	/* Once armed, userspace sees no packets; the demand gates need the
	 * peer's state.
	 */
	if (ms.last_seen_ns)
		s->r_state = ms.remote_state;
	if (ms.detect_iv_us)
		s->detect_iv_us = ms.detect_iv_us;
	/* The RX window comes back while the fast path answers, since
	 * userspace then sees no packets.
	 */
	if (s->auth_present && ktx_answers(s) && ms.auth_rx_seen) {
		s->auth_rx_seq = ms.auth_rx_seq;
		s->auth_rx_seen = 1;
	}
	if (ms.mac_valid) {
		memcpy(s->peer_mac, ms.peer_mac, 6);
		s->mac_valid = 1;
	}
	/* Kernel RX stamp, so this is wire RTT. */
	if (s->echo_sent_us && ms.echo_last_nonce == s->echo_nonce && ms.echo_last_seen_ns) {
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
		s->echo_sent_us = 0;
	}
	s->echo_alive_k = ms.echo_alive;
	if (s->polling && ms.final_seq == s->poll_seq) {
		/* The peer's F ended this Poll. */
		s->polling = 0;
		s->applied_tx_us = s->min_tx_us;
		ktx_mirror(s);
	}
	/* fsm_rx no longer runs once armed, and fsm_detect sizes its budget
	 * from r_mult.
	 */
	if (ms.min_tx_us &&
	    (ms.min_tx_us != s->r_min_tx || ms.min_rx_us != s->r_min_rx ||
	     ms.remote_min_echo_us != s->r_min_echo ||
	     (ms.detect_mult && ms.detect_mult != s->r_mult) || ms.remote_flags != s->r_flags)) {
		s->r_min_tx = ms.min_tx_us;
		s->r_min_rx = ms.min_rx_us;
		s->r_min_echo = ms.remote_min_echo_us;
		if (ms.detect_mult)
			s->r_mult = ms.detect_mult;
		s->r_flags = ms.remote_flags;
		dp_notify_state(s);
	}
	if (ms.remote_state == ST_DOWN)
		state_transition(s, ST_DOWN, 3, t, "map: peer sent Down");
}
