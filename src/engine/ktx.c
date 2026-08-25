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
#include "objpath.h"
#include "util.h"
#include "session.h"
#include "ktx.h"
#include "dplane.h"
#include "fsm.h"
#include "echo_tx.h"

int use_ktx = 0;
const char *ktx_obj_path;   /* --bpf-obj, or NULL for the default search */
/* Attach mode. Native is the default and is what every measured
 * result was taken with; generic (skb) mode exists so the engine can
 * run on veth and other drivers with no native XDP. Generic mode runs
 * after skb allocation, so it does NOT carry the softirq-timing
 * properties this project measures - use it for functional testing,
 * never for a timing claim. */
unsigned int ktx_xdp_flags = XDP_FLAGS_DRV_MODE;
/* --sweep-us, in nanoseconds; 0 leaves the compiled default. */
__u64 ktx_sweep_ns;
/* One entry per attached interface. The link fd is held for the life of
 * the process: closing it detaches the program, which is the whole point,
 * so we never close one deliberately. link_fd -1 means that interface fell
 * back to the flags-based attach and its program will outlive us. */
#define KTX_MAX_IFACES 8
struct ktx_iface {
	int ifindex;
	int link_fd;
	const char *mode;
};
static struct ktx_iface ktx_ifaces[KTX_MAX_IFACES];
static int ktx_niface;
/* The interface named by --kernel-tx. Others are attached on demand as
 * sessions arrive; ktx_covers() is the question worth asking, not this. */
int ktx_ifindex;
static struct bpf_program *ktx_prog;

/* One batch fetch of bfd_sessions per main-loop pass, refreshed by
 * ktx_poll_all() before the per-session tick runs. Each session used
 * to do its own bpf_map_lookup_elem: at 62 sessions and a 200us tick
 * that was ~310k syscalls a second and 67% of the engine's syscall
 * time. The data is no less fresh - the batch is taken in the same
 * pass the sessions read it. */
static struct session_key   poll_keys[MAX_SESSIONS];
static struct session_state poll_vals[MAX_SESSIONS];
static __u32 poll_n;
/* Set when the batch syscall is unavailable. Without it every session
 * would silently stop syncing from the map while the engine looked
 * healthy, which is the failure mode the per-session kernel-TX gate
 * already taught us to distrust. */
static int poll_batch_unsupported;

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
	if (bpf_map_lookup_batch(sess_fd, &in, &out, poll_keys, poll_vals,
				 &count, &bopts) && errno != ENOENT) {
		if (errno == EINVAL || errno == EOPNOTSUPP) {
			poll_batch_unsupported = 1;
			fprintf(stderr,
				"kernel-tx: batch map lookup unavailable (%s), "
				"falling back to one lookup per session\n",
				strerror(errno));
		}
		return;
	}
	poll_n = count;
}

/* The batch is unordered, so find this session's entry in it. A linear
 * scan of at most MAX_SESSIONS keys costs far less than the syscall it
 * replaces, and matches how the session table is searched elsewhere. */
static const struct session_state *poll_find(const struct session *s)
{
	for (__u32 i = 0; i < poll_n; i++)
		if (!memcmp(&poll_keys[i].peer, &s->peer, sizeof(s->peer)) &&
		    !memcmp(&poll_keys[i].local, &s->local, sizeof(s->local)))
			return &poll_vals[i];
	return NULL;
}
static int cfg_fd = -1;
int sess_fd = -1, echo_peers_fd = -1;
int echo_disc_fd = -1;
int stats_fd = -1;      /* the only map fd ktx did not keep; the stats
                         * dump needs it */
static int flags_fd = -1;
static struct bpf_object *bpf_obj;

/* ---------- BPF plumbing ---------- */
int ktx_load(void)
{
	if (bpf_obj)
		return 0;

	const char *obj = bfd_obj_path(ktx_obj_path);

	bpf_obj = bpf_object__open_file(obj, NULL);
	if (!bpf_obj || bpf_object__load(bpf_obj)) {
		fprintf(stderr, "%s load failed\n", obj);
		bpf_obj = NULL;
		return -1;
	}
	/* Tunables go in after load and before attach, so the first packet
	 * cannot arm the sweeper on the default and then be corrected. */
	if (ktx_sweep_ns) {
		int tune_fd = bpf_object__find_map_fd_by_name(bpf_obj,
							      "tunables");
		__u32 k = BFD_TUNE_SWEEP_NS;

		if (tune_fd < 0 ||
		    bpf_map_update_elem(tune_fd, &k, &ktx_sweep_ns, 0)) {
			fprintf(stderr,
				"kernel-tx: sweep interval NOT applied, "
				"running the compiled default\n");
			ktx_sweep_ns = 0;
		}
	}

	ktx_prog = bpf_object__find_program_by_name(bpf_obj, "bfd_observer");
	if (!ktx_prog) {
		fprintf(stderr, "bfd_observer not found in %s\n", obj);
		return -1;
	}

	/* The maps come from the object, not from any one link, which is
	 * what lets every attached interface share one set. */
	cfg_fd  = bpf_object__find_map_fd_by_name(bpf_obj, "tx_config");
	sess_fd = bpf_object__find_map_fd_by_name(bpf_obj, "bfd_sessions");
	echo_peers_fd = bpf_object__find_map_fd_by_name(bpf_obj, "echo_peers");
	echo_disc_fd = bpf_object__find_map_fd_by_name(bpf_obj, "echo_disc");
	flags_fd = bpf_object__find_map_fd_by_name(bpf_obj, "prog_flags");
	stats_fd = bpf_object__find_map_fd_by_name(bpf_obj, "bfd_stats");

	if (ktx_sweep_ns)
		printf("kernel-tx: sweep interval %lluus (default %lluus)\n",
		       (unsigned long long)(ktx_sweep_ns / 1000),
		       (unsigned long long)(BFD_SWEEP_NS_DEFAULT / 1000));

	return 0;
}

int ktx_covers(int ifindex)
{
	for (int i = 0; i < ktx_niface; i++)
		if (ktx_ifaces[i].ifindex == ifindex)
			return 1;
	return 0;
}

/* Attach the one loaded program to one more interface. Idempotent, so
 * the caller does not have to track what is already covered. */
int ktx_attach_if(int ifindex, const char *ifname)
{
	if (ktx_covers(ifindex))
		return 0;
	if (ktx_load())
		return -1;
	if (ktx_niface == KTX_MAX_IFACES) {
		fprintf(stderr,
			"kernel-tx: %s not attached, already on %d interfaces\n",
			ifname, ktx_niface);
		return -1;
	}

	unsigned int flags = ktx_xdp_flags;
	const char *mode = (flags & XDP_FLAGS_SKB_MODE) ? "generic" : "native";

	/* Attach through a bpf_link, so the kernel detaches the program
	 * when this process dies - including on SIGKILL, where we get no
	 * chance to clean up. With the plain attach the fast path kept
	 * answering control packets from a frozen tx_config after the
	 * engine was gone, so the peer saw a session that nothing was
	 * driving.
	 *
	 * The mode is per interface rather than per process: a veth or a
	 * driver without native XDP refuses drv mode, and an on-demand
	 * attach cannot choose the interface it is handed.
	 */
	LIBBPF_OPTS(bpf_link_create_opts, lopts, .flags = flags);
	int fd = bpf_link_create(bpf_program__fd(ktx_prog), ifindex,
				 BPF_XDP, &lopts);

	if (fd < 0 && !(flags & XDP_FLAGS_SKB_MODE)) {
		flags = XDP_FLAGS_SKB_MODE;
		mode = "generic";
		lopts.flags = flags;
		fd = bpf_link_create(bpf_program__fd(ktx_prog), ifindex,
				     BPF_XDP, &lopts);
	}
	if (fd < 0) {
		if (bpf_xdp_attach(ifindex, bpf_program__fd(ktx_prog),
				   flags, NULL)) {
			fprintf(stderr, "%s XDP attach failed on %s\n", mode,
				ifname);
			return -1;
		}
		fprintf(stderr,
			"kernel-tx: bpf_link unavailable (%s), attached with "
			"flags - the program will OUTLIVE this process\n",
			strerror(-fd));
	}

	ktx_ifaces[ktx_niface].ifindex = ifindex;
	ktx_ifaces[ktx_niface].link_fd = fd;
	ktx_ifaces[ktx_niface].mode    = mode;
	ktx_niface++;

	printf("kernel-tx: XDP attached to %s (%s mode, %s)\n", ifname, mode,
	       fd >= 0 ? "link" : "flags");
	return 0;
}

int ktx_attach(const char *ifname)
{
	int ifindex = if_nametoindex(ifname);
	if (!ifindex) { perror("ifname"); return -1; }

	if (ktx_attach_if(ifindex, ifname))
		return -1;
	ktx_ifindex = ifindex;
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

/* echo_peers is keyed on the peer address alone - that is all the
 * reflector has when a self-addressed echo arrives, since it never
 * learns which of our local addresses the session used. Several
 * sessions can therefore share one entry, so no single session owns it
 * and no single session may delete it: doing that disabled reflection
 * for every other session with the same peer.
 *
 * Membership is re-derived from the session table rather than
 * refcounted. A refcount that drifts by one silently disables or
 * silently enables echo and there is no witness for either; a rescan of
 * 64 slots on a config event costs nothing.
 *
 * `skip` is the session being torn down or reconfigured, whose own
 * state must not count toward the answer.
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

/* Clear the kernel state for an address pair. Split from ktx_clear so
 * an address change can drop the OLD key while the session lives on
 * under the new one. */
void ktx_clear_key(const struct bfd_addr *peer, const struct bfd_addr *local,
		   uint32_t wire_disc)
{
	if (!use_ktx)
		return;
	struct session_key k = {};
	k.peer  = *peer;
	k.local = *local;
	bpf_map_delete_elem(cfg_fd, &k);
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


void ktx_poll_map(struct session *s, uint64_t t)
{
	if (!use_ktx || s->state != ST_UP)
		return;
	struct session_state ms;
	if (poll_batch_unsupported) {
		struct session_key k = {};

		k.peer  = s->peer;
		k.local = s->local;
		if (bpf_map_lookup_elem(sess_fd, &k, &ms))
			return;
	} else {
		const struct session_state *msp = poll_find(s);

		if (!msp)
			return;
		ms = *msp;
	}
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
			     ms.remote_min_echo_us != s->r_min_echo ||
			     ms.remote_flags != s->r_flags)) {
		s->r_min_tx = ms.min_tx_us;
		s->r_min_rx = ms.min_rx_us;
		s->r_min_echo = ms.remote_min_echo_us;
		s->r_flags = ms.remote_flags;
		dp_notify_state(s);
	}
	if (ms.remote_state == ST_DOWN)
		state_transition(s, ST_DOWN, 3, t, "map: peer sent Down");
}
