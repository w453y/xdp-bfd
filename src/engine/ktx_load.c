// SPDX-License-Identifier: GPL-2.0
/* ktx_load.c - load bfd_xdp.o, check it matches this engine, set its
 * tunables, and attach it.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/mman.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>

#include "bfd_shared.h"
#include "objpath.h"
#include "util.h"
#include "log.h"
#include "ktx.h"

const char *ktx_obj_path; /* --bpf-obj, or NULL for the default search */
/* Attach mode. Native by default; generic (skb) mode serves drivers without
 * native XDP and is for functional testing, not timing.
 */
unsigned int ktx_xdp_flags = XDP_FLAGS_DRV_MODE;
/* --sweep-us, in nanoseconds; 0 leaves the compiled default. */
__u64 ktx_sweep_ns;
/* --deadman-us, in nanoseconds; 0 switches the gate off entirely. */
__u64 ktx_deadman_ns = BFD_DEADMAN_NS_DEFAULT;
/* Heartbeat cell, mmapped so a beat is a plain store; NULL if mmap failed. */
static __u64 *ktx_hb;
/* Attached interfaces. The link fd is never closed, since closing it detaches
 * the program. link_fd -1 is a flags attach, which outlives the process.
 */
#define KTX_MAX_IFACES 8
struct ktx_iface {
	int ifindex;
	int link_fd;
	const char *mode;
};
static struct ktx_iface ktx_ifaces[KTX_MAX_IFACES];
static int ktx_niface;
/* --kernel-tx interface; others attach on demand, see ktx_covers(). */
int ktx_ifindex;
static struct bpf_program *ktx_prog;

int ktx_cfg_fd = -1;
int sess_fd = -1, echo_peers_fd = -1;
int echo_disc_fd = -1;
int stats_fd = -1; /* needed by the stats dump */
int ktx_flags_fd = -1;
static struct bpf_object *bpf_obj;

/* Dead-man heartbeat: one __u64 store. The program compares it against
 * bpf_ktime_get_ns, the same clock in nanoseconds.
 */
void ktx_heartbeat(uint64_t now)
{
	if (ktx_hb)
		*ktx_hb = now * 1000ull;
}

/* Refuse an object whose shared structs or enum-sized maps differ from ours.
 *
 * The engine and bfd_xdp.o are built separately and paired at runtime, so a
 * stale object would read the maps with a different layout. Sizes come from
 * the object's BTF; an object without BTF loads with a warning.
 */
static int ktx_abi_check(struct bpf_object *o, const char *path)
{
	static const struct {
		const char *name;
		size_t sz;
	} want[] = {
		{ "session_key", sizeof(struct session_key) },
		{ "session_state", sizeof(struct session_state) },
		{ "tx_cfg", sizeof(struct tx_cfg) },
		{ "bfd_event", sizeof(struct bfd_event) },
		{ "bfd_ctrl_pkt", sizeof(struct bfd_ctrl_pkt) },
	};
	/* Enum-sized maps: compare max_entries against our count. */
	static const struct {
		const char *map;
		__u32 n;
	} counts[] = {
		{ "bfd_stats", BFD_STAT_MAX },
		{ "tunables", BFD_TUNE_MAX },
	};
	struct btf *btf = bpf_object__btf(o);
	int bad = 0;

	if (!btf) {
		log_err("kernel-tx: %s carries no BTF, ABI not checked\n", path);
	} else {
		for (unsigned int i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
			__s32 id = btf__find_by_name_kind(btf, want[i].name, BTF_KIND_STRUCT);
			__s64 got;

			/* Missing from an object that has BTF: it predates
			 * this check.
			 */
			if (id < 0) {
				log_err("kernel-tx: %s has no BTF record of struct %s, so it predates this check\n",
					path, want[i].name);
				bad = 1;
				continue;
			}
			got = btf__resolve_size(btf, id);
			if (got < 0) {
				log_err("kernel-tx: %s has an unresolvable struct %s (%lld)\n",
					path, want[i].name, (long long)got);
				bad = 1;
			} else if (got != (__s64)want[i].sz) {
				log_err("kernel-tx: %s was built with %s at %lld bytes, this engine has %zu\n",
					path, want[i].name, (long long)got, want[i].sz);
				bad = 1;
			}
		}
	}

	for (unsigned int i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		struct bpf_map *m = bpf_object__find_map_by_name(o, counts[i].map);
		__u32 got;

		if (!m) {
			log_err("kernel-tx: %s has no map %s\n", path, counts[i].map);
			bad = 1;
			continue;
		}
		got = bpf_map__max_entries(m);
		if (got != counts[i].n) {
			log_err("kernel-tx: %s sizes %s for %u entries, this engine expects %u\n",
				path, counts[i].map, got, counts[i].n);
			bad = 1;
		}
	}

	if (bad)
		log_err("kernel-tx: refusing to load %s - rebuild both halves from the same tree\n",
			path);
	return bad ? -1 : 0;
}

int ktx_load(void)
{
	if (bpf_obj)
		return 0;

	const char *obj = bfd_obj_path(ktx_obj_path);

	bpf_obj = bpf_object__open_file(obj, NULL);
	if (!bpf_obj || ktx_abi_check(bpf_obj, obj) || bpf_object__load(bpf_obj)) {
		log_err("%s load failed\n", obj);
		/* Close a refused object too; ktx_load may be called again. */
		if (bpf_obj)
			bpf_object__close(bpf_obj);
		bpf_obj = NULL;
		return -1;
	}
	/* Tunables go in after load and before attach, so the first packet
	 * cannot arm the sweeper on the default and then be corrected.
	 */
	if (ktx_sweep_ns) {
		int tune_fd = bpf_object__find_map_fd_by_name(bpf_obj, "tunables");
		__u32 k = BFD_TUNE_SWEEP_NS;

		if (tune_fd < 0 || bpf_map_update_elem(tune_fd, &k, &ktx_sweep_ns, 0)) {
			log_err("kernel-tx: sweep interval NOT applied, running the compiled default\n");
			ktx_sweep_ns = 0;
		}
	}

	/* Map the heartbeat before writing the bound, so a failed mmap leaves
	 * no bound in the map. Both happen before attach.
	 */
	if (ktx_deadman_ns) {
		int hb_fd = bpf_object__find_map_fd_by_name(bpf_obj, "heartbeat");
		void *m = MAP_FAILED;

		if (hb_fd >= 0)
			m = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE, MAP_SHARED,
				 hb_fd, 0);
		if (m == MAP_FAILED) {
			log_err("kernel-tx: heartbeat not mapped (%s), dead-man gate disarmed\n",
				strerror(errno));
			ktx_deadman_ns = 0;
		} else {
			ktx_hb = m;
			/* Beat once so the cell is fresh before the first loop
			 * pass.
			 */
			ktx_heartbeat(now_us());
		}
	}

	/* Write the bound. On failure, disarm the gate so the log matches what
	 * is in force.
	 */
	if (ktx_deadman_ns) {
		int tune_fd = bpf_object__find_map_fd_by_name(bpf_obj, "tunables");
		__u32 k = BFD_TUNE_DEADMAN_NS;

		if (tune_fd < 0 || bpf_map_update_elem(tune_fd, &k, &ktx_deadman_ns, 0)) {
			log_err("kernel-tx: dead-man bound NOT applied, the fast path will answer for a wedged engine\n");
			ktx_deadman_ns = 0;
		}
	}

	ktx_prog = bpf_object__find_program_by_name(bpf_obj, "bfd_observer");
	if (!ktx_prog) {
		log_err("bfd_observer not found in %s\n", obj);
		return -1;
	}

	/* The maps come from the object, not from any one link, which is
	 * what lets every attached interface share one set.
	 */
	ktx_cfg_fd = bpf_object__find_map_fd_by_name(bpf_obj, "tx_config");
	sess_fd = bpf_object__find_map_fd_by_name(bpf_obj, "bfd_sessions");
	echo_peers_fd = bpf_object__find_map_fd_by_name(bpf_obj, "echo_peers");
	echo_disc_fd = bpf_object__find_map_fd_by_name(bpf_obj, "echo_disc");
	ktx_flags_fd = bpf_object__find_map_fd_by_name(bpf_obj, "prog_flags");
	stats_fd = bpf_object__find_map_fd_by_name(bpf_obj, "bfd_stats");

	/* Sweep verdict ring. Optional: fsm_detect covers detection without
	 * it.
	 */
	ktx_events_init(bpf_object__find_map_fd_by_name(bpf_obj, "bfd_events"));

	if (ktx_deadman_ns)
		log_info("kernel-tx: dead-man gate at %lluus\n",
			 (unsigned long long)(ktx_deadman_ns / 1000));
	else
		log_info(
			"kernel-tx: dead-man gate off, the fast path will answer for a wedged engine\n");

	if (ktx_sweep_ns)
		log_info("kernel-tx: sweep interval %lluus (default %lluus)\n",
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

/* Attach the loaded program to one more interface. Idempotent. */
int ktx_attach_if(int ifindex, const char *ifname)
{
	if (ktx_covers(ifindex))
		return 0;
	if (ktx_load())
		return -1;
	if (ktx_niface == KTX_MAX_IFACES) {
		log_err("kernel-tx: %s not attached, already on %d interfaces\n", ifname,
			ktx_niface);
		return -1;
	}

	unsigned int flags = ktx_xdp_flags;
	const char *mode = (flags & XDP_FLAGS_SKB_MODE) ? "generic" : "native";

	/* Attach via bpf_link so the kernel detaches the program when we exit,
	 * even on SIGKILL. Fall back per interface to generic mode, then to a
	 * flags attach if bpf_link is unavailable.
	 */
	LIBBPF_OPTS(bpf_link_create_opts, lopts, .flags = flags);
	int fd = bpf_link_create(bpf_program__fd(ktx_prog), ifindex, BPF_XDP, &lopts);

	if (fd < 0 && !(flags & XDP_FLAGS_SKB_MODE)) {
		flags = XDP_FLAGS_SKB_MODE;
		mode = "generic";
		lopts.flags = flags;
		fd = bpf_link_create(bpf_program__fd(ktx_prog), ifindex, BPF_XDP, &lopts);
	}
	if (fd < 0) {
		if (bpf_xdp_attach(ifindex, bpf_program__fd(ktx_prog), flags, NULL)) {
			log_err("%s XDP attach failed on %s\n", mode, ifname);
			return -1;
		}
		log_err("kernel-tx: bpf_link unavailable (%s), attached with flags - the program will OUTLIVE this process\n",
			strerror(-fd));
	}

	ktx_ifaces[ktx_niface].ifindex = ifindex;
	ktx_ifaces[ktx_niface].link_fd = fd;
	ktx_ifaces[ktx_niface].mode = mode;
	ktx_niface++;

	log_info("kernel-tx: XDP attached to %s (%s mode, %s)\n", ifname, mode,
		 fd >= 0 ? "link" : "flags");
	return 0;
}

int ktx_attach(const char *ifname)
{
	int ifindex = if_nametoindex(ifname);

	if (!ifindex) {
		perror("ifname");
		return -1;
	}

	if (ktx_attach_if(ifindex, ifname))
		return -1;
	ktx_ifindex = ifindex;
	return 0;
}
