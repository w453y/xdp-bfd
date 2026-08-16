// SPDX-License-Identifier: GPL-2.0
/* bfd_loader.c - attach, dump sessions each second, log liveness events. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#include "bfd_shared.h"
#include "objpath.h"

static volatile sig_atomic_t stop;
static void on_int(int sig) { (void)sig; stop = 1; }
static FILE *evlog;

/* The session key always holds the shared 16-byte address, with v4 stored
 * v4-mapped (::ffff:a.b.c.d). Rendering it unconditionally as AF_INET
 * printed a v6 peer as the last four bytes of its address. Same test the
 * python harness uses in addr_of(). */
static const char *addr_str(const struct bfd_addr *a, char *buf, size_t n)
{
	static const __u8 v4map[12] = { 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0xff, 0xff };

	if (!memcmp(a->b, v4map, sizeof(v4map)))
		return inet_ntop(AF_INET, &a->b[12], buf, n);
	return inet_ntop(AF_INET6, a->b, buf, n);
}

/* Slot names must track the comment on bfd_stats in src/xdp/maps.h, and
 * the STAT dict in tests/inject_matrix.py. The dump only ever covered the
 * first four of nine, so no echo activity was ever visible here. */
static const char *const stat_name[] = {
	"pkts", "well-formed", "malformed", "rejected", "echo-reflected",
	"echo-returns", "echo-declined", "echo-not-self", "echo-ttl",
	"unsupported-flags",
};
#define NSTATS ((__u32)(sizeof(stat_name) / sizeof(stat_name[0])))

/* fopen(..., "a") does not define where the stream position starts, so
 * ftell() on a fresh append handle is not reliably 0 on an empty file.
 * Seek to the end explicitly before deciding whether to write a header. */
static int file_is_empty(FILE *f)
{
	return f && !fseek(f, 0, SEEK_END) && ftell(f) == 0;
}

/* Age of a timestamp against a snapshot taken slightly earlier. A packet
 * arriving between the snapshot and the map read leaves last_seen_ns
 * ahead of now, and an unguarded __u64 subtraction then wraps to about
 * 1.8e13 ms. sweep.h's check_session() already guards this the same way. */
static double age_ms(__u64 now, __u64 then)
{
	__s64 d = (__s64)(now - then);

	return d > 0 ? d / 1e6 : 0.0;
}

static __u64 mono_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static int on_event(void *ctx, void *data, size_t len)
{
	struct bfd_event *e = data;
	char peer[INET6_ADDRSTRLEN];

	addr_str(&e->key.peer, peer, sizeof(peer));

	double silent_ms = age_ms(e->ts_ns, e->last_seen_ns);

	printf(">>> %s peer=%s disc=%u silent=%.1fms mono_ts=%llu\n",
	       e->event ? "ALIVE" : "DETECT-DOWN",
	       peer, e->remote_disc, silent_ms,
	       (unsigned long long)e->ts_ns);
	if (evlog) {
		fprintf(evlog, "%ld,%llu,%s,%s,%.1f\n",
			time(NULL), (unsigned long long)e->ts_ns,
			e->event ? "ALIVE" : "DOWN", peer, silent_ms);
		fflush(evlog);
	}
	return 0;
}

int main(int argc, char **argv)
{
	unsigned int xdp_flags = XDP_FLAGS_DRV_MODE;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "usage: %s <ifname> [--generic]\n", argv[0]);
		return 1;
	}
	if (argc == 3) {
		if (strcmp(argv[2], "--generic")) {
			fprintf(stderr, "usage: %s <ifname> [--generic]\n",
				argv[0]);
			return 1;
		}
		xdp_flags = XDP_FLAGS_SKB_MODE;
	}
	int ifindex = if_nametoindex(argv[1]);
	if (!ifindex) { perror("if_nametoindex"); return 1; }

	const char *objpath = bfd_obj_path(NULL);
	struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "%s open/load failed\n", objpath);
		return 1;
	}
	struct bpf_program *prog =
		bpf_object__find_program_by_name(obj, "bfd_observer");
	if (!prog) {
		fprintf(stderr, "bfd_observer not found in object\n");
		return 1;
	}
	const char *mode = (xdp_flags & XDP_FLAGS_SKB_MODE) ? "GENERIC"
							    : "NATIVE";
	if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), xdp_flags, NULL)) {
		fprintf(stderr, "%s XDP attach failed on %s\n", mode, argv[1]);
		return 1;
	}
	printf("attached (%s mode)\n", mode);

	int sess_fd  = bpf_object__find_map_fd_by_name(obj, "bfd_sessions");
	int stats_fd = bpf_object__find_map_fd_by_name(obj, "bfd_stats");
	int rb_fd    = bpf_object__find_map_fd_by_name(obj, "bfd_events");
	if (sess_fd < 0 || stats_fd < 0 || rb_fd < 0) {
		fprintf(stderr, "map lookup failed\n");
		bpf_xdp_detach(ifindex, xdp_flags, NULL);
		return 1;
	}

	/* Standalone observer tracks everything; bfd_tx leaves this 0 so
	 * only control-plane-configured sessions create map state. */
	int flags_fd = bpf_object__find_map_fd_by_name(obj, "prog_flags");
	if (flags_fd >= 0) {
		__u32 zero = 0, promisc = 1;
		bpf_map_update_elem(flags_fd, &zero, &promisc, 0);
	}

	struct ring_buffer *rb =
		ring_buffer__new(rb_fd, on_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ringbuf setup failed\n");
		bpf_xdp_detach(ifindex, xdp_flags, NULL);
		return 1;
	}

	evlog = fopen("events.csv", "a");
	if (file_is_empty(evlog))
		fprintf(evlog, "epoch,mono_ns,event,peer,silent_ms\n");

	FILE *log = fopen("observer.csv", "a");
	if (file_is_empty(log))
		fprintf(log, "epoch,rx_pkts,age_ms,remote_state,alive\n");

	signal(SIGINT, on_int);
	signal(SIGTERM, on_int);

	int ncpu = libbpf_num_possible_cpus();
	time_t last_dump = 0;

	while (!stop) {
		ring_buffer__poll(rb, 100);   /* 100ms: events are prompt */

		if (time(NULL) == last_dump)
			continue;
		last_dump = time(NULL);

		printf("--");
		for (__u32 i = 0; i < NSTATS; i++) {
			__u64 vals[ncpu], tot = 0;

			memset(vals, 0, sizeof(vals));
			if (!bpf_map_lookup_elem(stats_fd, &i, vals))
				for (int c = 0; c < ncpu; c++)
					tot += vals[c];
			printf(" %s:%llu", stat_name[i],
			       (unsigned long long)tot);
		}
		printf(" --\n");

		struct session_key key, next;
		void *pkey = NULL;
		__u64 now = mono_now_ns();
		while (bpf_map_get_next_key(sess_fd, pkey, &next) == 0) {
			struct session_state st;
			if (bpf_map_lookup_elem(sess_fd, &next, &st) == 0) {
				char peer[INET6_ADDRSTRLEN];

				addr_str(&next.peer, peer, sizeof(peer));
				double age = age_ms(now, st.last_seen_ns);
				printf("%s state=%s alive=%u pkts=%llu age=%.1fms\n",
				       peer,
				       bfd_state_str(st.remote_state),
				       st.alive,
				       (unsigned long long)st.rx_pkts, age);
				if (log) {
					fprintf(log, "%ld,%llu,%.1f,%u,%u\n",
						time(NULL),
						(unsigned long long)st.rx_pkts,
						age, st.remote_state, st.alive);
					fflush(log);
				}
			}
			key = next; pkey = &key;
		}
		fflush(stdout);
	}

	bpf_xdp_detach(ifindex, xdp_flags, NULL);
	printf("\ndetached.\n");
	if (log) fclose(log);
	if (evlog) fclose(evlog);
	ring_buffer__free(rb);
	bpf_object__close(obj);
	return 0;
}
