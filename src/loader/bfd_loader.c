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

static __u64 mono_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static int on_event(void *ctx, void *data, size_t len)
{
	struct bfd_event *e = data;
	char peer[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &e->key.peer.b[12], peer, sizeof(peer));

	double silent_ms = (e->ts_ns - e->last_seen_ns) / 1e6;

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
	if (argc != 2) {
		fprintf(stderr, "usage: %s <ifname>\n", argv[0]);
		return 1;
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
	if (bpf_xdp_attach(ifindex, bpf_program__fd(prog),
			   XDP_FLAGS_DRV_MODE, NULL)) {
		fprintf(stderr, "native XDP attach failed on %s\n", argv[1]);
		return 1;
	}
	printf("attached (NATIVE mode)\n");

	int sess_fd  = bpf_object__find_map_fd_by_name(obj, "bfd_sessions");
	int stats_fd = bpf_object__find_map_fd_by_name(obj, "bfd_stats");
	int rb_fd    = bpf_object__find_map_fd_by_name(obj, "bfd_events");
	if (sess_fd < 0 || stats_fd < 0 || rb_fd < 0) {
		fprintf(stderr, "map lookup failed\n");
		bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
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
		bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
		return 1;
	}

	evlog = fopen("events.csv", "a");
	if (evlog && ftell(evlog) == 0)
		fprintf(evlog, "epoch,mono_ns,event,peer,silent_ms\n");

	FILE *log = fopen("observer.csv", "a");
	if (log && ftell(log) == 0)
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

		__u64 totals[4] = {0};
		for (__u32 i = 0; i < 4; i++) {
			__u64 vals[ncpu];
			memset(vals, 0, sizeof(vals));
			if (!bpf_map_lookup_elem(stats_fd, &i, vals))
				for (int c = 0; c < ncpu; c++)
					totals[i] += vals[c];
		}
		printf("-- pkts:%llu bfd:%llu bad:%llu rej:%llu --\n",
		       (unsigned long long)totals[0],
		       (unsigned long long)totals[1],
		       (unsigned long long)totals[2],
		       (unsigned long long)totals[3]);

		struct session_key key, next;
		void *pkey = NULL;
		__u64 now = mono_now_ns();
		while (bpf_map_get_next_key(sess_fd, pkey, &next) == 0) {
			struct session_state st;
			if (bpf_map_lookup_elem(sess_fd, &next, &st) == 0) {
				char peer[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &next.peer.b[12],
					  peer, sizeof(peer));
				double age = (now - st.last_seen_ns) / 1e6;
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

	bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
	printf("\ndetached.\n");
	if (log) fclose(log);
	if (evlog) fclose(evlog);
	ring_buffer__free(rb);
	bpf_object__close(obj);
	return 0;
}
