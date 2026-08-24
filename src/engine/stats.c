// SPDX-License-Identifier: GPL-2.0
/* stats.c - a JSON snapshot of everything the engine knows.
 *
 * Diagnosing this engine meant `bpftool map dump` plus reading a log, and
 * the test harness leans hard on the former. One snapshot makes the state
 * assertable without reimplementing map parsing, and gives the sweeper's
 * arming error a user-visible face rather than only a counter.
 *
 * SIGUSR1 sets a flag and the dump runs from the main loop, so nothing
 * here has to be async-signal-safe. The file is written to a temp path and
 * renamed, so a reader never sees a half-written snapshot.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bfd_shared.h"
#include "addrstr.h"
#include "util.h"
#include "session.h"
#include "ktx.h"
#include "stats.h"

const char *stats_path = "/tmp/bfd_tx_stats.json";
volatile sig_atomic_t stats_wanted;

void stats_on_signal(int sig)
{
	(void)sig;
	stats_wanted = 1;
}

/* Sum a per-CPU stat slot. Zero when the map is absent, which is the
 * honest answer without kernel TX rather than an error. */
static unsigned long long slot_total(__u32 key, int ncpu)
{
	unsigned long long tot = 0;
	__u64 vals[ncpu];

	if (stats_fd < 0)
		return 0;
	memset(vals, 0, sizeof(vals));
	if (bpf_map_lookup_elem(stats_fd, &key, vals))
		return 0;
	for (int c = 0; c < ncpu; c++)
		tot += vals[c];
	return tot;
}

static void one_session(FILE *f, const struct session *s, int first)
{
	char peer[INET6_ADDRSTRLEN], local[INET6_ADDRSTRLEN];

	bfd_addr_str(&s->peer, peer, sizeof(peer));
	bfd_addr_str(&s->local, local, sizeof(local));

	fprintf(f, "%s\n    {\"lid\": %u, \"peer\": \"%s\", \"local\": \"%s\",",
		first ? "" : ",", s->lid, peer, local);
	fprintf(f, " \"family\": %d, \"multihop\": %s, \"min_ttl\": %u,",
		s->family == AF_INET6 ? 6 : 4,
		s->is_mhop ? "true" : "false", s->min_ttl);
	fprintf(f, " \"state\": \"%s\", \"diag\": %d,",
		bfd_state_str(s->state), s->diag);
	fprintf(f, " \"my_disc\": %u, \"remote_disc\": %u,",
		s->wire_disc, s->rdisc);
	fprintf(f, " \"up_events\": %u, \"down_events\": %u,",
		s->up_events, s->down_events);
	fprintf(f, " \"last_transition_us\": %llu, \"last_reason\": \"%s\",",
		(unsigned long long)s->last_transition_us, s->last_reason);
	fprintf(f, " \"last_rx_us\": %llu,",
		(unsigned long long)s->last_rx_us);
	fprintf(f, " \"last_detect_us\": %u, \"last_overshoot_us\": %u,",
		s->last_detect_us, s->last_overshoot_us);
	fprintf(f, " \"min_tx_us\": %u, \"min_rx_us\": %u, \"detect_mult\": %u,",
		s->min_tx_us, s->min_rx_us, s->detect_mult);
	fprintf(f, " \"remote_min_tx_us\": %u, \"remote_min_rx_us\": %u,",
		s->r_min_tx, s->r_min_rx);
	fprintf(f, " \"remote_detect_mult\": %u, \"remote_flags\": %u,",
		s->r_mult, s->r_flags);
	fprintf(f, " \"detect_basis_us\": %u, \"polling\": %s,",
		s->detect_iv_us, s->polling ? "true" : "false");
	fprintf(f, " \"orphaned\": %s,", s->orphaned ? "true" : "false");
	fprintf(f, " \"rx_pkts\": %llu, \"tx_pkts\": %llu,",
		(unsigned long long)s->rx_pkts,
		(unsigned long long)s->tx_pkts);
	fprintf(f, " \"echo\": {\"on\": %s, \"tx\": %llu, \"rx\": %llu,"
		   " \"lost\": %llu, \"rtt_last_us\": %llu,"
		   " \"rtt_min_us\": %llu, \"rtt_max_us\": %llu,"
		   " \"alive\": %s}}",
		s->echo_on ? "true" : "false",
		(unsigned long long)s->echo_tx_pkts,
		(unsigned long long)s->echo_rx_pkts,
		(unsigned long long)s->echo_lost,
		(unsigned long long)s->echo_rtt_last_us,
		(unsigned long long)s->echo_rtt_min_us,
		(unsigned long long)s->echo_rtt_max_us,
		s->echo_alive_k ? "true" : "false");
}

void stats_dump(void)
{
	/* Names from the same list the program counts with, so this cannot
	 * drift from the numbering. */
	static const char *const names[] = {
#define BFD_STAT_NAME(n, s) s,
		BFD_STAT_LIST(BFD_STAT_NAME)
#undef BFD_STAT_NAME
	};
	char tmp[512];
	FILE *f;
	int ncpu = libbpf_num_possible_cpus();
	int configured = 0, up = 0, first = 1;

	if (ncpu < 1)
		ncpu = 1;

	snprintf(tmp, sizeof(tmp), "%s.tmp", stats_path);
	f = fopen(tmp, "w");
	if (!f) {
		fprintf(stderr, "stats: %s: %s\n", tmp, strerror(errno));
		return;
	}

	for (int i = 0; i < MAX_SESSIONS; i++) {
		if (!sessions[i].used)
			continue;
		configured++;
		if (sessions[i].state == ST_UP)
			up++;
	}

	fprintf(f, "{\n  \"now_us\": %llu,\n", (unsigned long long)now_us());
	fprintf(f, "  \"kernel_tx\": %s,\n", use_ktx ? "true" : "false");
	fprintf(f, "  \"xdp_ifindex\": %d,\n", ktx_ifindex);
	fprintf(f, "  \"sessions_configured\": %d,\n", configured);
	fprintf(f, "  \"sessions_up\": %d,\n", up);
	fprintf(f, "  \"loop_passes\": %llu, \"loop_rx_wakeups\": %llu,\n",
		(unsigned long long)loop_passes,
		(unsigned long long)loop_rx_wakeups);
	fprintf(f, "  \"loop_gap_us\": [");
	for (int i = 0; i < 24; i++)
		fprintf(f, "%s%llu", i ? ", " : "",
			(unsigned long long)loop_gap_us[i]);
	fprintf(f, "],\n");

	fprintf(f, "  \"stats\": {");
	for (__u32 k = 0; k < BFD_STAT_MAX; k++)
		fprintf(f, "%s\"%s\": %llu", k ? ", " : "", names[k],
			slot_total(k, ncpu));
	fprintf(f, "},\n");

	fprintf(f, "  \"sessions\": [");
	for (int i = 0; i < MAX_SESSIONS; i++) {
		if (!sessions[i].used)
			continue;
		one_session(f, &sessions[i], first);
		first = 0;
	}
	fprintf(f, "%s]\n}\n", first ? "" : "\n  ");
	fclose(f);

	if (rename(tmp, stats_path))
		fprintf(stderr, "stats: rename %s: %s\n", stats_path,
			strerror(errno));
	else
		printf("stats: wrote %s (%d session(s))\n", stats_path,
		       configured);
}
