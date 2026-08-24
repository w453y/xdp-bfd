// SPDX-License-Identifier: GPL-2.0
#ifndef BFD_ENGINE_STATS_H
#define BFD_ENGINE_STATS_H

#include <signal.h>
#include <stdint.h>

/* Main loop pass count and how many of those passes were woken by an
 * arriving packet rather than by the tick timeout. Rates, not states:
 * take two snapshots and divide by the now_us delta. */
extern uint64_t loop_passes;
extern uint64_t loop_rx_wakeups;
extern uint64_t loop_gap_us[24];

/* Where the snapshot lands; --stats-dump overrides it. */
extern const char *stats_path;

/* Set by the SIGUSR1 handler, cleared by the main loop. The dump itself
 * runs in the loop, so it is under no async-signal-safety constraint. */
extern volatile sig_atomic_t stats_wanted;

void stats_on_signal(int sig);
void stats_dump(void);

#endif /* BFD_ENGINE_STATS_H */
