// SPDX-License-Identifier: GPL-2.0
#ifndef BFD_ENGINE_STATS_H
#define BFD_ENGINE_STATS_H

#include <signal.h>
#include <stdint.h>

/* Loop passes, and passes woken by a packet rather than the tick. Rates: diff
 * two snapshots.
 */
extern uint64_t loop_passes;
extern uint64_t loop_rx_wakeups;
extern uint64_t loop_gap_us[24];

/* Where the snapshot lands; --stats-dump overrides it. */
extern const char *stats_path;

/* Set by the SIGUSR1 handler, cleared by the main loop. The dump itself
 * runs in the loop, so it is under no async-signal-safety constraint.
 */
extern volatile sig_atomic_t stats_wanted;

void stats_on_signal(int sig);
void stats_dump(void);

#endif /* BFD_ENGINE_STATS_H */
