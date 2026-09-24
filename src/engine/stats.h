// SPDX-License-Identifier: GPL-2.0
#ifndef BFD_ENGINE_STATS_H
#define BFD_ENGINE_STATS_H

#include <signal.h>
#include <stdint.h>

/* Diff two snapshots for rates. */
extern uint64_t loop_passes;
extern uint64_t loop_rx_wakeups;
extern uint64_t loop_gap_us[24];

extern const char *stats_path;

/* Set by the SIGUSR1 handler; the loop dumps. */
extern volatile sig_atomic_t stats_wanted;

void stats_on_signal(int sig);
void stats_dump(void);

#endif /* BFD_ENGINE_STATS_H */
