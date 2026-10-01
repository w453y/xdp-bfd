// SPDX-License-Identifier: GPL-2.0
/* sched_dl.h - the loop's SCHED_DEADLINE reservation. */
#ifndef BFD_ENGINE_SCHED_DL_H
#define BFD_ENGINE_SCHED_DL_H

/* --sched-deadline, microseconds; runtime 0 is off. */
extern unsigned int dl_runtime_us, dl_period_us;

/* Takes the reservation if one was asked for, then drops CAP_SYS_NICE.
 * A refused reservation is logged and the inherited policy kept.
 */
void sched_dl_apply(void);

#endif /* BFD_ENGINE_SCHED_DL_H */
