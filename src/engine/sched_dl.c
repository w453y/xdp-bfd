// SPDX-License-Identifier: GPL-2.0
/* sched_dl.c - run the loop on a SCHED_DEADLINE reservation. Deadline tasks
 * run ahead of every SCHED_FIFO priority, so no real-time load starves the
 * engine however high it runs, and admission control keeps the reservations
 * within the CPUs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>

#include "log.h"
#include "sched_dl.h"

unsigned int dl_runtime_us, dl_period_us;

#define DL_POLICY	 6    /* SCHED_DEADLINE */
#define DL_RESET_ON_FORK 0x01 /* a child would otherwise inherit it */
#define DL_RECLAIM	 0x02 /* a burst may use idle CPU past the budget */

/* struct sched_attr, version 0; older glibc does not declare it. */
struct dl_attr {
	uint32_t size;
	uint32_t policy;
	uint64_t flags;
	int32_t nice;
	uint32_t priority;
	uint64_t runtime;
	uint64_t deadline;
	uint64_t period;
};

void cap_drop(int cap, const char *name)
{
	struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
	struct __user_cap_data_struct d[2];

	prctl(PR_CAP_AMBIENT_LOWER, cap, 0, 0, 0);
	if (syscall(SYS_capget, &h, d))
		return;
	d[CAP_TO_INDEX(cap)].effective &= ~CAP_TO_MASK(cap);
	d[CAP_TO_INDEX(cap)].permitted &= ~CAP_TO_MASK(cap);
	d[CAP_TO_INDEX(cap)].inheritable &= ~CAP_TO_MASK(cap);
	if (syscall(SYS_capset, &h, d))
		log_err("cannot drop %s: %s\n", name, strerror(errno));
}

void sched_dl_apply(void)
{
	struct dl_attr a = {
		.size = sizeof(a),
		.policy = DL_POLICY,
		.flags = DL_RESET_ON_FORK | DL_RECLAIM,
		.runtime = dl_runtime_us * 1000ull,
		.deadline = dl_period_us * 1000ull,
		.period = dl_period_us * 1000ull,
	};

	if (dl_runtime_us) {
		if (syscall(SYS_sched_setattr, 0, &a, 0))
			log_err("--sched-deadline %u/%u: %s; keeping the inherited policy\n",
				dl_runtime_us, dl_period_us, strerror(errno));
		else
			log_info("engine: SCHED_DEADLINE, %uus every %uus\n", dl_runtime_us,
				 dl_period_us);
	}
	/* Only needed for the reservation; kept, it reschedules any task. */
	cap_drop(CAP_SYS_NICE, "CAP_SYS_NICE");
}
