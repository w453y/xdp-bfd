// SPDX-License-Identifier: GPL-2.0
/* util.h - small helpers shared across the engine. */
#ifndef BFD_ENGINE_UTIL_H
#define BFD_ENGINE_UTIL_H

#include <stdint.h>
#include <time.h>

static inline uint64_t now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ull + ts.tv_nsec / 1000;
}

#endif /* BFD_ENGINE_UTIL_H */
