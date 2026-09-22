// SPDX-License-Identifier: GPL-2.0
/* log.h - levels for the engine's output.
 *
 *   ERROR  the engine cannot do its job; never gated, always on stderr.
 *   INFO   lifecycle: attach, bfdd connect/disconnect, session add/delete
 *          and state transitions. The default.
 *   DEBUG  per-packet and per-timeout detail.
 *
 * Transitions are INFO because a flap cannot be debugged retroactively.
 */
#ifndef BFD_ENGINE_LOG_H
#define BFD_ENGINE_LOG_H

#include <stdio.h>

enum bfd_log_level {
	BFD_LOG_ERROR = 0,
	BFD_LOG_INFO  = 1,
	BFD_LOG_DEBUG = 2,
};

/* Set once from --log-level before the loop starts; read everywhere. */
extern int bfd_log_level;

/* Error sink; NULL means stderr. The fuzz target redirects it without touching
 * the process's stderr. */
extern FILE *bfd_log_err_fp;

#define log_err(...) \
	fprintf(bfd_log_err_fp ? bfd_log_err_fp : stderr, __VA_ARGS__)

#define log_info(...)  do { \
	if (bfd_log_level >= BFD_LOG_INFO) \
		printf(__VA_ARGS__); \
} while (0)

#define log_debug(...) do { \
	if (bfd_log_level >= BFD_LOG_DEBUG) \
		printf(__VA_ARGS__); \
} while (0)

#endif /* BFD_ENGINE_LOG_H */
