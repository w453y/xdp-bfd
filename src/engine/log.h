// SPDX-License-Identifier: GPL-2.0
/* log.h - levels for the engine's output.
 *
 *   ERROR  the engine cannot do its job and an operator has to act.
 *          Never gated, always on stderr.
 *   INFO   lifecycle: attach, bfdd connect and disconnect, session add
 *          and delete, session state transitions. The default.
 *   DEBUG  per-packet and per-timeout detail.
 *
 * State transitions are INFO deliberately: it is the most operationally
 * valuable line the process emits, and an operator debugging a flap
 * cannot raise the verbosity retroactively.
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

/* Where errors go, which is separate from whether they are emitted: the
 * fuzz target sinks them, since rejection messages dominate its runtime,
 * and it must not redirect the process's stderr because that would also
 * swallow the sanitizer and libFuzzer output.
 *
 * NULL means stderr, resolved at each use: stderr is not a constant
 * expression, so a static initialiser is not portable. */
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
