// SPDX-License-Identifier: GPL-2.0
/* log.h - levels for the engine's output.
 *
 * The engine used to write to stdout unconditionally: a line per state
 * transition, a line per detect timeout, a line per session ADD. At 64
 * sessions on 10ms timers that is a real operational problem, not a
 * tidiness one - a flap storm produces hundreds of lines a second and the
 * useful ones are buried in the duplicates.
 *
 * Three levels, and the split is about who needs the line:
 *
 *   ERROR  something is wrong and an operator has to act. Goes to stderr,
 *          always, at any level.
 *   INFO   lifecycle: attach, bfdd connect and disconnect, session add and
 *          delete, and session state transitions. The default.
 *   DEBUG  per-packet and per-timeout detail that is only useful when you
 *          are already looking at a specific problem.
 *
 * State transitions are INFO on purpose. In a dataplane the session state
 * change is the most operationally valuable line the process emits, and
 * hiding it by default would mean an operator debugging a flap has to
 * restart at a higher verbosity to see what has already happened - by
 * which time the event is gone. Volume is not a good enough reason to
 * suppress the one line that says what the box decided.
 *
 * The detect-timeout line IS debug, because the transition that follows it
 * carries "detect timeout" as its reason. Two lines for one event is what
 * made the output unreadable, not the transition itself.
 *
 * Output text is unchanged from before this header existed. Only the
 * gating is new, so anything parsing these logs still works.
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

/* Errors are never gated: if the engine cannot do its job the operator
 * needs to know regardless of what verbosity was asked for. */
#define log_err(...)   fprintf(stderr, __VA_ARGS__)

#define log_info(...)  do { \
	if (bfd_log_level >= BFD_LOG_INFO) \
		printf(__VA_ARGS__); \
} while (0)

#define log_debug(...) do { \
	if (bfd_log_level >= BFD_LOG_DEBUG) \
		printf(__VA_ARGS__); \
} while (0)

#endif /* BFD_ENGINE_LOG_H */
