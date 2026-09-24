// SPDX-License-Identifier: GPL-2.0
/* log.h - ERROR always goes to stderr; INFO (default) is lifecycle and every
 * transition, since a flap cannot be debugged afterwards; DEBUG is per packet.
 */
#ifndef BFD_ENGINE_LOG_H
#define BFD_ENGINE_LOG_H

#include <stdio.h>

enum bfd_log_level {
	BFD_LOG_ERROR = 0,
	BFD_LOG_INFO = 1,
	BFD_LOG_DEBUG = 2,
};

/* --log-level */
extern int bfd_log_level;

/* NULL means stderr; the fuzz target redirects it. */
extern FILE *bfd_log_err_fp;

#define log_err(...) fprintf(bfd_log_err_fp ? bfd_log_err_fp : stderr, __VA_ARGS__)

#define log_info(...)                                                                             \
	do {                                                                                      \
		if (bfd_log_level >= BFD_LOG_INFO)                                                \
			printf(__VA_ARGS__);                                                      \
	} while (0)

#define log_debug(...)                                                                            \
	do {                                                                                      \
		if (bfd_log_level >= BFD_LOG_DEBUG)                                               \
			printf(__VA_ARGS__);                                                      \
	} while (0)

#endif /* BFD_ENGINE_LOG_H */
