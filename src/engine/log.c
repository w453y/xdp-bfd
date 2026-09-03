// SPDX-License-Identifier: GPL-2.0
/* log.c - the one definition of the level.
 *
 * Not in main.c: the test binaries link fsm.o, dplane.o and ktx.o, which
 * all read it, without main.o.
 */
#include "log.h"

int bfd_log_level = BFD_LOG_INFO;
/* NULL means stderr; see log.h for why this is a sink and not a level. */
FILE *bfd_log_err_fp;
