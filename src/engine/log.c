// SPDX-License-Identifier: GPL-2.0
/* log.c - the one definition of the level.
 *
 * Not in main.c: fsm.c, dplane.c and ktx.c all read it, and the test
 * binaries link those without main.o. A global four modules use does not
 * belong in the one that happens to parse argv.
 */
#include "log.h"

int bfd_log_level = BFD_LOG_INFO;
