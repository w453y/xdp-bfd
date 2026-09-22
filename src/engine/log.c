// SPDX-License-Identifier: GPL-2.0
/* log.c - the log level, outside main.c so test binaries link without main.o. */
#include "log.h"

int bfd_log_level = BFD_LOG_INFO;
/* NULL means stderr; see log.h for why this is a sink and not a level. */
FILE *bfd_log_err_fp;
