// SPDX-License-Identifier: GPL-2.0
/* log.c - outside main.c so test binaries link without main.o. */
#include "log.h"

int bfd_log_level = BFD_LOG_INFO;
FILE *bfd_log_err_fp;
