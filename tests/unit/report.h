// SPDX-License-Identifier: GPL-2.0
/* report.h - one line per case. Explain a failure on indented lines first; the
 * detail prints only on success.
 */
#ifndef BFD_TEST_REPORT_H
#define BFD_TEST_REPORT_H

#include <stdio.h>

static int fails;

static void report(const char *name, int bad, const char *detail)
{
	if (bad) {
		printf("FAIL %-44s\n", name);
		fails++;
	} else {
		printf("ok   %-44s %s\n", name, detail ? detail : "");
	}
}

#endif /* BFD_TEST_REPORT_H */
