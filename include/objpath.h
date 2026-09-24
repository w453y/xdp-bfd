// SPDX-License-Identifier: GPL-2.0
/* objpath.h - find bfd_xdp.o: --bpf-obj, beside the binary, the install directory, the cwd. */
#ifndef BFD_OBJPATH_H
#define BFD_OBJPATH_H

#include <limits.h>
#include <string.h>
#include <unistd.h>

#define BFD_XDP_OBJ "bfd_xdp.o"

static inline const char *bfd_obj_path(const char *override)
{
	static char buf[PATH_MAX];
	ssize_t n;
	char *slash;

	if (override)
		return override;

	n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
	if (n <= 0)
		return BFD_XDP_OBJ;
	buf[n] = '\0';

	slash = strrchr(buf, '/');
	if (slash && (size_t)(slash - buf) + sizeof("/" BFD_XDP_OBJ) <= sizeof(buf)) {
		strcpy(slash, "/" BFD_XDP_OBJ);
		if (!access(buf, R_OK))
			return buf; /* the build tree */
	}

#ifdef BFD_XDP_OBJDIR
	if (sizeof(BFD_XDP_OBJDIR "/" BFD_XDP_OBJ) <= sizeof(buf)) {
		strcpy(buf, BFD_XDP_OBJDIR "/" BFD_XDP_OBJ);
		if (!access(buf, R_OK))
			return buf;
	}
#endif

	return BFD_XDP_OBJ; /* the cwd */
}

#endif /* BFD_OBJPATH_H */
