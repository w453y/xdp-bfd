// SPDX-License-Identifier: GPL-2.0
/* objpath.h - locate bfd_xdp.o without depending on the working directory.
 *
 * The object is built beside the binaries, so the binary's own directory
 * is where to look; the cwd stays a last resort so an explicitly placed
 * object still works.
 */
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
	if (slash &&
	    (size_t)(slash - buf) + sizeof("/" BFD_XDP_OBJ) <= sizeof(buf)) {
		strcpy(slash, "/" BFD_XDP_OBJ);
		if (!access(buf, R_OK))
			return buf;   /* beside the binary: the build tree */
	}

	/* The install location, compiled in by the package build as
	 * -DBFD_XDP_OBJDIR=\"/usr/lib/xdp-bfd\". An installed binary lives in
	 * /usr/sbin and its object in /usr/lib/xdp-bfd, so the beside-the-
	 * binary search above misses it and this is where it is found. Absent
	 * in a plain `make` build, where beside-the-binary already works. */
#ifdef BFD_XDP_OBJDIR
	if (sizeof(BFD_XDP_OBJDIR "/" BFD_XDP_OBJ) <= sizeof(buf)) {
		strcpy(buf, BFD_XDP_OBJDIR "/" BFD_XDP_OBJ);
		if (!access(buf, R_OK))
			return buf;
	}
#endif

	return BFD_XDP_OBJ;   /* last resort: the cwd, as before */
}

#endif /* BFD_OBJPATH_H */
