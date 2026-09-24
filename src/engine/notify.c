// SPDX-License-Identifier: GPL-2.0
/* notify.c - systemd's readiness protocol without libsystemd: one datagram
 * to $NOTIFY_SOCKET, and nothing when it is unset.
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "notify.h"

void sd_note(const char *msg)
{
	const char *path = getenv("NOTIFY_SOCKET");
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	socklen_t len;
	int fd;

	if (!path || (path[0] != '/' && path[0] != '@') || strlen(path) >= sizeof(sa.sun_path))
		return;
	memcpy(sa.sun_path, path, strlen(path));
	if (path[0] == '@')
		sa.sun_path[0] = '\0'; /* abstract namespace */
	len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(path));
	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return;
	(void)!sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&sa, len);
	close(fd);
}
