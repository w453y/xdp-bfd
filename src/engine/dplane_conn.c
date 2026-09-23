// SPDX-License-Identifier: GPL-2.0
/* dplane_conn.c - the bfddp connection: listen, authorize, frame, queue. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include "bfddp.h"
#include "log.h"
#include "dplane.h"

static int dp_listen = -1, dp_conn = -1;

/* Not cached: dp_conn changes on reconnect. */
void dp_fds(int *listen_fd, int *conn_fd)
{
	*listen_fd = dp_listen;
	*conn_fd = dp_conn;
}
static uint8_t dp_buf[4096];
static size_t dp_have;

/* dp_conn is non-blocking and the tick cannot wait, so writes queue here. Only
 * overflow or a send error drops the connection.
 */
static char dp_out[65536];
static size_t dp_out_len;

/* Both directions: queued output may end mid-frame. */
static void dp_conn_reset(void)
{
	dp_have = 0;
	dp_out_len = 0;
}

static void dp_drop_conn(const char *why)
{
	close(dp_conn);
	dp_conn = -1;
	dp_conn_reset();
	dp_sessions_orphan(why);
}

void dp_flush(void)
{
	if (dp_conn < 0)
		return;

	while (dp_out_len) {
		ssize_t n = send(dp_conn, dp_out, dp_out_len, MSG_NOSIGNAL);

		if (n > 0) {
			dp_out_len -= (size_t)n;
			memmove(dp_out, dp_out + n, dp_out_len);
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return; /* still backed up; retry next pass */
		log_err("dplane: send failed (%s), dropping connection\n",
			n < 0 ? strerror(errno) : "zero-length write");
		dp_drop_conn("send failure");
		return;
	}
}

int dp_connected(void)
{
	return dp_conn >= 0;
}

size_t dp_out_room(void)
{
	return sizeof(dp_out) - dp_out_len;
}

void dp_send(const void *msg, size_t len)
{
	if (dp_conn < 0)
		return;
	if (len > sizeof(dp_out) - dp_out_len) {
		log_err("dplane: output queue full (%zu bytes pending), dropping connection\n",
			dp_out_len);
		dp_drop_conn("output queue overflow");
		return;
	}
	memcpy(dp_out + dp_out_len, msg, len);
	dp_out_len += len;
	dp_flush();
}

/* The fuzz harness feeds dp_read through this. */
ssize_t (*dp_recv_hook)(int fd, void *buf, size_t len) = NULL;

void dp_set_conn_for_test(int fd)
{
	dp_conn = fd;
	dp_have = 0;
}

void dp_read(void)
{
	if (dp_conn < 0)
		return;
	ssize_t n = dp_recv_hook
			    ? dp_recv_hook(dp_conn, dp_buf + dp_have, sizeof(dp_buf) - dp_have)
			    : recv(dp_conn, dp_buf + dp_have, sizeof(dp_buf) - dp_have, 0);
	if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
		log_info("dplane: bfdd disconnected\n");
		dp_drop_conn("bfdd disconnected");
		return;
	}
	if (n < 0)
		return;
	dp_have += n;

	size_t off = 0;

	while (off + sizeof(struct bfddp_message_header) <= dp_have) {
		const struct bfddp_message_header *h = (const void *)(dp_buf + off);
		uint16_t mlen = ntohs(h->length);

		if (mlen < sizeof(*h) || mlen > sizeof(dp_buf)) {
			/* Framing lost: drop so bfdd reconnects on a clean
			 * boundary.
			 */
			log_err("dplane: bad frame length %u, dropping connection\n", mlen);
			dp_drop_conn("bad frame length");
			return;
		}
		if (dp_have - off < mlen)
			break;
		dp_process(dp_buf + off, mlen);
		off += mlen;
		/* dp_process may have dropped the connection. */
		if (dp_conn < 0)
			return;
	}
	if (off) {
		memmove(dp_buf, dp_buf + off, dp_have - off);
		dp_have -= off;
	}
}

/* -1 means our own uid. root is always allowed. */
static uid_t dp_peer_uid = (uid_t)-1;

void dp_set_peer_uid(uid_t uid)
{
	dp_peer_uid = uid;
}

/* UNIX sockets check SO_PEERCRED; TCP only confirms loopback. */
static int dp_peer_allowed(int fd)
{
	/* For scan-build. */
	struct sockaddr_storage ss = { 0 };
	socklen_t sslen = sizeof(ss);

	/* SO_PEERCRED succeeds on TCP too, with uid -1. */
	if (getsockname(fd, (void *)&ss, &sslen) != 0)
		return 0;

	if (ss.ss_family == AF_UNIX) {
		struct ucred cr;
		socklen_t crlen = sizeof(cr);

		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &crlen) != 0)
			return 0;
		if (cr.uid == 0)
			return 1;
		if (dp_peer_uid != (uid_t)-1)
			return cr.uid == dp_peer_uid;
		return cr.uid == geteuid();
	}

	sslen = sizeof(ss);
	if (getpeername(fd, (void *)&ss, &sslen) != 0)
		return 0;
	if (ss.ss_family == AF_INET) {
		const struct sockaddr_in *si = (const void *)&ss;

		return (ntohl(si->sin_addr.s_addr) >> 24) == 127;
	}

	return 0;
}

void dp_accept(void)
{
	if (dp_listen < 0)
		return;
	int c = accept(dp_listen, NULL, NULL);

	if (c < 0)
		return;
	if (!dp_peer_allowed(c)) {
		log_err("dplane: refusing a control connection from an unauthorized peer\n");
		close(c);
		return;
	}
	if (dp_conn >= 0) {
		log_info("dplane: replacing existing bfdd connection\n");
		close(dp_conn);
		dp_conn_reset();
		dp_sessions_orphan("connection replaced");
	}
	fcntl(c, F_SETFL, O_NONBLOCK);
	dp_conn = c;
	log_info("dplane: bfdd connected\n");
	dp_sessions_reclaim();
}

int dp_listen_init(const char *arg)
{
	/* A path is a UNIX socket, a number a TCP port on 127.0.0.1. Released
	 * FRR cannot use unixc (EINVAL through 10.7.1).
	 */
	if (arg[0] == '/') {
		dp_listen = socket(AF_UNIX, SOCK_STREAM, 0);
		if (dp_listen < 0) {
			perror("dplane socket (unix)");
			return -1;
		}
		struct sockaddr_un su = { .sun_family = AF_UNIX };

		strncpy(su.sun_path, arg, sizeof(su.sun_path) - 1);
		unlink(arg);
		if (bind(dp_listen, (void *)&su, sizeof(su)) || listen(dp_listen, 1)) {
			perror("dplane listen (unix)");
			return -1;
		}
		/* 0600, or 0660 owned by --dp-peer. */
		if (dp_peer_uid != (uid_t)-1) {
			if (chown(arg, dp_peer_uid, (gid_t)-1))
				perror("dplane chown (unix)");
			chmod(arg, 0660);
		} else {
			chmod(arg, 0600);
		}
		log_info("dplane: listening on %s (bfdd: unixc:%s)\n", arg, arg);
	} else {
		/* atoi would bind port 0 for "abc". */
		char *end;
		long parsed = strtol(arg, &end, 10);
		int port;

		if (end == arg || *end || parsed < 1 || parsed > 65535) {
			log_err("dplane: expected a port in 1-65535 or a socket path, got '%s'\n",
				arg);
			return -1;
		}
		port = (int)parsed;
		dp_listen = socket(AF_INET, SOCK_STREAM, 0);
		if (dp_listen < 0) {
			perror("dplane socket (tcp)");
			return -1;
		}
		int one = 1;

		setsockopt(dp_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		struct sockaddr_in si = {
			.sin_family = AF_INET,
			.sin_port = htons(port),
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		};
		if (bind(dp_listen, (void *)&si, sizeof(si)) || listen(dp_listen, 1)) {
			perror("dplane listen (tcp)");
			return -1;
		}
		log_info("dplane: listening on 127.0.0.1:%d (bfdd: ipv4c:127.0.0.1:%d)\n", port,
			 port);
		log_info("dplane: TCP has no peer authorization, any local process may connect\n");
	}
	fcntl(dp_listen, F_SETFL, O_NONBLOCK);
	return 0;
}
