// SPDX-License-Identifier: GPL-2.0
/* sock.c - the engine's UDP sockets. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "bfd_shared.h"
#include "session.h"
#include "rx.h"
#include "fsm.h"
#include "sock.h"

/* Multihop (RFC 5883) uses 4784. XDP takes over both ports once Up. */
struct rx_sock rx_socks[RX_NSOCK] = {
	{ -1, AF_INET, 0, "socket v4 control", "bind 3784 (is another BFD daemon running?)" },
	{ -1, AF_INET, 1, "socket v4 multihop (multihop disabled)",
	  "bind 4784 (multihop disabled)" },
	{ -1, AF_INET6, 0, "socket v6 control", "bind 3784 v6 (is another BFD daemon running?)" },
	{ -1, AF_INET6, 1, "socket v6 multihop (v6 multihop disabled)",
	  "bind 4784 v6 (v6 multihop disabled)" },
};

static int rx_open(struct rx_sock *r)
{
	uint16_t port = htons(r->mhop ? BFD_PORT_MHOP : PORT_CTRL);
	int on = 1;
	int fd = socket(r->family, SOCK_DGRAM, 0);

	if (fd < 0) {
		perror(r->sock_err);
		return -1;
	}
	if (r->family == AF_INET6) {
		struct sockaddr_in6 la = { .sin6_family = AF_INET6, .sin6_port = port };

		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
		if (bind(fd, (void *)&la, sizeof(la)))
			goto fail;
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
		setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
	} else {
		struct sockaddr_in la = { .sin_family = AF_INET,
					  .sin_port = port,
					  .sin_addr.s_addr = INADDR_ANY };

		if (bind(fd, (void *)&la, sizeof(la)))
			goto fail;
		setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
		setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
	}
	/* GTSM is checked per packet: Linux honours IP_MINTTL and
	 * IPV6_MINHOPCOUNT only for TCP.
	 */
	r->fd = fd;
	return 0;
fail:
	perror(r->bind_err);
	close(fd);
	return -1;
}

int rx_open_all(void)
{
	for (int i = 0; i < RX_NSOCK; i++)
		if (rx_open(&rx_socks[i]) && !rx_socks[i].mhop)
			return -1;
	return 0;
}

/* Returns the TTL or hop limit, -1 if the cmsg is missing. */
static int rx_meta(struct msghdr *mh, int family, struct bfd_addr *src, struct bfd_addr *dst)
{
	int ttl = -1;

	if (family == AF_INET6) {
		const struct sockaddr_in6 *from = mh->msg_name;

		memset(src, 0, sizeof(*src));
		memset(dst, 0, sizeof(*dst));
		memcpy(src->b, &from->sin6_addr, 16);
		for (struct cmsghdr *c = CMSG_FIRSTHDR(mh); c; c = CMSG_NXTHDR(mh, c)) {
			if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_HOPLIMIT)
				memcpy(&ttl, CMSG_DATA(c), sizeof(ttl));
			if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO)
				memcpy(dst->b, &((struct in6_pktinfo *)CMSG_DATA(c))->ipi6_addr,
				       16);
		}
	} else {
		const struct sockaddr_in *from = mh->msg_name;
		uint32_t to = 0;

		for (struct cmsghdr *c = CMSG_FIRSTHDR(mh); c; c = CMSG_NXTHDR(mh, c)) {
			if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO)
				to = ((struct in_pktinfo *)CMSG_DATA(c))->ipi_addr.s_addr;
			if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TTL)
				memcpy(&ttl, CMSG_DATA(c), sizeof(ttl));
		}
		key_set_v4(src, from->sin_addr.s_addr);
		key_set_v4(dst, to);
	}
	return ttl;
}

int rx_drain(const struct rx_sock *r, uint64_t t, int budget)
{
	int d;

	for (d = 0; d < budget; d++) {
		/* rx_accept wants it zeroed per packet. */
		__u8 buf[BFD_MAX_LEN] = { 0 };
		struct bfd_ctrl_pkt p;
		struct sockaddr_in6 from; /* either family */
		struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
		char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
		struct msghdr mh = {
			.msg_name = &from,
			.msg_namelen = sizeof(from),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cbuf,
			.msg_controllen = sizeof(cbuf),
		};
		struct bfd_addr src, dst;
		enum rx_verdict why;
		struct session *s;
		ssize_t n = recvmsg(r->fd, &mh, MSG_DONTWAIT | MSG_TRUNC);
		int ttl;

		if (n < 0)
			break;
		memcpy(&p, buf, sizeof(p));
		ttl = rx_meta(&mh, r->family, &src, &dst);
		s = rx_accept(buf, (size_t)n, ttl, &src, &dst, r->mhop, &why);
		if (s)
			fsm_rx(s, &p, t);
	}
	return d;
}

void tx_open_fallback(void)
{
	int hops = 255;

	tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (tx_sock < 0)
		perror("socket v4 fallback TX");
	else
		setsockopt(tx_sock, IPPROTO_IP, IP_TTL, &hops, sizeof(hops));
	tx6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (tx6_sock < 0)
		perror("socket v6 fallback TX");
	else
		setsockopt(tx6_sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));
}
