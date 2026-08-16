// SPDX-License-Identifier: GPL-2.0
/*
 * main.c - userspace BFD endpoint (RFC 5880/5881 subset).
 *
 * M4b: FRR distributed-BFD dataplane integration. We listen on a unix
 * socket; bfdd (started with --dplaneaddr unixc:<path>) connects and
 * drives session lifecycle via the bfddp protocol. Our engine (and the
 * XDP fast path in --kernel-tx mode) runs the sessions and reports
 * state changes back. No FRR patches required.
 *
 * Modes:
 *   ./bfd_tx <local-ip> <peer-ip> [--kernel-tx <if>]      static session
 *   ./bfd_tx --dplane <port|sock-path> [--kernel-tx <if>]      bfdd-driven
 *
 * bfddp wire structs adapted from FRR bfdd/bfddp_packet.h
 * (MIT licensed, Copyright (C) 2020 NetDEF, Rafael F. Zalamena).
 * All bfddp fields are network byte order; 64-bit fields big-endian.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <endian.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#include "bfd_shared.h"
#include "util.h"
#include "session.h"
#include "dplane.h"
#include "ktx.h"
#include "fsm.h"
#include "echo_tx.h"
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>




#include "bffdp.h"


/* ---------- globals ---------- */
static int rx_sock = -1, rx6_sock = -1;
static int rxm_sock = -1;   /* v4 multihop RX, port 4784 */
static int rxm6_sock = -1;  /* v6 multihop RX, port 4784 */




/* ---------- main ---------- */
int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);

	const char *dplane_path = NULL;
	const char *ktx_if = NULL;
	const char *static_local = NULL, *static_peer = NULL;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--dplane") && i + 1 < argc)
			dplane_path = argv[++i];
		else if (!strcmp(argv[i], "--kernel-tx") && i + 1 < argc)
			ktx_if = argv[++i];
		else if (!strcmp(argv[i], "--bpf-obj") && i + 1 < argc)
			ktx_obj_path = argv[++i];
		else if (!strcmp(argv[i], "--dp-hold") && i + 1 < argc)
			dp_hold_us = strtoull(argv[++i], NULL, 10) * 1000000ull;
		else if (!static_local)
			static_local = argv[i];
		else if (!static_peer)
			static_peer = argv[i];
	}
	if (!dplane_path && (!static_local || !static_peer)) {
		fprintf(stderr,
			"usage: %s <local-ip> <peer-ip> [--kernel-tx <if>]\n"
			"       %s --dplane <port|sock-path> [--kernel-tx <if>] [--dp-hold <sec>]\n"
			"       [--bpf-obj <path>]\n",
			argv[0], argv[0]);
		return 1;
	}

	rx_sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in la = { .sin_family = AF_INET,
				  .sin_port = htons(PORT_CTRL),
				  .sin_addr.s_addr = INADDR_ANY };
	if (bind(rx_sock, (void *)&la, sizeof(la))) {
		perror("bind 3784 (is another BFD daemon running?)");
		return 1;
	}
	struct timeval tv = { .tv_usec = 2000 };
	setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	int pi = 1;
	setsockopt(rx_sock, IPPROTO_IP, IP_PKTINFO, &pi, sizeof(pi));

	/* RFC 5883 multihop control packets arrive on 4784. Bound
	 * separately so single-hop demux is untouched; the XDP path
	 * handles both ports once a session is Up, but establishment
	 * still comes through userspace. */
	rxm_sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in lam = { .sin_family = AF_INET,
				   .sin_port = htons(BFD_PORT_MHOP),
				   .sin_addr.s_addr = INADDR_ANY };
	if (bind(rxm_sock, (void *)&lam, sizeof(lam)))
		perror("bind 4784 (multihop disabled)");
	else
		setsockopt(rxm_sock, IPPROTO_IP, IP_PKTINFO, &pi, sizeof(pi));

#ifndef IPV6_MINHOPCOUNT
#define IPV6_MINHOPCOUNT 73
#endif
	rx6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	int v6only = 1;
	setsockopt(rx6_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
	struct sockaddr_in6 la6 = { .sin6_family = AF_INET6,
		.sin6_port = htons(PORT_CTRL) };
	if (bind(rx6_sock, (void *)&la6, sizeof(la6))) {
		perror("bind 3784 v6 (is another BFD daemon running?)");
		return 1;
	}
	setsockopt(rx6_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &pi, sizeof(pi));
	int minhop = 255;
	setsockopt(rx6_sock, IPPROTO_IPV6, IPV6_MINHOPCOUNT, &minhop,
		   sizeof(minhop));

	/* v6 multihop, port 4784. Deliberately NO IPV6_MINHOPCOUNT:
	 * multihop packets arrive below 255 by definition, so the
	 * kernel filter that protects the single-hop socket would
	 * drop them all. The per-session minimum is enforced in XDP
	 * against cfg->min_ttl instead, so nothing is given up. */
	rxm6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	setsockopt(rxm6_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
		   sizeof(v6only));
	struct sockaddr_in6 lam6 = { .sin6_family = AF_INET6,
				     .sin6_port = htons(BFD_PORT_MHOP) };
	if (bind(rxm6_sock, (void *)&lam6, sizeof(lam6)))
		perror("bind 4784 v6 (v6 multihop disabled)");
	else
		setsockopt(rxm6_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &pi,
			   sizeof(pi));

	/* Unbound fallback TX socket; per-slot bound sockets carry
	 * normal traffic (slot_sock). */
	tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
	int ttl = 255;
	setsockopt(tx_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	tx6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	int hops6 = 255;
	setsockopt(tx6_sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops6,
		   sizeof(hops6));

	if (ktx_if) {
		if (ktx_attach(ktx_if))
			return 1;
		echo_tx_init(ktx_if);
		use_ktx = 1;
	}
	if (dplane_path && dp_listen_init(dplane_path))
		return 1;

	srandom(getpid() ^ time(NULL));

	if (static_local) {
		struct session *s = sess_alloc();
		uint32_t sl, sp;
		inet_pton(AF_INET, static_local, &sl);
		inet_pton(AF_INET, static_peer, &sp);
		key_set_v4(&s->local, sl);
		key_set_v4(&s->peer, sp);
		s->family = AF_INET;
		s->lid         = (random() & 0x7fffffff) | 1;
		s->wire_disc   = s->lid;
		s->min_tx_us   = DEF_MIN_TX;
		s->applied_tx_us = DEF_MIN_TX;
		s->min_rx_us   = DEF_MIN_RX;
		s->detect_mult = DEF_MULT;
		s->state       = ST_DOWN;
		s->pushed_valid = 0;
		s->next_tx_us  = now_us();
		printf("bfd_tx: static session lid=%u %s -> %s%s\n",
		       s->lid, static_local, static_peer,
		       use_ktx ? " (kernel-tx)" : "");
	}

	for (;;) {
		dp_accept();
		dp_read();

		struct bfd_ctrl_pkt p;
		struct sockaddr_in from;
		struct iovec iov = { .iov_base = &p, .iov_len = sizeof(p) };
		char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
		struct msghdr mh = {
			.msg_name = &from, .msg_namelen = sizeof(from),
			.msg_iov = &iov, .msg_iovlen = 1,
			.msg_control = cbuf, .msg_controllen = sizeof(cbuf),
		};
		/* This recvmsg is the loop's clock: it blocks with the 2ms
		 * SO_RCVTIMEO set above, which is what keeps main from spinning
		 * and what sets how often the per-session tick below runs. The
		 * three drains that follow are MSG_DONTWAIT on purpose. The
		 * asymmetry is deliberate - collapsing the four into one helper
		 * means choosing one blocking discipline for all of them, which
		 * changes transmit and detect pacing. */
		ssize_t n = recvmsg(rx_sock, &mh, 0);
		uint64_t t = now_us();

		if (n >= 24 && BFD_VERS(&p) == BFD_VERSION &&
		    p.detect_mult && p.my_disc) {
			uint32_t dst_ip = 0;
			for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c;
			     c = CMSG_NXTHDR(&mh, c))
				if (c->cmsg_level == IPPROTO_IP &&
				    c->cmsg_type == IP_PKTINFO)
					dst_ip = ((struct in_pktinfo *)
						  CMSG_DATA(c))->ipi_addr.s_addr;
			struct session *rs = sess_by_wire(ntohl(p.your_disc));
			if (!rs)
				{
				struct bfd_addr fp, fl;
				key_set_v4(&fp, from.sin_addr.s_addr);
				key_set_v4(&fl, dst_ip);
				rs = sess_by_addr(&fp, &fl);
			}
			if (rs)
				fsm_rx(rs, &p, t);
		}

		/* RFC 5883 multihop control packets, port 4784. Same demux as
		 * single-hop: your_disc first, address pair as fallback. */
		while (rxm_sock >= 0) {
			struct bfd_ctrl_pkt pm;
			struct sockaddr_in fromm;
			struct iovec iovm = { .iov_base = &pm,
					      .iov_len = sizeof(pm) };
			char cbufm[CMSG_SPACE(sizeof(struct in_pktinfo))];
			struct msghdr mhm = {
				.msg_name = &fromm, .msg_namelen = sizeof(fromm),
				.msg_iov = &iovm, .msg_iovlen = 1,
				.msg_control = cbufm,
				.msg_controllen = sizeof(cbufm),
			};
			ssize_t nm = recvmsg(rxm_sock, &mhm, MSG_DONTWAIT);
		
			if (nm < 0)
				break;
			if (nm < 24 || BFD_VERS(&pm) != BFD_VERSION ||
			    !pm.detect_mult || !pm.my_disc)
				continue;
		
			uint32_t mdst = 0;
			for (struct cmsghdr *c = CMSG_FIRSTHDR(&mhm); c;
			     c = CMSG_NXTHDR(&mhm, c))
				if (c->cmsg_level == IPPROTO_IP &&
				    c->cmsg_type == IP_PKTINFO)
					mdst = ((struct in_pktinfo *)
						CMSG_DATA(c))->ipi_addr.s_addr;
		
			struct session *ms = sess_by_wire(ntohl(pm.your_disc));
			if (!ms) {
				struct bfd_addr mp, ml;
				key_set_v4(&mp, fromm.sin_addr.s_addr);
				key_set_v4(&ml, mdst);
				ms = sess_by_addr(&mp, &ml);
			}
			if (ms)
				fsm_rx(ms, &pm, now_us());
		}

		for (;;) {
			struct bfd_ctrl_pkt p6;
			struct sockaddr_in6 from6;
			struct iovec iov6 = { .iov_base = &p6,
				.iov_len = sizeof(p6) };
			char cbuf6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
			struct msghdr mh6 = {
				.msg_name = &from6,
				.msg_namelen = sizeof(from6),
				.msg_iov = &iov6, .msg_iovlen = 1,
				.msg_control = cbuf6,
				.msg_controllen = sizeof(cbuf6),
			};
			ssize_t n6 = recvmsg(rx6_sock, &mh6, MSG_DONTWAIT);
			if (n6 < 0)
				break;
			if (n6 < 24 || BFD_VERS(&p6) != BFD_VERSION ||
			    !p6.detect_mult || !p6.my_disc)
				continue;
			struct bfd_addr fp6 = {0}, fl6 = {0};
			memcpy(fp6.b, &from6.sin6_addr, 16);
			for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh6); c;
			     c = CMSG_NXTHDR(&mh6, c))
				if (c->cmsg_level == IPPROTO_IPV6 &&
				    c->cmsg_type == IPV6_PKTINFO)
					memcpy(fl6.b,
					       &((struct in6_pktinfo *)
						CMSG_DATA(c))->ipi6_addr, 16);
			struct session *rs6 = sess_by_wire(ntohl(p6.your_disc));
			if (!rs6)
				rs6 = sess_by_addr(&fp6, &fl6);
			if (rs6)
				fsm_rx(rs6, &p6, t);
		}

		/* v6 multihop control packets, port 4784. */
		while (rxm6_sock >= 0) {
			struct bfd_ctrl_pkt pm6;
			struct sockaddr_in6 fromm6;
			struct iovec iovm6 = { .iov_base = &pm6,
					       .iov_len = sizeof(pm6) };
			char cbufm6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
			struct msghdr mhm6 = {
				.msg_name = &fromm6,
				.msg_namelen = sizeof(fromm6),
				.msg_iov = &iovm6, .msg_iovlen = 1,
				.msg_control = cbufm6,
				.msg_controllen = sizeof(cbufm6),
			};
			ssize_t nm6 = recvmsg(rxm6_sock, &mhm6, MSG_DONTWAIT);
		
			if (nm6 < 0)
				break;
			if (nm6 < 24 || BFD_VERS(&pm6) != BFD_VERSION ||
			    !pm6.detect_mult || !pm6.my_disc)
				continue;
		
			struct bfd_addr mp6 = {0}, ml6 = {0};
			memcpy(mp6.b, &fromm6.sin6_addr, 16);
			for (struct cmsghdr *c = CMSG_FIRSTHDR(&mhm6); c;
			     c = CMSG_NXTHDR(&mhm6, c))
				if (c->cmsg_level == IPPROTO_IPV6 &&
				    c->cmsg_type == IPV6_PKTINFO)
					memcpy(ml6.b,
					       &((struct in6_pktinfo *)
						CMSG_DATA(c))->ipi6_addr, 16);
		
			struct session *ms6 = sess_by_wire(ntohl(pm6.your_disc));
			if (!ms6)
				ms6 = sess_by_addr(&mp6, &ml6);
			if (ms6)
				fsm_rx(ms6, &pm6, t);
		}

		if (dp_reconcile_us && t >= dp_reconcile_us) {
			dp_reconcile_us = 0;
			for (int i = 0; i < MAX_SESSIONS; i++)
				if (sessions[i].used && sessions[i].orphaned)
					sess_teardown_one(&sessions[i],
						"not re-added by bfdd");
		}

		for (int i = 0; i < MAX_SESSIONS; i++) {
			struct session *cs = &sessions[i];
			if (!cs->used)
				continue;
			if (cs->orphaned && t >= cs->orphan_deadline_us) {
				sess_teardown_one(cs, "hold expired");
				continue;
			}
			ktx_poll_map(cs, t);
			fsm_detect(cs, t);
			fsm_tx(cs, t);
			echo_tx_maybe(cs, t);
			ktx_mirror(cs);
		}
	}
	return 0;
}
