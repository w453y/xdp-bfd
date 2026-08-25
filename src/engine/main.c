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
#include <poll.h>
#include <sys/timerfd.h>
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
#include "stats.h"
#include "echo_tx.h"
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>




#include "bffdp.h"


/* ---------- globals ---------- */
static int rx_sock = -1, rx6_sock = -1;
static int rxm_sock = -1;   /* v4 multihop RX, port 4784 */
static int rxm6_sock = -1;  /* v6 multihop RX, port 4784 */
/* The loop's clock. SO_RCVTIMEO sleeps on the jiffy timer wheel, so a
 * sub-millisecond tick was rounded up and the loop ran no faster;
 * docs/tick-ladder/ measures that. A timerfd is hrtimer-backed and is
 * also readable by poll, so the wait covers every socket rather than
 * blocking on the v4 one and leaving v6 to wait out its timeout. */
static int tick_fd = -1;




/* ---------- main ---------- */
/* Main loop tick in microseconds, the SO_RCVTIMEO on the control
 * socket. Overridable with --tick-us so the detection ladder can
 * vary it without a rebuild. */
#define TICK_US_DEFAULT 2000
static unsigned tick_us = TICK_US_DEFAULT;

/* How often the loop actually runs, and how often the control-socket
 * recvmsg returned a packet rather than timing out. Below roughly a
 * 1ms tick the arriving mesh traffic returns it first, so the timeout
 * stops being what clocks the loop and detection resolution stops
 * improving. Reported rather than reasoned about. */
uint64_t loop_passes;
uint64_t loop_rx_wakeups;

/* Inter-pass gap histogram, log2 buckets in microseconds. The ten-second
 * average cannot tell a steady period from fast passes plus stalls, and
 * four explanations for the observed rate have already been wrong. */
uint64_t loop_gap_us[24];

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
		else if (!strcmp(argv[i], "--stats-dump") && i + 1 < argc)
			stats_path = argv[++i];
		else if (!strcmp(argv[i], "--sweep-us") && i + 1 < argc) {
			const char *a = argv[++i];
			char *end;
			unsigned long long v = strtoull(a, &end, 10);

			/* Bounded on both sides. Below ~0.5ms the timer churn
			 * starts to cost more than the quantization it removes;
			 * above 100ms the sweep is slower than any detection
			 * budget it is meant to serve. */
			if (end == a || *end || v < 500 || v > 100000) {
				fprintf(stderr,
					"--sweep-us: expected 500-100000, got '%s'\n",
					a);
				return 1;
			}
			ktx_sweep_ns = v * 1000ull;
		}
		else if (!strcmp(argv[i], "--tick-us") && i + 1 < argc) {
			const char *a = argv[++i];
			char *end;
			unsigned long long v = strtoull(a, &end, 10);

			/* The main loop's tick. The control-socket recvmsg blocks with
			 * this timeout, so it sets how often the per-session transmit
			 * and detect pass runs, and with it the resolution of userspace
			 * detection - which the sweep ladder showed is the only thing
			 * that declares a session Down in engine mode. Bounded at 200us
			 * because every pass walks all configured sessions, and at the
			 * same 100ms ceiling as the sweep. */
			if (end == a || *end || v < 200 || v > 100000) {
				fprintf(stderr,
					"--tick-us: expected 200-100000, got '%s'\n",
					a);
				return 1;
			}
			tick_us = (unsigned)v;
			/* SO_RCVTIMEO sleeps on the jiffy timer wheel, not an hrtimer,
			 * so a request under one jiffy is rounded up and the loop runs
			 * no faster. There is no portable way to read CONFIG_HZ from
			 * userspace (_SC_CLK_TCK is USER_HZ, fixed at 100), so this is
			 * the common 1000Hz value. On this testbed a 200us tick gave a
			 * measured 1024-2047us loop period; see docs/tick-ladder/.
			 * Warned rather than rejected: the arm is worth reproducing. */
			if (tick_us < 1000)
				fprintf(stderr,
					"--tick-us: %uus is likely below one jiffy; "
					"SO_RCVTIMEO will round it up\n", tick_us);
		}
		else if (!strcmp(argv[i], "--xdp-mode") && i + 1 < argc) {
			const char *m = argv[++i];
			if (!strcmp(m, "generic") || !strcmp(m, "skb"))
				ktx_xdp_flags = XDP_FLAGS_SKB_MODE;
			else if (!strcmp(m, "drv") || !strcmp(m, "native"))
				ktx_xdp_flags = XDP_FLAGS_DRV_MODE;
			else {
				fprintf(stderr,
					"--xdp-mode: expected drv or generic, got '%s'\n",
					m);
				return 1;
			}
		}
		else if (!strcmp(argv[i], "--dp-hold") && i + 1 < argc) {
			const char *a = argv[++i];
			char *end;
			unsigned long long v = strtoull(a, &end, 10);

			/* A NULL endptr made "abc" a silent zero-second
			 * hold and "10s" a silent 10 - both look like the
			 * flag worked. */
			if (end == a || *end || v > 86400) {
				fprintf(stderr,
					"--dp-hold: expected seconds (0-86400), got '%s'\n",
					a);
				return 1;
			}
			dp_hold_us = v * 1000000ull;
		}
		else if (!static_local)
			static_local = argv[i];
		else if (!static_peer)
			static_peer = argv[i];
	}
	if (!dplane_path && (!static_local || !static_peer)) {
		fprintf(stderr,
			"usage: %s <local-ip> <peer-ip> [--kernel-tx <if>]\n"
			"       %s --dplane <port|sock-path> [--kernel-tx <if>] [--dp-hold <sec>]\n"
			"       [--bpf-obj <path>] [--xdp-mode drv|generic]\n"
			"       [--stats-dump <path>]   (SIGUSR1 writes it)\n"
			"       [--sweep-us <500-100000>]\n"
			"       [--tick-us <200-100000>]\n",
			argv[0], argv[0]);
		return 1;
	}

	rx_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (rx_sock < 0) {
		perror("socket v4 control");
		return 1;
	}
	struct sockaddr_in la = { .sin_family = AF_INET,
				  .sin_port = htons(PORT_CTRL),
				  .sin_addr.s_addr = INADDR_ANY };
	if (bind(rx_sock, (void *)&la, sizeof(la))) {
		perror("bind 3784 (is another BFD daemon running?)");
		return 1;
	}
	struct timeval tv = { .tv_usec = 1000 };   /* drains only */
	if (tick_us != TICK_US_DEFAULT)
		printf("engine: main loop tick %uus (default %uus)\n",
		       tick_us, TICK_US_DEFAULT);
	setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	tick_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (tick_fd < 0) {
		perror("timerfd_create");
		return 1;
	}
	{
		struct itimerspec its = {
			.it_interval = { .tv_sec  = tick_us / 1000000,
					 .tv_nsec = (tick_us % 1000000) * 1000 },
		};
		its.it_value = its.it_interval;
		if (timerfd_settime(tick_fd, 0, &its, NULL)) {
			perror("timerfd_settime");
			return 1;
		}
	}
	int pi = 1;
	setsockopt(rx_sock, IPPROTO_IP, IP_PKTINFO, &pi, sizeof(pi));
	/* GTSM (RFC 5881 s5) by reading the arriving TTL, not by asking
	 * the kernel to filter.
	 *
	 * IP_MINTTL is accepted on a UDP socket and then never consulted:
	 * Linux enforces it only in tcp_v4_rcv, which has its own MIB
	 * counter, TCPMinTtlDrop. The same is true of IPV6_MINHOPCOUNT on
	 * the v6 socket below, which had been relying on it since long
	 * before anything could test the userspace path. Both were
	 * silently doing nothing; tests/netns_userspace.py caught it.
	 *
	 * So the same treatment the multihop sockets already get, against
	 * a fixed 255 rather than a per-session minimum. */
	setsockopt(rx_sock, IPPROTO_IP, IP_RECVTTL, &pi, sizeof(pi));

	/* RFC 5883 multihop control packets arrive on 4784. Bound
	 * separately so single-hop demux is untouched; the XDP path
	 * handles both ports once a session is Up, but establishment
	 * still comes through userspace. */
	rxm_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (rxm_sock < 0) {
		perror("socket v4 multihop (multihop disabled)");
	} else {
		struct sockaddr_in lam = { .sin_family = AF_INET,
					   .sin_port = htons(BFD_PORT_MHOP),
					   .sin_addr.s_addr = INADDR_ANY };
		if (bind(rxm_sock, (void *)&lam, sizeof(lam))) {
			perror("bind 4784 (multihop disabled)");
			close(rxm_sock);
			rxm_sock = -1;
		} else {
			setsockopt(rxm_sock, IPPROTO_IP, IP_PKTINFO, &pi,
				   sizeof(pi));
			/* No IP_MINTTL here: the minimum is per session, from
			 * the ADD, and one socket serves them all. Ask for the
			 * arriving TTL instead and compare after demux. */
			setsockopt(rxm_sock, IPPROTO_IP, IP_RECVTTL, &pi,
				   sizeof(pi));
		}
	}

#ifndef IPV6_MINHOPCOUNT
#define IPV6_MINHOPCOUNT 73
#endif
	rx6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (rx6_sock < 0) {
		perror("socket v6 control");
		return 1;
	}
	int v6only = 1;
	setsockopt(rx6_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
	struct sockaddr_in6 la6 = { .sin6_family = AF_INET6,
		.sin6_port = htons(PORT_CTRL) };
	if (bind(rx6_sock, (void *)&la6, sizeof(la6))) {
		perror("bind 3784 v6 (is another BFD daemon running?)");
		return 1;
	}
	setsockopt(rx6_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &pi, sizeof(pi));
	/* Not IPV6_MINHOPCOUNT - see the IP_RECVTTL comment above; it is
	 * enforced only for TCP, so this socket has been unguarded. */
	setsockopt(rx6_sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &pi,
		   sizeof(pi));

	/* v6 multihop, port 4784. Deliberately NO IPV6_MINHOPCOUNT:
	 * multihop packets arrive below 255 by definition, so the
	 * kernel filter that protects the single-hop socket would
	 * drop them all. The per-session minimum is enforced in XDP
	 * against cfg->min_ttl instead, so nothing is given up. */
	rxm6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (rxm6_sock < 0) {
		perror("socket v6 multihop (v6 multihop disabled)");
	} else {
		setsockopt(rxm6_sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only,
			   sizeof(v6only));
		struct sockaddr_in6 lam6 = { .sin6_family = AF_INET6,
					     .sin6_port = htons(BFD_PORT_MHOP) };
		if (bind(rxm6_sock, (void *)&lam6, sizeof(lam6))) {
			perror("bind 4784 v6 (v6 multihop disabled)");
			close(rxm6_sock);
			rxm6_sock = -1;
		} else {
			setsockopt(rxm6_sock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
				   &pi, sizeof(pi));
			/* Same reasoning as the v4 multihop socket: the minimum
			 * is per session, so read the hop limit per packet. */
			setsockopt(rxm6_sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
				   &pi, sizeof(pi));
		}
	}

	/* Unbound fallback TX socket; per-slot bound sockets carry
	 * normal traffic (slot_sock). */
	tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (tx_sock < 0) {
		perror("socket v4 fallback TX");
	} else {
		int ttl = 255;
		setsockopt(tx_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	}
	tx6_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (tx6_sock < 0) {
		perror("socket v6 fallback TX");
	} else {
		int hops6 = 255;
		setsockopt(tx6_sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops6,
			   sizeof(hops6));
	}

	if (ktx_if) {
		if (ktx_attach(ktx_if))
			return 1;
		echo_tx_init(ktx_if);
		use_ktx = 1;
	}
	if (dplane_path && dp_listen_init(dplane_path))
		return 1;

	srandom(getpid() ^ time(NULL));
	/* The only signal the engine handles. It sets a flag; the dump
	 * happens in the loop below, so nothing in it needs to be
	 * async-signal-safe. */
	signal(SIGUSR1, stats_on_signal);

	if (static_local) {
		struct session *s = sess_alloc();
		/* Family from the address text: a colon means v6. Both
		 * arguments must agree - a session cannot span families, and
		 * silently picking one would build a key that matches nothing
		 * arriving. */
		int fam = strchr(static_local, ':') ? AF_INET6 : AF_INET;

		if ((strchr(static_peer, ':') != NULL) != (fam == AF_INET6)) {
			fprintf(stderr,
				"static: %s and %s are different families\n",
				static_local, static_peer);
			return 1;
		}
		if (fam == AF_INET6) {
			struct in6_addr sl6, sp6;

			/* Checked, unlike before: a typo used to produce a
			 * zero address and a session that could never match. */
			if (inet_pton(AF_INET6, static_local, &sl6) != 1 ||
			    inet_pton(AF_INET6, static_peer, &sp6) != 1) {
				fprintf(stderr, "static: bad IPv6 address\n");
				return 1;
			}
			key_set_v6(&s->local, &sl6);
			key_set_v6(&s->peer, &sp6);
		} else {
			uint32_t sl, sp;

			if (inet_pton(AF_INET, static_local, &sl) != 1 ||
			    inet_pton(AF_INET, static_peer, &sp) != 1) {
				fprintf(stderr, "static: bad IPv4 address\n");
				return 1;
			}
			key_set_v4(&s->local, sl);
			key_set_v4(&s->peer, sp);
		}
		s->family = fam;
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
		/* Anything that did not fit the socket last pass. Cheap when
		 * the queue is empty, which is the normal case. */
		dp_flush();

		if (stats_wanted) {
			stats_wanted = 0;
			stats_dump();
		}

		struct bfd_ctrl_pkt p;
		struct sockaddr_in from;
		struct iovec iov = { .iov_base = &p, .iov_len = sizeof(p) };
		char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo)) +
			  CMSG_SPACE(sizeof(int))];
		struct msghdr mh = {
			.msg_name = &from, .msg_namelen = sizeof(from),
			.msg_iov = &iov, .msg_iovlen = 1,
			.msg_control = cbuf, .msg_controllen = sizeof(cbuf),
		};
		/* Packets drained per socket per pass. Each of these loops
		 * used to run until EAGAIN, so a sustained flood of frames
		 * XDP passes to the stack kept the loop here and starved
		 * everything below it - transmit, detection, the map poll,
		 * the dplane read. The process stays alive and does nothing,
		 * which is the failure mode no process-liveness check sees.
		 *
		 * MAX_SESSIONS is one packet per configured session per pass,
		 * so a legitimate burst still clears in a single iteration and
		 * anything larger spreads across the next few 2ms ticks
		 * instead of monopolising this one.
		 */
		const int drain_budget = MAX_SESSIONS;

		/* This poll is the loop's clock. It waits on a timerfd armed at
		 * --tick-us and on every RX socket at once, so a v6 packet no
		 * longer waits out the v4 socket's timeout, and the tick is not
		 * rounded up to a jiffy the way SO_RCVTIMEO was (docs/tick-ladder/).
		 *
		 * All four drains below are now non-blocking. The drain budget is
		 * what bounds a pass, not the blocking discipline: a sustained
		 * flood still spreads across ticks instead of monopolising one. */
		struct pollfd pfd[7] = {0};
		int dp_l = -1, dp_c = -1;

		dp_fds(&dp_l, &dp_c);
		int np = 0;
		{
			uint64_t exp;

			pfd[np].fd = tick_fd; pfd[np++].events = POLLIN;
			if (rx_sock >= 0)
				{ pfd[np].fd = rx_sock; pfd[np++].events = POLLIN; }
			if (rx6_sock >= 0)
				{ pfd[np].fd = rx6_sock; pfd[np++].events = POLLIN; }
			if (rxm_sock >= 0)
				{ pfd[np].fd = rxm_sock; pfd[np++].events = POLLIN; }
			if (rxm6_sock >= 0)
				{ pfd[np].fd = rxm6_sock; pfd[np++].events = POLLIN; }
			if (dp_l >= 0)
				{ pfd[np].fd = dp_l; pfd[np++].events = POLLIN; }
			if (dp_c >= 0)
				{ pfd[np].fd = dp_c; pfd[np++].events = POLLIN; }
			poll(pfd, np, -1);
			/* Drain the timer so it does not stay readable. */
			if (pfd[0].revents & POLLIN)
				(void)!read(tick_fd, &exp, sizeof(exp));
		}
		/* Only touch a socket poll said is readable. Four blind
		 * MSG_DONTWAIT drains per pass cost four EAGAIN syscalls
		 * every tick, which at a 200us tick is 20k/s of nothing. */
		int rd4 = 0, rd6 = 0, rdm4 = 0, rdm6 = 0, rdl = 0, rdc = 0;
		for (int k = 0; k < np; k++) {
			if (!(pfd[k].revents & POLLIN))
				continue;
			if (pfd[k].fd == rx_sock)   rd4 = 1;
			if (pfd[k].fd == rx6_sock)  rd6 = 1;
			if (pfd[k].fd == rxm_sock)  rdm4 = 1;
			if (pfd[k].fd == rxm6_sock) rdm6 = 1;
			if (dp_l >= 0 && pfd[k].fd == dp_l) rdl = 1;
			if (dp_c >= 0 && pfd[k].fd == dp_c) rdc = 1;
		}
		if (rdl)
			dp_accept();
		if (rdc)
			dp_read();
		ssize_t n = rd4 ? recvmsg(rx_sock, &mh, MSG_DONTWAIT | MSG_TRUNC)
				  : -1;
		uint64_t t = now_us();
		loop_passes++;
		{
			static uint64_t prev;
			if (prev) {
				uint64_t d = t - prev;
				int b = 0;
				while (d >>= 1)
					b++;
				loop_gap_us[b < 24 ? b : 23]++;
			}
			prev = t;
		}
		if (n >= 0)
			loop_rx_wakeups++;

		/* Same predicate the XDP path uses. Userspace used to check a
		 * shorter list that ignored p.len entirely, so a packet
		 * claiming 200 bytes inside a 24-byte datagram was accepted
		 * here and rejected in the kernel. */
		/* cmsgs first: the arriving TTL decides whether the packet is
		 * acceptable at all, so it is checked alongside the header
		 * rather than after demux. rttl stays -1 when the cmsg is
		 * missing, which drops the packet - that would mean the
		 * setsockopt did not take, and silently accepting anything is
		 * how this path came to be unguarded in the first place. */
		uint32_t dst_ip = 0;
		int rttl = -1;

		if (n >= 0)
			for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c;
			     c = CMSG_NXTHDR(&mh, c)) {
				if (c->cmsg_level == IPPROTO_IP &&
				    c->cmsg_type == IP_PKTINFO)
					dst_ip = ((struct in_pktinfo *)
						  CMSG_DATA(c))->ipi_addr.s_addr;
				if (c->cmsg_level == IPPROTO_IP &&
				    c->cmsg_type == IP_TTL)
					memcpy(&rttl, CMSG_DATA(c), sizeof(rttl));
			}

		if (n >= 0 && rttl == 255 &&
		    bfd_ctrl_check(p.vers_diag, p.flags, p.detect_mult, p.len,
				   p.my_disc, (__u32)n) == BFD_CTRL_ACCEPT) {
			/* Demux (RFC 5880 s6.8.6), the same rule XDP applies:
			 * your_disc must name our session, or be zero with the
			 * peer in Down or AdminDown - it has lost state, or is
			 * starting. Falling back to the address pair on any miss
			 * accepted packets naming a discriminator we never issued,
			 * which is the divergence tests/netns_userspace.py found. */
			uint32_t ydisc = ntohl(p.your_disc);
			struct session *rs = sess_by_wire(ydisc);

			if (!rs && ydisc == 0 && BFD_STATE(&p) <= ST_DOWN) {
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
		for (int d = 0; rdm4 && rxm_sock >= 0 && d < drain_budget; d++) {
			struct bfd_ctrl_pkt pm;
			struct sockaddr_in fromm;
			struct iovec iovm = { .iov_base = &pm,
					      .iov_len = sizeof(pm) };
			/* Two cmsgs now: IP_PKTINFO and IP_TTL. A buffer sized
			 * for one silently truncates the second, and the TTL
			 * check would then never see a value. */
			char cbufm[CMSG_SPACE(sizeof(struct in_pktinfo)) +
				   CMSG_SPACE(sizeof(int))];
			struct msghdr mhm = {
				.msg_name = &fromm, .msg_namelen = sizeof(fromm),
				.msg_iov = &iovm, .msg_iovlen = 1,
				.msg_control = cbufm,
				.msg_controllen = sizeof(cbufm),
			};
			ssize_t nm = recvmsg(rxm_sock, &mhm, MSG_DONTWAIT | MSG_TRUNC);
		
			if (nm < 0)
				break;
			if (bfd_ctrl_check(pm.vers_diag, pm.flags,
					   pm.detect_mult, pm.len, pm.my_disc,
					   (__u32)nm) != BFD_CTRL_ACCEPT)
				continue;
		
			uint32_t mdst = 0;
			int mttl = -1;
			for (struct cmsghdr *c = CMSG_FIRSTHDR(&mhm); c;
			     c = CMSG_NXTHDR(&mhm, c)) {
				if (c->cmsg_level == IPPROTO_IP &&
				    c->cmsg_type == IP_PKTINFO)
					mdst = ((struct in_pktinfo *)
						CMSG_DATA(c))->ipi_addr.s_addr;
				if (c->cmsg_level == IPPROTO_IP &&
				    c->cmsg_type == IP_TTL)
					memcpy(&mttl, CMSG_DATA(c), sizeof(mttl));
			}
		
			/* Same demux rule as the single-hop path above. */
			uint32_t mydisc = ntohl(pm.your_disc);
			struct session *ms = sess_by_wire(mydisc);

			if (!ms && mydisc == 0 && BFD_STATE(&pm) <= ST_DOWN) {
				struct bfd_addr mp, ml;

				key_set_v4(&mp, fromm.sin_addr.s_addr);
				key_set_v4(&ml, mdst);
				ms = sess_by_addr(&mp, &ml);
			}
			/* GTSM against this session's own minimum, the same rule
			 * the kernel applies against cfg->min_ttl. Enforced after
			 * demux because that is when the minimum is known. A
			 * missing cmsg (mttl < 0) means the setsockopt did not
			 * take, so drop rather than silently accept anything. */
			if (ms && (mttl < 0 || mttl < (int)ms->min_ttl))
				continue;
			if (ms)
				fsm_rx(ms, &pm, now_us());
		}

		for (int d = 0; rd6 && d < drain_budget; d++) {
			struct bfd_ctrl_pkt p6;
			struct sockaddr_in6 from6;
			struct iovec iov6 = { .iov_base = &p6,
				.iov_len = sizeof(p6) };
			char cbuf6[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
				   CMSG_SPACE(sizeof(int))];
			struct msghdr mh6 = {
				.msg_name = &from6,
				.msg_namelen = sizeof(from6),
				.msg_iov = &iov6, .msg_iovlen = 1,
				.msg_control = cbuf6,
				.msg_controllen = sizeof(cbuf6),
			};
			ssize_t n6 = recvmsg(rx6_sock, &mh6, MSG_DONTWAIT | MSG_TRUNC);
			if (n6 < 0)
				break;
			if (bfd_ctrl_check(p6.vers_diag, p6.flags,
					   p6.detect_mult, p6.len, p6.my_disc,
					   (__u32)n6) != BFD_CTRL_ACCEPT)
				continue;
			struct bfd_addr fp6 = {0}, fl6 = {0};
			int rhl6 = -1;

			memcpy(fp6.b, &from6.sin6_addr, 16);
			for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh6); c;
			     c = CMSG_NXTHDR(&mh6, c)) {
				if (c->cmsg_level == IPPROTO_IPV6 &&
				    c->cmsg_type == IPV6_HOPLIMIT)
					memcpy(&rhl6, CMSG_DATA(c), sizeof(rhl6));
				if (c->cmsg_level == IPPROTO_IPV6 &&
				    c->cmsg_type == IPV6_PKTINFO)
					memcpy(fl6.b,
					       &((struct in6_pktinfo *)
						CMSG_DATA(c))->ipi6_addr, 16);
			}
			/* Single-hop: exactly 255, same rule as v4 above. */
			if (rhl6 != 255)
				continue;
			/* Same demux rule as the v4 single-hop path above. */
			uint32_t ydisc6 = ntohl(p6.your_disc);
			struct session *rs6 = sess_by_wire(ydisc6);

			if (!rs6 && ydisc6 == 0 && BFD_STATE(&p6) <= ST_DOWN)
				rs6 = sess_by_addr(&fp6, &fl6);
			if (rs6)
				fsm_rx(rs6, &p6, t);
		}

		/* v6 multihop control packets, port 4784. */
		for (int d = 0; rdm6 && rxm6_sock >= 0 && d < drain_budget; d++) {
			struct bfd_ctrl_pkt pm6;
			struct sockaddr_in6 fromm6;
			struct iovec iovm6 = { .iov_base = &pm6,
					       .iov_len = sizeof(pm6) };
			char cbufm6[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
				    CMSG_SPACE(sizeof(int))];
			struct msghdr mhm6 = {
				.msg_name = &fromm6,
				.msg_namelen = sizeof(fromm6),
				.msg_iov = &iovm6, .msg_iovlen = 1,
				.msg_control = cbufm6,
				.msg_controllen = sizeof(cbufm6),
			};
			ssize_t nm6 = recvmsg(rxm6_sock, &mhm6, MSG_DONTWAIT | MSG_TRUNC);
		
			if (nm6 < 0)
				break;
			if (bfd_ctrl_check(pm6.vers_diag, pm6.flags,
					   pm6.detect_mult, pm6.len, pm6.my_disc,
					   (__u32)nm6) != BFD_CTRL_ACCEPT)
				continue;
		
			struct bfd_addr mp6 = {0}, ml6 = {0};
			memcpy(mp6.b, &fromm6.sin6_addr, 16);
			int mhl6 = -1;
			for (struct cmsghdr *c = CMSG_FIRSTHDR(&mhm6); c;
			     c = CMSG_NXTHDR(&mhm6, c)) {
				if (c->cmsg_level == IPPROTO_IPV6 &&
				    c->cmsg_type == IPV6_HOPLIMIT)
					memcpy(&mhl6, CMSG_DATA(c), sizeof(mhl6));
				if (c->cmsg_level == IPPROTO_IPV6 &&
				    c->cmsg_type == IPV6_PKTINFO)
					memcpy(ml6.b,
					       &((struct in6_pktinfo *)
						CMSG_DATA(c))->ipi6_addr, 16);
			}
		
			/* Same demux rule as the v4 single-hop path above. */
			uint32_t mydisc6 = ntohl(pm6.your_disc);
			struct session *ms6 = sess_by_wire(mydisc6);

			if (!ms6 && mydisc6 == 0 && BFD_STATE(&pm6) <= ST_DOWN)
				ms6 = sess_by_addr(&mp6, &ml6);
			/* Same per-session GTSM as the v4 multihop path. */
			if (ms6 && (mhl6 < 0 || mhl6 < (int)ms6->min_ttl))
				continue;
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

		/* One map fetch for the whole pass; each session reads its own
		 * entry out of it below. */
		ktx_poll_all();
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
