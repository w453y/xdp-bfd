// SPDX-License-Identifier: GPL-2.0
/*
 * main.c - userspace BFD endpoint (RFC 5880/5881 subset).
 *
 * Runs as a distributed-BFD data plane for FRR: bfdd connects over the
 * bfddp protocol and drives session lifecycle, this engine runs the
 * sessions and reports state changes back. Stock FRR, no patches.
 *
 * Modes:
 *   ./bfd_tx <local-ip> <peer-ip> [--kernel-tx <if>]    static session
 *   ./bfd_tx --dplane <port|sock-path> [--kernel-tx <if>]  bfdd-driven
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
#include <sys/utsname.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#include "bfd_shared.h"
#include "bfd_auth.h"
#include "util.h"
#include "log.h"
#include "session.h"
#include <pwd.h>

#include "dplane.h"
#include "rx.h"
#include "ktx.h"
#include "fsm.h"
#include "stats.h"
#include "echo_tx.h"
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>




#include "bfddp.h"


/* ---------- globals ---------- */
static int rx_sock = -1, rx6_sock = -1;
static int rxm_sock = -1;   /* v4 multihop RX, port 4784 */
static int rxm6_sock = -1;  /* v6 multihop RX, port 4784 */
/* The loop's clock. Hrtimer-backed and pollable, so one wait covers
 * every socket and a sub-millisecond tick is honoured - SO_RCVTIMEO
 * sleeps on the jiffy wheel and rounds anything under 1ms up. */
static int tick_fd = -1;





/* ---------- main ---------- */
/* Main loop tick in microseconds: the interval of the timerfd the
 * poll waits on. Overridable with --tick-us so the detection ladder
 * can vary it without a rebuild. */
#define TICK_US_DEFAULT 2000
static unsigned tick_us = TICK_US_DEFAULT;


/* How often the loop actually runs, and how often the control-socket
 * recvmsg returned a packet rather than timing out. Below roughly a
 * 1ms tick the arriving mesh traffic returns it first, so the timeout
 * stops being what clocks the loop and detection resolution stops
 * improving. Reported rather than reasoned about. */
uint64_t loop_passes;
/* --demand, for static mode only: under bfdd the flag arrives per session
 * on the bfddp ADD. Without it standalone mode cannot reach demand mode at
 * all, which left the one behaviour that only shows up there - a session
 * whose detection is held and which therefore has to verify its own path -
 * reachable only from a full FRR testbed. */
static int static_demand;
static int check_only;
uint64_t loop_rx_wakeups;

/* Inter-pass gap histogram, log2 buckets in microseconds. The ten-second
 * average cannot tell a steady period from fast passes plus stalls, and
 * four explanations for the observed rate have already been wrong. */
uint64_t loop_gap_us[24];

/* Re-choose keys whose periods have moved on.
 *
 * The control plane sends the whole chain once and lets this side follow
 * the clock, so nothing arrives to prompt a rollover: it has to be
 * noticed. Sessions are few and the periods are in whole seconds, so a
 * pass a second costs nothing and is well inside the resolution anyone
 * can configure.
 */
static void auth_rollover_tick(void)
{
	static int64_t last;
	int64_t now = (int64_t)time(NULL);
	int i;

	if (now == last)
		return;
	last = now;

	for (i = 0; i < MAX_SESSIONS; i++) {
		struct session *s = &sessions[i];

		if (!s->used || !s->auth_nkeys)
			continue;
		/* Nothing changes until the next boundary, and a session
		 * whose keys never expire has none. */
		if (s->auth_next_change == 0 || now < s->auth_next_change)
			continue;
		if (session_auth_evaluate(s, now))
			log_info("lid=%u authentication key %u is now in use\n",
				 s->lid, s->auth_keyid);
		/* The acceptable set is evaluated here too, so the program
		 * is refreshed whether or not the transmit key moved. */
		ktx_mirror(s);
	}
}

/* SIGTERM and SIGINT ask for an orderly exit.
 *
 * Without this the process simply died. bpf_link detached the program,
 * which is correct, but the peer then discovered the loss the slow way: a
 * detect timeout, diag 1, after a full detection time. That is exactly the
 * outcome fsm_announce_down exists to avoid, on the most common orderly
 * shutdown there is - systemctl stop sends SIGTERM.
 */
static volatile sig_atomic_t shutdown_wanted;

static void shutdown_on_signal(int sig)
{
	(void)sig;
	shutdown_wanted = 1;
}

#ifndef BFD_XDP_VERSION
#define BFD_XDP_VERSION "0.0.0-dev"
#endif

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);

	const char *dplane_path = NULL;
	const char *ktx_if = NULL;
	const char *static_local = NULL, *static_peer = NULL;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--version")) {
			printf("xdp-bfd %s\n", BFD_XDP_VERSION);
			return 0;
		}
		else if (!strcmp(argv[i], "--dplane") && i + 1 < argc)
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
				log_err(
					"--sweep-us: expected 500-100000, got '%s'\n",
					a);
				return 1;
			}
			ktx_sweep_ns = v * 1000ull;
		}
		else if (!strcmp(argv[i], "--deadman-us") && i + 1 < argc) {
			const char *a = argv[++i];
			char *end;
			unsigned long long v = strtoull(a, &end, 10);

			/* 0 is the documented off switch, so it is not a
			 * range error. Above zero the floor is 50ms: the
			 * worst loop gap measured over 651347 passes was in
			 * the 16-32ms bucket, and a bound inside the range
			 * the engine legitimately reaches would hold real
			 * sessions down. The ceiling is a minute, past which
			 * the gate is not bounding anything a human would
			 * wait for. */
			if (end == a || *end ||
			    (v && (v < 50000 || v > 60000000))) {
				log_err(
					"--deadman-us: expected 0 (off) or 50000-60000000, got '%s'\n",
					a);
				return 1;
			}
			ktx_deadman_ns = v * 1000ull;
		}
		else if (!strcmp(argv[i], "--demand"))
			static_demand = 1;
		else if (!strcmp(argv[i], "--check"))
			check_only = 1;
		else if (!strcmp(argv[i], "--demand-poll-us") && i + 1 < argc) {
			const char *a = argv[++i];
			char *end;
			unsigned long long v = strtoull(a, &end, 10);

			/* 0 is the documented off switch. Above it the floor
			 * is 10ms only to catch a typo; the effective
			 * interval is raised to the session's detect budget
			 * anyway, so a small value here means "as often as
			 * detection would have run" rather than a flood. */
			if (end == a || *end ||
			    (v && (v < 10000 || v > 600000000))) {
				log_err(
					"--demand-poll-us: expected 0 (off) or 10000-600000000, got '%s'\n",
					a);
				return 1;
			}
			demand_poll_us = v;
		}
		else if (!strcmp(argv[i], "--log-level") && i + 1 < argc) {
			const char *a = argv[++i];

			if (!strcmp(a, "error"))
				bfd_log_level = BFD_LOG_ERROR;
			else if (!strcmp(a, "info"))
				bfd_log_level = BFD_LOG_INFO;
			else if (!strcmp(a, "debug"))
				bfd_log_level = BFD_LOG_DEBUG;
			else {
				log_err(
					"--log-level: expected error|info|debug, got '%s'\n",
					a);
				return 1;
			}
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
				log_err(
					"--tick-us: expected 200-100000, got '%s'\n",
					a);
				return 1;
			}
			tick_us = (unsigned)v;
		}
		else if (!strcmp(argv[i], "--xdp-mode") && i + 1 < argc) {
			const char *m = argv[++i];
			if (!strcmp(m, "generic") || !strcmp(m, "skb"))
				ktx_xdp_flags = XDP_FLAGS_SKB_MODE;
			else if (!strcmp(m, "drv") || !strcmp(m, "native"))
				ktx_xdp_flags = XDP_FLAGS_DRV_MODE;
			else {
				log_err(
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
				log_err(
					"--dp-hold: expected seconds (0-86400), got '%s'\n",
					a);
				return 1;
			}
			dp_hold_us = v * 1000000ull;
		}
		else if (!strcmp(argv[i], "--dp-peer") && i + 1 < argc) {
			/* The account bfdd runs as. A UNIX control socket is
			 * created 0600 without this, so an engine running as
			 * root and a bfdd running as `frr` need to be told.
			 * Also the uid SO_PEERCRED is checked against, so it
			 * is authorization rather than only file mode. */
			const char *a = argv[++i];
			const struct passwd *pw = getpwnam(a);
			char *end;

			if (pw) {
				dp_set_peer_uid(pw->pw_uid);
			} else {
				unsigned long long v = strtoull(a, &end, 10);

				if (end == a || *end || v > (unsigned)-2) {
					log_err("--dp-peer: no such user and not a uid: '%s'\n",
						a);
					return 1;
				}
				dp_set_peer_uid((uid_t)v);
			}
		}
		/* Before the positional arguments, or a mistyped option lands
		 * in one of them. `--dead-man-us 50000` reported "static: bad
		 * IPv4 address", and an option whose value was left off was
		 * dropped without a word, so the engine started on the
		 * default having been told otherwise. Both are configuration
		 * silently not taking effect, which is the failure this whole
		 * program exists to avoid elsewhere. */
		else if (argv[i][0] == '-') {
			log_err("unrecognised option '%s', or an option"
				" missing its value\n", argv[i]);
			return 1;
		}
		else if (!static_local)
			static_local = argv[i];
		else if (!static_peer)
			static_peer = argv[i];
		else {
			log_err("unexpected argument '%s'\n", argv[i]);
			return 1;
		}
	}
	/* --check: the matrix probe. Open the object, run the ABI check, and
	 * hand it to the verifier by loading it, then report and exit without
	 * attaching to anything or opening a socket. ktx_load does exactly
	 * that and logs the specific failure (ABI size mismatch, or the
	 * verifier's own line) on the way; this reports the verdict and the
	 * kernel it was reached on, which is what a package's postinst or a
	 * support-matrix arm wants to know. */
	if (check_only) {
		struct utsname un;
		int rc = ktx_load();

		uname(&un);
		if (rc == 0)
			printf("xdp-bfd %s: bfd_xdp.o loads and is ABI-matched on %s %s\n",
			       BFD_XDP_VERSION, un.sysname, un.release);
		else
			printf("xdp-bfd %s: object did NOT load on %s %s (see above)\n",
			       BFD_XDP_VERSION, un.sysname, un.release);
		return rc ? 1 : 0;
	}

	/* One address without the other: the guard below only demands a
	 * pair when --dplane is absent, so `--dplane <p> <one-address>`
	 * would otherwise reach the static setup with a NULL peer. */
	if (static_local && !static_peer) {
		log_err("static: %s given without a peer address\n",
			static_local);
		return 1;
	}
	if (!dplane_path && (!static_local || !static_peer)) {
		log_err(
			"usage: %s <local-ip> <peer-ip> [--kernel-tx <if>]\n"
			"       %s --dplane <port|sock-path> [--kernel-tx <if>] [--dp-hold <sec>]\n"
			"       [--dp-peer <user|uid>]  (the account bfdd runs as)\n"
			"       [--bpf-obj <path>] [--xdp-mode drv|generic]\n"
			"       [--stats-dump <path>]   (SIGUSR1 writes it)\n"
			"       [--sweep-us <500-100000>]\n"
			"       [--tick-us <200-100000>]\n"
			"       [--deadman-us <0|50000-60000000>]  (0 = off)\n"
			"       [--demand] [--demand-poll-us <0|10000-600000000>]\n"
			"       [--log-level error|info|debug]\n",
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
	if (tick_us != TICK_US_DEFAULT)
		log_info("engine: main loop tick %uus (default %uus)\n",
		       tick_us, TICK_US_DEFAULT);
	/* No SO_RCVTIMEO: the poll below is the only wait and every drain
	 * is MSG_DONTWAIT. A timeout here would be dead code that looks
	 * protective - if a drain ever loses MSG_DONTWAIT the loop blocks
	 * on an idle socket, and a stale timeout would only make that
	 * stall periodic rather than permanent. */
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
	 * Linux enforces it only in tcp_v4_rcv. IPV6_MINHOPCOUNT on the v6
	 * socket below behaves the same way. Both are silently inert.
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
	/* Both handlers set a flag and nothing else; the work happens in
	 * the loop below, so neither needs to be async-signal-safe. */
	signal(SIGUSR1, stats_on_signal);
	signal(SIGTERM, shutdown_on_signal);
	signal(SIGINT, shutdown_on_signal);

	if (static_local) {
		struct session *s = sess_alloc();
		/* Family from the address text: a colon means v6. Both
		 * arguments must agree - a session cannot span families, and
		 * silently picking one would build a key that matches nothing
		 * arriving. */
		int fam = strchr(static_local, ':') ? AF_INET6 : AF_INET;

		if ((strchr(static_peer, ':') != NULL) != (fam == AF_INET6)) {
			log_err(
				"static: %s and %s are different families\n",
				static_local, static_peer);
			return 1;
		}
		if (fam == AF_INET6) {
			struct in6_addr sl6, sp6;

			/* Unchecked, a typo yields a zero address and a
			 * session that can never match. */
			if (inet_pton(AF_INET6, static_local, &sl6) != 1 ||
			    inet_pton(AF_INET6, static_peer, &sp6) != 1) {
				log_err("static: bad IPv6 address\n");
				return 1;
			}
			key_set_v6(&s->local, &sl6);
			key_set_v6(&s->peer, &sp6);
		} else {
			uint32_t sl, sp;

			if (inet_pton(AF_INET, static_local, &sl) != 1 ||
			    inet_pton(AF_INET, static_peer, &sp) != 1) {
				log_err("static: bad IPv4 address\n");
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
		s->demand      = static_demand;
		s->pushed_valid = 0;
		s->next_tx_us  = now_us();
		log_info("bfd_tx: static session lid=%u %s -> %s%s\n",
		       s->lid, static_local, static_peer,
		       use_ktx ? " (kernel-tx)" : "");
	}

	for (;;) {
		auth_rollover_tick();

		/* Anything that did not fit the socket last pass. Cheap when
		 * the queue is empty, which is the normal case. */
		dp_flush();

		/* Room the flush just freed goes to sessions whose state
		 * change was deferred rather than dropped (G5). */
		dp_notify_flush_pending();

		if (shutdown_wanted) {
			/* Tell every peer before going, rather than leaving
			 * each to time out. fsm_announce_down sends three
			 * AdminDown packets because nothing retransmits once
			 * we are gone, and it deliberately skips sessions the
			 * dp-hold path has orphaned: those are meant to
			 * survive a control-plane restart unnoticed, and this
			 * is not that. */
			int announced = 0;

			for (int i = 0; i < MAX_SESSIONS; i++) {
				struct session *cs = &sessions[i];

				if (!cs->used || cs->orphaned)
					continue;
				fsm_announce_down(cs);
				announced++;
			}
			log_info("shutdown: announced AdminDown on %d session(s)\n",
				 announced);
			break;
		}

		if (stats_wanted) {
			stats_wanted = 0;
			stats_dump();
		}

		__u8 p_buf[BFD_MAX_LEN] = {0};
		struct bfd_ctrl_pkt p;
		struct sockaddr_in from;
		/* Packets drained per socket per pass. Draining until EAGAIN
		 * lets a sustained flood starve everything below it -
		 * transmit, detection, the map poll, the dplane read - while
		 * the process stays alive, which no liveness check catches.
		 *
		 * One packet per configured session per pass: a legitimate
		 * burst clears in a single iteration and anything larger
		 * spreads across the next few ticks.
		 */
		const int drain_budget = MAX_SESSIONS;

		/* The loop's clock: a timerfd armed at --tick-us plus every RX
		 * socket, so no socket waits out another's timeout. All four
		 * drains below are non-blocking, and the drain budget rather
		 * than the blocking discipline is what bounds a pass. */
		/* tick, four receive sockets, the dplane listener and its
		 * connection, and the sweep event ring. */
		struct pollfd pfd[8] = {0};
		int dp_l = -1, dp_c = -1;

		dp_fds(&dp_l, &dp_c);
		int np = 0;
		{
			uint64_t exp;

			pfd[np].fd = tick_fd; pfd[np++].events = POLLIN;
			if (ktx_events_fd() >= 0)
				{ pfd[np].fd = ktx_events_fd(); pfd[np++].events = POLLIN; }
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
		/* The fd check is redundant with rd4, which is only set from a
		 * pollfd built when rx_sock >= 0 - but it was a comment saying
		 * so until scan-build kept flagging it, and the comment itself
		 * admitted the checker would be right if the poll-set build and
		 * this ever disagreed. Stating the invariant in code rather
		 * than in prose costs one comparison per pass and lets the
		 * analyser run as a gate with no findings to excuse. */
		uint64_t t = now_us();
		loop_passes++;
		/* Still here. The fast path answers on our behalf only for
		 * as long as this keeps moving; see the gate in bfd_xdp.c.
		 *
		 * Here rather than at the top of the pass, because the top
		 * is on the other side of poll(), and a pass that blocks
		 * forever in poll is one of the wedges worth catching. This
		 * is the first point at which the loop has demonstrably come
		 * round again. */
		ktx_heartbeat(t);
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

		/* Drained per pass like the other three sockets.
		 *
		 * This one took a single packet per pass, which the other
		 * three were converted away from and this one was not. It is
		 * the busiest socket in every deployment, and a pass is not
		 * cheap: a batch map lookup plus a walk of all 64 sessions.
		 * Correctness survived, because a backlog makes poll() return
		 * at once and the loop comes round again, but each packet
		 * then paid for a whole pass, so the drain rate was capped at
		 * the loop rate and the per-packet cost was some sixty times
		 * its siblings.
		 *
		 * loop_rx_wakeups still counts passes on which this socket
		 * had something, not packets, so the histogram it feeds keeps
		 * meaning what it meant.
		 */
		for (int d = 0; rd4 && rx_sock >= 0 && d < drain_budget; d++) {
			struct iovec iov4 = { .iov_base = p_buf,
					      .iov_len = sizeof(p_buf) };
			char cbuf4[CMSG_SPACE(sizeof(struct in_pktinfo)) +
				   CMSG_SPACE(sizeof(int))];
			struct msghdr mh4 = {
				.msg_name = &from, .msg_namelen = sizeof(from),
				.msg_iov = &iov4, .msg_iovlen = 1,
				.msg_control = cbuf4,
				.msg_controllen = sizeof(cbuf4),
			};
			ssize_t n = recvmsg(rx_sock, &mh4,
					    MSG_DONTWAIT | MSG_TRUNC);

			if (n < 0)
				break;
			if (!d)
				loop_rx_wakeups++;
			memcpy(&p, p_buf, sizeof(p));

			/* The same predicate the XDP path uses, so the two
			 * cannot disagree about what is acceptable. */
			/* cmsgs first: the arriving TTL decides whether the
			 * packet is acceptable at all, so it is checked
			 * alongside the header rather than after demux. rttl
			 * stays -1 when the cmsg is missing, which drops the
			 * packet - that means the setsockopt did not take,
			 * and accepting anything then is worse. */
			uint32_t dst_ip = 0;
			int rttl = -1;

			for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh4); c;
			     c = CMSG_NXTHDR(&mh4, c)) {
				if (c->cmsg_level == IPPROTO_IP &&
				    c->cmsg_type == IP_PKTINFO)
					dst_ip = ((struct in_pktinfo *)
						  CMSG_DATA(c))->ipi_addr.s_addr;
				if (c->cmsg_level == IPPROTO_IP &&
				    c->cmsg_type == IP_TTL)
					memcpy(&rttl, CMSG_DATA(c),
					       sizeof(rttl));
			}

			struct bfd_addr fp, fl;
			enum rx_verdict why;
			struct session *rs;

			key_set_v4(&fp, from.sin_addr.s_addr);
			key_set_v4(&fl, dst_ip);
			rs = rx_accept(p_buf, (size_t)n, rttl, &fp, &fl, 0, &why);
			if (rs)
				fsm_rx(rs, &p, t);
		}

		/* RFC 5883 multihop control packets, port 4784. Same demux as
		 * single-hop: your_disc first, address pair as fallback. */
		for (int d = 0; rdm4 && rxm_sock >= 0 && d < drain_budget; d++) {
			__u8 pm_buf[BFD_MAX_LEN] = {0};
		struct bfd_ctrl_pkt pm;
			struct sockaddr_in fromm;
			struct iovec iovm = { .iov_base = pm_buf,
					      .iov_len = sizeof(pm_buf) };
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
			memcpy(&pm, pm_buf, sizeof(pm));
		
			if (nm < 0)
				break;
		
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
		
			struct bfd_addr mp, ml;
			enum rx_verdict mwhy;
			struct session *ms;

			key_set_v4(&mp, fromm.sin_addr.s_addr);
			key_set_v4(&ml, mdst);
			ms = rx_accept(pm_buf, (size_t)nm, mttl, &mp, &ml, 1, &mwhy);
			/* `t`, like the other three drains: packets taken in one
			 * pass are stamped together rather than a few microseconds
			 * apart for no reason. */
			if (ms)
				fsm_rx(ms, &pm, t);
		}

		/* rx6_sock >= 0 is redundant with rd6, which is only set from a
		 * pollfd built when the socket exists. Stated in code rather
		 * than in a comment for the same reason as the v4 drain above:
		 * it lets scan-build run as a gate with nothing to excuse. */
		for (int d = 0; rd6 && rx6_sock >= 0 && d < drain_budget; d++) {
			__u8 p6_buf[BFD_MAX_LEN] = {0};
		struct bfd_ctrl_pkt p6;
			struct sockaddr_in6 from6;
			struct iovec iov6 = { .iov_base = p6_buf,
				.iov_len = sizeof(p6_buf) };
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
			memcpy(&p6, p6_buf, sizeof(p6));
			if (n6 < 0)
				break;
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
			enum rx_verdict why6;
			struct session *rs6 = rx_accept(p6_buf, (size_t)n6, rhl6,
							       &fp6, &fl6, 0, &why6);

			if (rs6)
				fsm_rx(rs6, &p6, t);
		}

		/* v6 multihop control packets, port 4784. */
		for (int d = 0; rdm6 && rxm6_sock >= 0 && d < drain_budget; d++) {
			__u8 pm6_buf[BFD_MAX_LEN] = {0};
		struct bfd_ctrl_pkt pm6;
			struct sockaddr_in6 fromm6;
			struct iovec iovm6 = { .iov_base = pm6_buf,
					       .iov_len = sizeof(pm6_buf) };
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
			memcpy(&pm6, pm6_buf, sizeof(pm6));
		
			if (nm6 < 0)
				break;
		
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
		
			enum rx_verdict mwhy6;
			struct session *ms6 = rx_accept(pm6_buf, (size_t)nm6, mhl6,
							       &mp6, &ml6, 1, &mwhy6);

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
		/* The sweep's verdicts, before the per-session walk below,
		 * so a session the kernel has already declared down is seen
		 * as down by everything that follows in this pass rather
		 * than the next one. */
		ktx_drain_events();

		ktx_poll_all();
		for (int i = 0; i < MAX_SESSIONS; i++) {
			struct session *cs = &sessions[i];
			if (!cs->used)
				continue;
			if (cs->orphaned && t >= cs->orphan_deadline_us) {
				sess_teardown_one(cs, "hold expired");
				continue;
			}
			/* An authenticated session whose keys never arrived.
			 * bfdd set SESSION_AUTH on the ADD but sent no
			 * DP_SESSION_AUTH, which is what a bfdd predating the
			 * key extension does. Distinct from a key-chain
			 * rollover gap (auth_nkeys > 0, none sendable now),
			 * which tx_one already reports and which self-heals:
			 * this is permanent, the session never comes up, and
			 * the remedy is the opposite, act rather than wait.
			 * auth_nkeys == 0 is the discriminator. A deadline,
			 * not an ADD check, so the normal two-message
			 * handshake (keys arrive within the same burst) does
			 * not false-positive. */
			if (cs->auth_present && cs->auth_nkeys == 0) {
				if (!cs->auth_keys_deadline_us)
					cs->auth_keys_deadline_us = t + 1000000;
				else if (!cs->auth_nokeys_warned &&
					 t >= cs->auth_keys_deadline_us) {
					log_err("lid=%u: bfdd offloaded an authenticated session but sent no keys within 1s; this bfdd predates the DP_SESSION_AUTH key extension. Upgrade bfdd or keep authenticated sessions off the data plane.\n",
						cs->lid);
					cs->auth_nokeys_warned = 1;
				}
			} else {
				/* keys arrived, or authentication withdrawn:
				 * disarm, and re-arm for a future recurrence. */
				cs->auth_keys_deadline_us = 0;
				cs->auth_nokeys_warned = 0;
			}

			ktx_poll_map(cs, t);
			fsm_detect(cs, t);
			fsm_tx(cs, t);
			echo_tx_maybe(cs, t);
			dp_reresolve_wildcard(cs, t);
			ktx_mirror(cs);
		}
	}
	return 0;
}
