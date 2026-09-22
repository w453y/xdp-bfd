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
 *     --auth <type>:<keyid>:<key>   authenticate that static session
 *                                   (simple, keyed-sha1, meticulous-sha1)
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
/* Loop clock: a timerfd, so sub-millisecond ticks are honoured. SO_RCVTIMEO
 * would round anything under 1ms up. */
static int tick_fd = -1;





/* ---------- main ---------- */
/* Main loop tick in microseconds, --tick-us. */
#define TICK_US_DEFAULT 2000
static unsigned tick_us = TICK_US_DEFAULT;


/* Loop passes, and passes on which the control socket had a packet
 * (loop_rx_wakeups), for the stats dump. */
uint64_t loop_passes;
/* --demand, static mode only; under bfdd demand arrives per session in the
 * ADD. */
static int static_demand;
const char *static_auth = NULL;
static int check_only;
uint64_t loop_rx_wakeups;

/* Inter-pass gap histogram, log2 buckets in microseconds. */
uint64_t loop_gap_us[24];

/* Re-choose keys whose periods have moved on. The chain arrives once, so
 * rollovers are noticed here; once a second suits periods in whole seconds. */
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

/* SIGTERM and SIGINT request an orderly exit, so peers get AdminDown instead
 * of a detect timeout. */
static volatile sig_atomic_t shutdown_wanted;

static void shutdown_on_signal(int sig)
{
	(void)sig;
	shutdown_wanted = 1;
}

#ifndef BFD_XDP_VERSION
#define BFD_XDP_VERSION "0.0.0-dev"
#endif

/* --auth <type>:<keyid>:<key> for static mode, to test authentication between
 * two static engines. The key has no lifetime. */
static int static_auth_apply(struct session *s, const char *spec)
{
	const char *c1 = strchr(spec, ':');
	const char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
	struct auth_key *k = &s->auth_keys[0];
	char type[24];
	unsigned long keyid;
	size_t tlen, klen;

	if (!c1 || !c2 || c1 == spec) {
		log_err("--auth wants <type>:<keyid>:<key>\n");
		return -1;
	}
	tlen = (size_t)(c1 - spec);
	if (tlen >= sizeof(type)) {
		log_err("--auth: unknown type\n");
		return -1;
	}
	memcpy(type, spec, tlen);
	type[tlen] = 0;

	memset(s->auth_keys, 0, sizeof(s->auth_keys));
	if (!strcmp(type, "simple"))
		k->type = BFD_AUTH_SIMPLE;
	else if (!strcmp(type, "keyed-sha1"))
		k->type = BFD_AUTH_KEYED_SHA1;
	else if (!strcmp(type, "meticulous-sha1"))
		k->type = BFD_AUTH_METICULOUS_SHA1;
	else {
		log_err("--auth: type must be simple, keyed-sha1 or meticulous-sha1\n");
		return -1;
	}

	keyid = strtoul(c1 + 1, NULL, 0);
	if (keyid > 255) {
		log_err("--auth: key id %lu is out of range\n", keyid);
		return -1;
	}
	klen = strlen(c2 + 1);
	if (!klen || klen > sizeof(k->kpad) ||
	    (k->type == BFD_AUTH_SIMPLE && klen > BFD_AUTH_SIMPLE_MAXKEY)) {
		log_err("--auth: key length %zu is unusable for this type\n", klen);
		return -1;
	}

	k->key_id = (uint8_t)keyid;
	k->keylen = (uint8_t)klen;
	memcpy(k->kpad, c2 + 1, klen);

	s->auth_present = 1;
	s->auth_nkeys = 1;
	/* Picks the send key and fills auth_type, auth_keyid and the pads,
	 * the same call the dplane path makes when keys arrive. */
	session_auth_evaluate(s, (int64_t)time(NULL));
	if (!s->auth_type) {
		log_err("--auth: no key is sendable, nothing would go out\n");
		return -1;
	}
	return 0;
}

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

			/* Below ~0.5ms timer churn outweighs the gain; above
			 * 100ms the sweep is slower than any detect budget. */
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

			/* 0 turns the gate off. Otherwise at least 50ms, above
			 * the worst measured loop gap, and at most a minute. */
			if (end == a || *end ||
			    (v && (v < 50000 || v > 60000000))) {
				log_err(
					"--deadman-us: expected 0 (off) or 50000-60000000, got '%s'\n",
					a);
				return 1;
			}
			ktx_deadman_ns = v * 1000ull;
		}
		else if (!strcmp(argv[i], "--auth") && i + 1 < argc)
			static_auth = argv[++i];
		else if (!strcmp(argv[i], "--demand"))
			static_demand = 1;
		else if (!strcmp(argv[i], "--check"))
			check_only = 1;
		else if (!strcmp(argv[i], "--demand-poll-us") && i + 1 < argc) {
			const char *a = argv[++i];
			char *end;
			unsigned long long v = strtoull(a, &end, 10);

			/* 0 turns it off. The 10ms floor only catches typos;
			 * the interval is raised to the detect budget anyway. */
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

			/* Main loop tick: how often the per-session TX and
			 * detect pass runs. Floor 200us, since each pass walks
			 * every session; ceiling 100ms. */
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

			/* Reject trailing text: "10s" must not parse as 10. */
			if (end == a || *end || v > 86400) {
				log_err(
					"--dp-hold: expected seconds (0-86400), got '%s'\n",
					a);
				return 1;
			}
			dp_hold_us = v * 1000000ull;
		}
		else if (!strcmp(argv[i], "--dp-peer") && i + 1 < argc) {
			/* The account bfdd runs as: owner of the UNIX control
			 * socket, and the uid SO_PEERCRED must match. */
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
		/* Reject unknown options, and options missing their value,
		 * before they are taken as positional arguments. */
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
	/* --check: load the object (ABI check and verifier), report the
	 * verdict and kernel, and exit without attaching. */
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

	/* Static mode needs both addresses, even alongside --dplane. */
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
	/* No SO_RCVTIMEO: poll() is the only wait and every drain is
	 * MSG_DONTWAIT. */
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
	/* GTSM (RFC 5881 s5) by checking the received TTL. Linux honours
	 * IP_MINTTL and IPV6_MINHOPCOUNT only for TCP. */
	setsockopt(rx_sock, IPPROTO_IP, IP_RECVTTL, &pi, sizeof(pi));

	/* RFC 5883 multihop control packets arrive on 4784, on their own
	 * socket. Establishment goes through userspace; XDP handles both ports
	 * once Up. */
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
			/* The minimum TTL is per session, so read the TTL per
			 * packet instead of setting IP_MINTTL. */
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
	/* Not IPV6_MINHOPCOUNT: Linux enforces it only for TCP. */
	setsockopt(rx6_sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &pi,
		   sizeof(pi));

	/* v6 multihop, port 4784. The minimum hop limit is per session and
	 * checked per packet. */
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
			/* As for v4 multihop: read the hop limit per packet. */
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
		 * addresses must be the same family. */
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
		if (static_auth && static_auth_apply(s, static_auth))
			return 1;
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
		 * change was deferred rather than dropped. */
		dp_notify_flush_pending();

		if (shutdown_wanted) {
			/* Announce AdminDown to every peer before exiting.
			 * fsm_announce_down skips dp-hold orphans, which must
			 * survive unnoticed. */
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
		/* Packets drained per socket per pass. The bound keeps a flood
		 * from starving TX, detection and the dplane; one per session
		 * clears a legitimate burst in one pass. */
		const int drain_budget = MAX_SESSIONS;

		/* Poll set: the tick timerfd, four RX sockets, the dplane
		 * listener and connection, and the sweep event ring. Drains
		 * are non-blocking; drain_budget bounds a pass. */
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
		/* Drain only the sockets poll reported readable. */
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
		uint64_t t = now_us();
		loop_passes++;
		/* Heartbeat for the dead-man gate in bfd_xdp.c. Taken after
		 * poll() returns, so a loop stuck in poll stops beating. */
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

		/* Drain up to drain_budget packets. loop_rx_wakeups counts
		 * passes with traffic, not packets. rx_sock >= 0 duplicates
		 * rd4, but lets scan-build prove it. */
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

			/* Read the TTL from cmsg before demux. A missing cmsg
			 * leaves rttl -1, which drops the packet. */
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
			/* Room for two cmsgs, IP_PKTINFO and IP_TTL. */
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
			/* Stamp with the pass time, as the other drains do. */
			if (ms)
				fsm_rx(ms, &pm, t);
		}

		/* rx6_sock >= 0 duplicates rd6, as in the v4 drain. */
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

		/* Apply the sweep's verdicts first, so this pass sees sessions
		 * the kernel already declared down. */
		ktx_drain_events();

		/* One batch map fetch for the whole pass. */
		ktx_poll_all();
		for (int i = 0; i < MAX_SESSIONS; i++) {
			struct session *cs = &sessions[i];
			if (!cs->used)
				continue;
			if (cs->orphaned && t >= cs->orphan_deadline_us) {
				sess_teardown_one(cs, "hold expired");
				continue;
			}
			/* Authenticated session whose keys never arrived:
			 * SESSION_AUTH but no DP_SESSION_AUTH, as from a bfdd
			 * without the key extension. Unlike a rollover gap
			 * this never heals, so warn after a 1s grace. */
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
