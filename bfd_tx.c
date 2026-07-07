// SPDX-License-Identifier: GPL-2.0
/*
 * bfd_tx.c - userspace BFD endpoint (RFC 5880/5881 subset).
 *
 * M4a: multi-session core. Sessions live in a table; the CLI still
 * configures exactly one (behavior-compatible with M3), the bfddp
 * dataplane socket (M4b) will add/remove them dynamically.
 *
 * Modes:
 *   ./bfd_tx <local-ip> <peer-ip>                    plain userspace TX
 *   ./bfd_tx <local-ip> <peer-ip> --kernel-tx <if>   XDP RX-clocked TX
 *
 * Proven behaviors carried over from M3 (see git history):
 *   - TX schedule re-clamp on timer renegotiation (Init-loop fix)
 *   - single transition packet on entering Up (eaten-Final fix)
 *   - signed-delta guard on detect timeout (map timestamp race fix)
 *   - RFC slow rate (1s) while not Up; 75-100% jitter while Up
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

#define PORT_CTRL    3784
#define SRC_PORT     49152
#define DEF_MIN_TX   10000
#define DEF_MIN_RX   10000
#define DEF_MULT     3
#define SLOW_TX_US   1000000ull
#define MAX_SESSIONS 64

enum { ST_ADMINDOWN, ST_DOWN, ST_INIT, ST_UP };
static const char *stname[] = { "AdminDown", "Down", "Init", "Up" };

/* ---------- wire format ---------- */
struct bfdpkt {
	uint8_t  vers_diag, flags, mult, len;
	uint32_t my_disc, your_disc, min_tx, min_rx, min_echo;
} __attribute__((packed));

#define F_P 0x20
#define F_F 0x10

/* ---------- BPF map mirror types (must match bfd_xdp.c) ---------- */
struct map_key   { uint32_t peer_ip, local_ip; };
struct map_cfg   { uint32_t enable, my_disc, your_disc, min_tx_us, min_rx_us;
		   uint8_t state, diag, mult, pad; };
struct map_state { uint64_t last_seen_ns, rx_pkts;
		   uint32_t remote_disc, local_disc, min_tx_us, min_rx_us;
		   uint8_t remote_state, remote_diag, detect_mult, alive; };

/* ---------- session ---------- */
struct session {
	int      used;
	uint32_t lid;           /* our discriminator                  */
	uint32_t local_ip, peer_ip;   /* network byte order           */
	uint32_t min_tx_us, min_rx_us;
	uint8_t  detect_mult;
	int      passive;

	/* FSM */
	int      state, diag;
	uint32_t rdisc;
	uint32_t r_min_tx, r_min_rx;
	uint8_t  r_mult;
	int      r_state;
	int      send_final, just_up;
	int      pushed_state;  /* last state mirrored to BPF map     */
	uint64_t last_rx_us, next_tx_us;
};

static struct session sessions[MAX_SESSIONS];

/* ---------- globals ---------- */
static int rx_sock = -1, tx_sock = -1;
static int use_ktx = 0;
static int cfg_fd = -1, sess_fd = -1;
static struct bpf_object *bpf_obj;

static uint64_t now_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000ull + ts.tv_nsec / 1000;
}

/* ---------- session table ---------- */
static struct session *sess_alloc(void)
{
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (!sessions[i].used) {
			memset(&sessions[i], 0, sizeof(sessions[i]));
			sessions[i].used = 1;
			return &sessions[i];
		}
	return NULL;
}

static struct session *sess_by_disc(uint32_t your_disc)
{
	if (!your_disc)
		return NULL;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].lid == your_disc)
			return &sessions[i];
	return NULL;
}

static struct session *sess_by_addr(uint32_t peer_ip, uint32_t local_ip)
{
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used &&
		    sessions[i].peer_ip == peer_ip &&
		    sessions[i].local_ip == local_ip)
			return &sessions[i];
	return NULL;
}

/* ---------- BPF plumbing ---------- */
static int ktx_attach(const char *ifname)
{
	int ifindex = if_nametoindex(ifname);
	if (!ifindex) { perror("ifname"); return -1; }

	bpf_obj = bpf_object__open_file("bfd_xdp.o", NULL);
	if (!bpf_obj || bpf_object__load(bpf_obj)) {
		fprintf(stderr, "bfd_xdp.o load failed\n");
		return -1;
	}
	struct bpf_program *pr =
		bpf_object__find_program_by_name(bpf_obj, "bfd_observer");
	if (bpf_xdp_attach(ifindex, bpf_program__fd(pr),
			   XDP_FLAGS_DRV_MODE, NULL)) {
		fprintf(stderr, "native XDP attach failed on %s\n", ifname);
		return -1;
	}
	cfg_fd  = bpf_object__find_map_fd_by_name(bpf_obj, "tx_config");
	sess_fd = bpf_object__find_map_fd_by_name(bpf_obj, "bfd_sessions");
	printf("kernel-tx: XDP attached to %s\n", ifname);
	return 0;
}

static void ktx_mirror(struct session *s)
{
	if (!use_ktx || s->state == s->pushed_state)
		return;
	struct map_key k = { .peer_ip = s->peer_ip, .local_ip = s->local_ip };
	struct map_cfg c = {
		.enable    = (s->state == ST_UP),
		.my_disc   = s->lid,
		.your_disc = s->rdisc,
		.min_tx_us = s->min_tx_us,
		.min_rx_us = s->min_rx_us,
		.state     = s->state,
		.diag      = s->diag,
		.mult      = s->detect_mult,
	};
	bpf_map_update_elem(cfg_fd, &k, &c, 0);
	s->pushed_state = s->state;
}

/* Pull RX liveness + remote-down signal from the XDP map (kernel-tx
 * consumes packets in Up state, so the socket goes quiet). */
static void ktx_poll_map(struct session *s, uint64_t t)
{
	if (!use_ktx || s->state != ST_UP)
		return;
	struct map_key k = { .peer_ip = s->peer_ip, .local_ip = s->local_ip };
	struct map_state ms;
	if (bpf_map_lookup_elem(sess_fd, &k, &ms))
		return;
	if (ms.last_seen_ns / 1000 > s->last_rx_us)
		s->last_rx_us = ms.last_seen_ns / 1000;
	if (ms.remote_state == ST_DOWN) {
		printf("[%llu] lid=%u Up -> Down (map: peer sent Down)\n",
		       (unsigned long long)t, s->lid);
		s->state = ST_DOWN;
		s->diag = 3;
		s->next_tx_us = t;
	}
}

/* ---------- FSM ---------- */
static void fsm_rx(struct session *s, const struct bfdpkt *p, uint64_t t)
{
	int ps = (p->flags >> 6) & 3;

	s->rdisc    = ntohl(p->my_disc);
	s->r_state  = ps;
	s->r_min_rx = ntohl(p->min_rx);
	s->r_min_tx = ntohl(p->min_tx);
	s->r_mult   = p->mult;
	s->last_rx_us = t;
	if (p->flags & F_P)
		s->send_final = 1;

	int old = s->state;
	if (ps == ST_ADMINDOWN) {
		if (s->state != ST_DOWN) { s->state = ST_DOWN; s->diag = 3; }
	} else switch (s->state) {
	case ST_DOWN:
		if (ps == ST_DOWN && !s->passive) s->state = ST_INIT;
		else if (ps == ST_INIT)           s->state = ST_UP;
		break;
	case ST_INIT:
		if (ps == ST_INIT || ps == ST_UP) s->state = ST_UP;
		break;
	case ST_UP:
		if (ps == ST_DOWN) { s->state = ST_DOWN; s->diag = 3; }
		break;
	}
	if (s->state != old) {
		printf("[%llu] lid=%u %s -> %s (peer sent %s)\n",
		       (unsigned long long)t, s->lid,
		       stname[old], stname[s->state], stname[ps]);
		s->just_up = (s->state == ST_UP);
		s->next_tx_us = t;
	}
}

static void fsm_detect(struct session *s, uint64_t t)
{
	if (s->state == ST_DOWN || s->state == ST_ADMINDOWN || !s->last_rx_us)
		return;
	uint64_t iv = s->r_min_tx > s->min_rx_us ? s->r_min_tx : s->min_rx_us;
	int64_t sd = (int64_t)(t - s->last_rx_us);
	if (sd < 0)
		sd = 0;   /* XDP stamped newer than our snapshot */
	uint8_t mult = s->r_mult ? s->r_mult : s->detect_mult;
	if ((uint64_t)sd > (uint64_t)mult * iv) {
		printf("[%llu] lid=%u DETECT TIMEOUT: %s -> Down (silent %.1fms)\n",
		       (unsigned long long)t, s->lid, stname[s->state],
		       sd / 1000.0);
		s->state = ST_DOWN;
		s->diag = 1;
		s->rdisc = 0;
	}
}

static void fsm_tx(struct session *s, uint64_t t)
{
	/* Re-clamp if negotiated interval shrank (renegotiation fix). */
	if (s->last_rx_us) {
		uint64_t cur = (s->state == ST_UP)
			? (s->min_tx_us > s->r_min_rx ? s->min_tx_us
						      : s->r_min_rx)
			: SLOW_TX_US;
		if (s->next_tx_us > t + cur)
			s->next_tx_us = t + cur;
	}

	int due = (t >= s->next_tx_us) || s->send_final;
	/* kernel speaks in steady Up; userspace only for transition/Final */
	if (use_ktx && s->state == ST_UP && !s->send_final && !s->just_up)
		due = 0;
	if (!due)
		return;

	struct bfdpkt o = {0};
	o.vers_diag = (1 << 5) | (s->diag & 0x1f);
	o.flags     = (s->state << 6) | (s->send_final ? F_F : 0);
	o.mult      = s->detect_mult;
	o.len       = 24;
	o.my_disc   = htonl(s->lid);
	o.your_disc = htonl(s->rdisc);
	o.min_tx    = htonl(s->state == ST_UP ? s->min_tx_us
					      : (uint32_t)SLOW_TX_US);
	o.min_rx    = htonl(s->min_rx_us);

	struct sockaddr_in dst = {
		.sin_family = AF_INET,
		.sin_port   = htons(PORT_CTRL),
		.sin_addr.s_addr = s->peer_ip,
	};
	sendto(tx_sock, &o, 24, 0, (void *)&dst, sizeof(dst));
	s->send_final = 0;
	s->just_up = 0;

	if (t >= s->next_tx_us) {
		uint64_t iv;
		if (s->state == ST_UP) {
			iv = s->min_tx_us > s->r_min_rx ? s->min_tx_us
							: s->r_min_rx;
			iv = iv * 3 / 4 + (random() % (iv / 4 + 1));
		} else {
			iv = SLOW_TX_US;
		}
		s->next_tx_us = t + iv;
	}
}

/* ---------- main ---------- */
int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s <local-ip> <peer-ip> [--kernel-tx <ifname>]\n",
			argv[0]);
		return 1;
	}

	/* RX: wildcard bind so multiple local addresses work later */
	rx_sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in la = { .sin_family = AF_INET,
				  .sin_port = htons(PORT_CTRL),
				  .sin_addr.s_addr = INADDR_ANY };
	if (bind(rx_sock, (void *)&la, sizeof(la))) {
		perror("bind 3784 (is bfdd running?)");
		return 1;
	}
	struct timeval tv = { .tv_usec = 2000 };
	setsockopt(rx_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	/* TX: fixed source port, TTL 255 (GTSM) */
	tx_sock = socket(AF_INET, SOCK_DGRAM, 0);
	int ttl = 255;
	setsockopt(tx_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
	struct sockaddr_in sa = { .sin_family = AF_INET,
				  .sin_port = htons(SRC_PORT),
				  .sin_addr.s_addr = INADDR_ANY };
	if (bind(tx_sock, (void *)&sa, sizeof(sa))) {
		perror("bind src");
		return 1;
	}

	if (argc >= 5 && !strcmp(argv[3], "--kernel-tx")) {
		if (ktx_attach(argv[4]))
			return 1;
		use_ktx = 1;
	}

	srandom(getpid() ^ time(NULL));

	/* CLI-configured single session (bfddp will replace this in M4b) */
	struct session *s = sess_alloc();
	inet_pton(AF_INET, argv[1], &s->local_ip);
	inet_pton(AF_INET, argv[2], &s->peer_ip);
	s->lid         = (random() & 0x7fffffff) | 1;
	s->min_tx_us   = DEF_MIN_TX;
	s->min_rx_us   = DEF_MIN_RX;
	s->detect_mult = DEF_MULT;
	s->state       = ST_DOWN;
	s->pushed_state = -1;
	s->next_tx_us  = now_us();
	printf("bfd_tx: lid=%u %s -> %s%s\n", s->lid, argv[1], argv[2],
	       use_ktx ? " (kernel-tx)" : "");

	for (;;) {
		/* ---- RX + demux ---- */
		struct bfdpkt p;
		struct sockaddr_in from;
		socklen_t flen = sizeof(from);
		ssize_t n = recvfrom(rx_sock, &p, sizeof(p), 0,
				     (void *)&from, &flen);
		uint64_t t = now_us();

		if (n >= 24 && ((p.vers_diag >> 5) & 7) == 1 &&
		    p.mult && p.my_disc) {
			struct session *rs = sess_by_disc(ntohl(p.your_disc));
			if (!rs)
				rs = sess_by_addr(from.sin_addr.s_addr, 0) ?:
				     sess_by_addr(from.sin_addr.s_addr,
						  sessions[0].local_ip);
			if (rs)
				fsm_rx(rs, &p, t);
		}

		/* ---- per-session housekeeping ---- */
		for (int i = 0; i < MAX_SESSIONS; i++) {
			struct session *cs = &sessions[i];
			if (!cs->used)
				continue;
			ktx_poll_map(cs, t);
			fsm_detect(cs, t);
			fsm_tx(cs, t);
			ktx_mirror(cs);
		}
	}
	return 0;
}
