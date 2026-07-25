// SPDX-License-Identifier: GPL-2.0
/*
 * bfd_tx.c - userspace BFD endpoint (RFC 5880/5881 subset).
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
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define PORT_CTRL    BFD_PORT_1HOP
#define SRC_PORT     BFD_SRC_PORT
#define DEF_MIN_TX   10000
#define DEF_MIN_RX   10000
#define DEF_MULT     3
#define SLOW_TX_US   1000000ull
#define MAX_SESSIONS BFD_MAX_SESSIONS

enum { ST_ADMINDOWN, ST_DOWN, ST_INIT, ST_UP };
static const char *stname[] = { "AdminDown", "Down", "Init", "Up" };

/* ---------- BFD wire format ---------- */
struct bfdpkt {
	uint8_t  vers_diag, flags, mult, len;
	uint32_t my_disc, your_disc, min_tx, min_rx, min_echo;
} __attribute__((packed));

#define F_P BFD_F_POLL
#define F_F BFD_F_FINAL

/* ---------- bfddp protocol (from FRR bfddp_packet.h, MIT) ---------- */
enum bfddp_message_type {
	ECHO_REQUEST = 0,
	ECHO_REPLY = 1,
	DP_ADD_SESSION = 2,
	DP_DELETE_SESSION = 3,
	BFD_STATE_CHANGE = 4,
	DP_REQUEST_SESSION_COUNTERS = 5,
	BFD_SESSION_COUNTERS = 6,
};

enum bfddp_session_flag {
	SESSION_MULTIHOP = (1 << 0),
	SESSION_DEMAND   = (1 << 1),
	SESSION_CBIT     = (1 << 2),
	SESSION_ECHO     = (1 << 3),
	SESSION_IPV6     = (1 << 4),
	SESSION_PASSIVE  = (1 << 5),
	SESSION_SHUTDOWN = (1 << 6),
};

struct bfddp_message_header {
	uint8_t  version;      /* 1 */
	uint8_t  zero;
	uint16_t type;
	uint16_t id;           /* 0 = async */
	uint16_t length;       /* total, including this header */
} __attribute__((packed));

struct bfddp_echo {
	uint64_t dp_time;
	uint64_t bfdd_time;
} __attribute__((packed));

struct bfddp_session_msg {
	uint32_t flags;
	struct in6_addr src;
	struct in6_addr dst;
	uint32_t lid;
	uint32_t min_tx;
	uint32_t min_rx;
	uint32_t min_echo_tx;
	uint32_t min_echo_rx;
	uint32_t hold_time;
	uint8_t  ttl;
	uint8_t  detect_mult;
	uint16_t zero;
	uint32_t ifindex;
	char     ifname[64];
} __attribute__((packed));

struct bfddp_state_change {
	uint32_t lid;
	uint32_t rid;
	uint32_t remote_flags;
	uint32_t desired_tx;
	uint32_t required_rx;
	uint32_t required_echo_rx;
	uint8_t  state;
	uint8_t  diagnostics;
	uint8_t  detection_multiplier;
} __attribute__((packed));

struct bfddp_counters {
	uint32_t lid;
	uint32_t pad;   /* FRR struct is unpacked: u64s are 8-aligned */
	uint64_t control_input_bytes;
	uint64_t control_input_packets;
	uint64_t control_output_bytes;
	uint64_t control_output_packets;
	uint64_t echo_input_bytes;
	uint64_t echo_input_packets;
	uint64_t echo_output_bytes;
	uint64_t echo_output_packets;
} __attribute__((packed));


/* ---------- session ---------- */
struct session {
	int      used;
	uint32_t lid;
	struct bfd_addr local, peer;  /* v4 stored v4-mapped */
	int      family;              /* AF_INET / AF_INET6 */
	uint32_t min_tx_us, min_rx_us;
	uint8_t  detect_mult;
	int      passive;
	int      admin_down;          /* SESSION_SHUTDOWN */

	int      state, diag;
	uint32_t rdisc;
	uint32_t r_min_tx, r_min_rx;
	uint32_t r_min_echo;          /* peer's Required Min Echo RX */
	uint8_t  r_mult, r_flags;     /* r_flags: last rx flags & 0x3f */
	int      r_state;
	uint32_t detect_iv_us;        /* poll-aware effective detect basis */
	int      send_final, just_up;
	int      polling;             /* our Poll sequence in flight */
	uint32_t poll_seq;            /* id of current/last Poll sequence */
	uint32_t wire_disc;           /* my_disc on the wire; survives bfdd
	                               * restarts even when lid changes */
	int      orphaned;            /* held across a bfdd disconnect */
	uint64_t orphan_deadline_us;
	uint32_t applied_tx_us;       /* actual TX pace; lags an advertised
	                               * min_tx increase until poll ends */
	int      pushed_valid;
	struct tx_cfg pushed_cfg;
	uint64_t last_rx_us, next_tx_us;
	uint64_t tx_pkts;             /* userspace-sent control packets */
	uint32_t echo_tx_us;          /* echo interval from the ADD; 0 = off */
	uint32_t min_echo_rx_us;      /* advertised Required Min Echo RX */
	uint8_t  min_ttl;             /* from the ADD; 255 = single-hop */
	int      is_mhop;             /* RFC 5883: control port 4784 */
	uint8_t  peer_mac[6];         /* synced from the map, learned by XDP */
	int      mac_valid;
	uint64_t next_echo_tx_us;
	uint32_t echo_nonce;          /* nonce of the outstanding echo */
	uint64_t echo_sent_us;        /* 0 = none outstanding */
	uint64_t echo_tx_pkts;
	int      echo_disc_done;
	uint64_t echo_rx_pkts, echo_lost;
	uint64_t echo_rtt_last_us, echo_rtt_min_us, echo_rtt_max_us;
	uint64_t echo_rtt_sum_us, echo_rtt_n;
	int      echo_alive_k;        /* kernel's advisory verdict */
	uint64_t echo_last_send_us;   /* for inter-send gap tracking */
	uint64_t echo_gap_max_us;     /* windowed, reset each report */
	uint64_t echo_rtt_max_win_us; /* windowed, reset each report */
};

static struct session sessions[MAX_SESSIONS];

/* ---------- globals ---------- */
static int rx_sock = -1, tx_sock = -1, rx6_sock = -1, tx6_sock = -1;
static int rxm_sock = -1;   /* v4 multihop RX, port 4784 */
static int rxm6_sock = -1;  /* v6 multihop RX, port 4784 */

/* Per-slot TX sockets: source port = SRC_PORT + slot, bound to the
 * session's local address (INADDR_ANY would let routing source every
 * packet from the primary address, which breaks the peer's
 * address-based demux for your_disc=0 packets). Opened lazily and
 * kept; a reused slot with a different local address rebinds.
 * Stored as fd+1; 0 = not opened; -1 = bind failed. */
static int slot_tx[MAX_SESSIONS];
static struct bfd_addr slot_tx_ip[MAX_SESSIONS];

static int slot_sock(int slot, const struct session *s)
{
	if (slot_tx[slot] > 0 && !memcmp(&slot_tx_ip[slot], &s->local, 16))
		return slot_tx[slot] - 1;
	if (slot_tx[slot] < 0 && !memcmp(&slot_tx_ip[slot], &s->local, 16))
		return -1;   /* bind failed earlier; caller uses fallback */
	if (slot_tx[slot] > 0)
		close(slot_tx[slot] - 1);   /* slot reused, new local addr */
	slot_tx[slot] = 0;
	slot_tx_ip[slot] = s->local;
	int fd, rc;
	if (s->family == AF_INET6) {
		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		int hops = 255, on = 1;
		setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
		struct sockaddr_in6 sa6 = { .sin6_family = AF_INET6,
			.sin6_port = htons(SRC_PORT + slot) };
		memcpy(&sa6.sin6_addr, s->local.b, 16);
		rc = bind(fd, (void *)&sa6, sizeof(sa6));
	} else {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		int ttl = 255;
		setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
		struct sockaddr_in sa = { .sin_family = AF_INET,
			.sin_port = htons(SRC_PORT + slot) };
		memcpy(&sa.sin_addr.s_addr, &s->local.b[12], 4);
		rc = bind(fd, (void *)&sa, sizeof(sa));
	}
	if (rc) {
		fprintf(stderr,
			"slot %d: bind port %d: %s - using fallback socket "
			"(ephemeral src port) for this session\n",
			slot, SRC_PORT + slot, strerror(errno));
		close(fd);
		slot_tx[slot] = -1;
		return -1;
	}
	slot_tx[slot] = fd + 1;
	return fd;
}
static int use_ktx = 0;
static int cfg_fd = -1, sess_fd = -1, echo_peers_fd = -1;
static int echo_sock = -1, echo_ifindex = 0;
static int echo_disc_fd = -1;
static int flags_fd = -1;
static uint8_t echo_src_mac[6];
static uint32_t echo_nonce_ctr;
static struct bpf_object *bpf_obj;

static int dp_listen = -1, dp_conn = -1;
static uint8_t dp_buf[4096];
static size_t dp_have;
static uint64_t dp_hold_us;              /* --dp-hold: keep sessions
                                          * across bfdd restarts */
static uint64_t dp_reconcile_us;         /* sweep deadline after reconnect */
#define DP_RECONCILE_US (10ull * 1000000)

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

static struct session *sess_by_lid(uint32_t lid)
{
	if (!lid)
		return NULL;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].lid == lid)
			return &sessions[i];
	return NULL;
}

static struct session *sess_by_wire(uint32_t disc)
{
	if (!disc)
		return NULL;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].wire_disc == disc)
			return &sessions[i];
	return NULL;
}

static void sm_addrs(const struct bfddp_session_msg *sm,
		     struct bfd_addr *l, struct bfd_addr *p, int *family)
{
	if (ntohl(sm->flags) & SESSION_IPV6) {
		memcpy(l->b, &sm->src, 16);
		memcpy(p->b, &sm->dst, 16);
		*family = AF_INET6;
	} else {
		uint32_t lip, pip;
		memcpy(&lip, &sm->src.s6_addr[0], 4);
		memcpy(&pip, &sm->dst.s6_addr[0], 4);
		key_set_v4(l, lip);
		key_set_v4(p, pip);
		*family = AF_INET;
	}
}

static struct session *sess_by_addr_pair_local(
	const struct bfddp_session_msg *sm)
{
	struct bfd_addr l, p;
	int fam;
	sm_addrs(sm, &l, &p, &fam);
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used &&
		    !memcmp(&sessions[i].local, &l, 16) &&
		    !memcmp(&sessions[i].peer, &p, 16))
			return &sessions[i];
	return NULL;
}

static struct session *sess_by_addr(const struct bfd_addr *peer,
				    const struct bfd_addr *local)
{
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used &&
		    !memcmp(&sessions[i].peer, peer, 16) &&
		    !memcmp(&sessions[i].local, local, 16))
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
	echo_peers_fd = bpf_object__find_map_fd_by_name(bpf_obj, "echo_peers");
	echo_disc_fd = bpf_object__find_map_fd_by_name(bpf_obj, "echo_disc");
	flags_fd = bpf_object__find_map_fd_by_name(bpf_obj, "prog_flags");
	printf("kernel-tx: XDP attached to %s\n", ifname);

	/* Echo TX needs a raw L2 socket: a self-addressed UDP packet sent
	 * through a normal socket is routed to loopback and never reaches
	 * the wire. */
	echo_ifindex = ifindex;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	int mfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (mfd >= 0) {
		if (!ioctl(mfd, SIOCGIFHWADDR, &ifr))
			memcpy(echo_src_mac, ifr.ifr_hwaddr.sa_data, 6);
		close(mfd);
	}
	echo_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (echo_sock < 0)
		perror("echo raw socket");
	printf("echo-tx: ifindex %d src-mac %02x:%02x:%02x:%02x:%02x:%02x sock %d\n",
	       echo_ifindex, echo_src_mac[0], echo_src_mac[1], echo_src_mac[2],
	       echo_src_mac[3], echo_src_mac[4], echo_src_mac[5], echo_sock);
	return 0;
}

/* prog_flags bit 1 tells the XDP parser that at least one multihop
 * session exists, so it must defer the TTL verdict instead of dropping
 * everything below 255 outright. Clearing it again restores the cheap
 * early filter for single-hop-only deployments. */
static void ktx_update_mhop_flag(void)
{
	if (flags_fd < 0)
		return;

	int mhop = 0;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].min_ttl &&
		    sessions[i].min_ttl < 255) {
			mhop = 1;
			break;
		}

	__u32 zero = 0, fl = 0;
	bpf_map_lookup_elem(flags_fd, &zero, &fl);
	__u32 want = mhop ? (fl | 2u) : (fl & ~2u);
	if (want != fl)
		bpf_map_update_elem(flags_fd, &zero, &want, 0);
}

static void ktx_mirror(struct session *s)
{
	if (!use_ktx)
		return;
	struct tx_cfg c = {
		.echo_iv_us = s->echo_tx_us,
		.min_echo_rx_us = s->min_echo_rx_us,
		.min_ttl   = s->min_ttl,
		.enable    = (s->state == ST_UP),
		.my_disc   = s->wire_disc,
		.your_disc = s->rdisc,
		.min_tx_us = s->min_tx_us,
		.min_rx_us = s->min_rx_us,
		.src_port  = (__u16)(SRC_PORT + (s - sessions)),
		.state     = s->state,
		.diag      = s->diag,
		.mult      = s->detect_mult,
		.poll      = (s->polling && s->state == ST_UP) ? 1 : 0,
		.poll_seq  = s->poll_seq,
	};
	if (s->pushed_valid && !memcmp(&c, &s->pushed_cfg, sizeof(c)))
		return;
	struct session_key k = {};
	k.peer  = s->peer;
	k.local = s->local;
	bpf_map_update_elem(cfg_fd, &k, &c, 0);
	s->pushed_cfg = c;
	s->pushed_valid = 1;
}

static void ktx_clear(struct session *s)
{
	if (!use_ktx)
		return;
	struct session_key k = {};
	k.peer  = s->peer;
	k.local = s->local;
	bpf_map_delete_elem(cfg_fd, &k);
	bpf_map_delete_elem(sess_fd, &k);
	if (echo_peers_fd >= 0)
		bpf_map_delete_elem(echo_peers_fd, &s->peer);
	if (echo_disc_fd >= 0 && s->wire_disc)
		bpf_map_delete_elem(echo_disc_fd, &s->wire_disc);
	s->min_ttl = 0;
	ktx_update_mhop_flag();
}

static void dp_notify_state(struct session *s);
static void state_transition(struct session *s, int newstate, int diag,
			     uint64_t t, const char *why);

static void ktx_poll_map(struct session *s, uint64_t t)
{
	if (!use_ktx || s->state != ST_UP)
		return;
	struct session_key k = {};
	k.peer  = s->peer;
	k.local = s->local;
	struct session_state ms;
	if (bpf_map_lookup_elem(sess_fd, &k, &ms))
		return;
	if (ms.last_seen_ns / 1000 > s->last_rx_us)
		s->last_rx_us = ms.last_seen_ns / 1000;
	if (ms.detect_iv_us)
		s->detect_iv_us = ms.detect_iv_us;
	if (ms.mac_valid) {
		memcpy(s->peer_mac, ms.peer_mac, 6);
		s->mac_valid = 1;
	}
	/* Our echo returned. The arrival stamp is the kernel's, taken in
	 * softirq at RX, so this is wire RTT and not poll latency. */
	if (s->echo_sent_us && ms.echo_last_nonce == s->echo_nonce &&
	    ms.echo_last_seen_ns) {
		uint64_t arr = ms.echo_last_seen_ns / 1000;
		if (arr > s->echo_sent_us) {
			uint64_t rtt = arr - s->echo_sent_us;
			s->echo_rtt_last_us = rtt;
			if (!s->echo_rtt_min_us || rtt < s->echo_rtt_min_us)
				s->echo_rtt_min_us = rtt;
			if (rtt > s->echo_rtt_max_win_us)
				s->echo_rtt_max_win_us = rtt;
			if (rtt > s->echo_rtt_max_us)
				s->echo_rtt_max_us = rtt;
			s->echo_rtt_sum_us += rtt;
			s->echo_rtt_n++;
		}
		s->echo_rx_pkts++;
		s->echo_sent_us = 0;   /* no longer outstanding */
	}
	s->echo_alive_k = ms.echo_alive;
	if (s->polling && ms.final_seq == s->poll_seq) {
		/* Kernel acked the peer's F for this Poll sequence via
		 * final_seq; end the poll and mirror poll=0 down. tx_cfg
		 * has a single writer (us), so the old read-back dance
		 * and the pushed_cfg fixup are gone. */
		s->polling = 0;
		s->applied_tx_us = s->min_tx_us;
		ktx_mirror(s);
	}
	if (ms.min_tx_us && (ms.min_tx_us != s->r_min_tx ||
			     ms.min_rx_us != s->r_min_rx ||
			     ms.remote_min_echo_us != s->r_min_echo)) {
		s->r_min_tx = ms.min_tx_us;
		s->r_min_rx = ms.min_rx_us;
		s->r_min_echo = ms.remote_min_echo_us;
		dp_notify_state(s);
	}
	if (ms.remote_state == ST_DOWN)
		state_transition(s, ST_DOWN, 3, t, "map: peer sent Down");
}

/* ---------- dplane socket: outbound ---------- */
static void ktx_clear(struct session *s);

static void dp_sessions_teardown(const char *why)
{
	int n = 0;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used) {
			ktx_clear(&sessions[i]);
			memset(&sessions[i], 0, sizeof(sessions[i]));
			n++;
		}
	if (n)
		printf("dplane: %s - tore down %d session(s)\n", why, n);
}

static void sess_teardown_one(struct session *s, const char *why)
{
	printf("dplane: lid=%u %s - torn down\n", s->lid, why);
	ktx_clear(s);
	memset(s, 0, sizeof(*s));
}

/* Connection lost: with --dp-hold, keep the wire sessions alive and
 * mark them orphaned (graceful restart); otherwise the historical
 * drop-and-recreate. Reconciliation happens after reconnect. */
static void dp_sessions_orphan(const char *why)
{
	if (!dp_hold_us) {
		dp_sessions_teardown(why);
		return;
	}
	uint64_t t = now_us();
	int n = 0;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && !sessions[i].orphaned) {
			sessions[i].orphaned = 1;
			sessions[i].orphan_deadline_us = t + dp_hold_us;
			n++;
		}
	if (n)
		printf("dplane: %s - holding %d session(s) up to %llus\n",
		       why, n, (unsigned long long)(dp_hold_us / 1000000));
}

static void dp_send(const void *msg, size_t len)
{
	if (dp_conn < 0)
		return;
	if (send(dp_conn, msg, len, MSG_NOSIGNAL) < 0) {
		printf("dplane: send failed (%s), dropping connection\n",
		       strerror(errno));
		close(dp_conn);
		dp_conn = -1;
		dp_have = 0;
		dp_sessions_orphan("send failure");
	}
}

static void dp_notify_state(struct session *s)
{
	struct {
		struct bfddp_message_header h;
		struct bfddp_state_change   sc;
	} __attribute__((packed)) m = {0};

	m.h.version = 1;
	m.h.type    = htons(BFD_STATE_CHANGE);
	m.h.id      = 0;                      /* async */
	m.h.length  = htons(sizeof(m));
	m.sc.lid    = htonl(s->lid);
	m.sc.rid    = htonl(s->rdisc);
	m.sc.remote_flags = htonl(s->r_flags);
	m.sc.desired_tx   = htonl(s->r_min_tx);
	m.sc.required_rx  = htonl(s->r_min_rx);
	m.sc.required_echo_rx = htonl(s->r_min_echo);
	m.sc.state  = s->state;
	m.sc.diagnostics = s->diag;
	m.sc.detection_multiplier = s->r_mult;
	dp_send(&m, sizeof(m));
}

/* ---------- FSM ---------- */
static void state_transition(struct session *s, int newstate, int diag,
			     uint64_t t, const char *why)
{
	if (s->state == newstate)
		return;
	printf("[%llu] lid=%u %s -> %s (%s)\n", (unsigned long long)t,
	       s->lid, stname[s->state], stname[newstate], why);
	s->state = newstate;
	s->diag  = diag;
	if (newstate == ST_DOWN)
		s->detect_iv_us = 0;
	if (newstate == ST_UP || newstate == ST_DOWN) {
		s->polling = 0;
		s->applied_tx_us = s->min_tx_us;
	}
	s->just_up = (newstate == ST_UP);
	s->next_tx_us = t;
	dp_notify_state(s);
}

static void fsm_rx(struct session *s, const struct bfdpkt *p, uint64_t t)
{
	int ps = (p->flags >> 6) & 3;

	{
		uint32_t ntx = ntohl(p->min_tx), nrx = ntohl(p->min_rx);
		if (s->state == ST_UP &&
		    (ntx != s->r_min_tx || nrx != s->r_min_rx)) {
			s->r_min_tx = ntx;
			s->r_min_rx = nrx;
			dp_notify_state(s);   /* refresh remote timers */
		}
	}
	s->rdisc    = ntohl(p->my_disc);
	s->r_state  = ps;
	s->r_min_rx = ntohl(p->min_rx);
	s->r_min_tx = ntohl(p->min_tx);
	s->r_min_echo = ntohl(p->min_echo);
	s->r_mult   = p->mult;
	s->r_flags  = p->flags & 0x3f;

	/* Poll-aware detect basis: decreases apply only once traffic
	 * actually paces at the new interval (RFC 5880 s6.8.3). */
	{
		uint32_t cand = s->r_min_tx > s->min_rx_us ?
				s->r_min_tx : s->min_rx_us;
		if (!s->detect_iv_us || cand >= s->detect_iv_us ||
		    (s->last_rx_us && t - s->last_rx_us <= cand))
			s->detect_iv_us = cand;
	}

	s->last_rx_us = t;
	if (p->flags & F_P)
		s->send_final = 1;
	if ((p->flags & F_F) && s->polling) {
		s->polling = 0;
		s->applied_tx_us = s->min_tx_us;
	}

	if (s->admin_down)
		return;

	if (ps == ST_ADMINDOWN) {
		if (s->state != ST_DOWN)
			state_transition(s, ST_DOWN, 3, t, "peer AdminDown");
		return;
	}
	switch (s->state) {
	case ST_DOWN:
		if (ps == ST_DOWN && !s->passive)
			state_transition(s, ST_INIT, s->diag, t,
					 "peer sent Down");
		else if (ps == ST_INIT)
			state_transition(s, ST_UP, 0, t, "peer sent Init");
		break;
	case ST_INIT:
		if (ps == ST_INIT || ps == ST_UP)
			state_transition(s, ST_UP, 0, t, "peer up");
		break;
	case ST_UP:
		if (ps == ST_DOWN)
			state_transition(s, ST_DOWN, 3, t, "peer sent Down");
		break;
	}
}

static void fsm_detect(struct session *s, uint64_t t)
{
	if (s->state == ST_DOWN || s->state == ST_ADMINDOWN || !s->last_rx_us)
		return;
	uint64_t iv = s->detect_iv_us;
	if (!iv)
		iv = s->r_min_tx > s->min_rx_us ? s->r_min_tx : s->min_rx_us;
	int64_t sd = (int64_t)(t - s->last_rx_us);
	if (sd < 0)
		sd = 0;
	uint8_t mult = s->r_mult ? s->r_mult : s->detect_mult;
	if ((uint64_t)sd > (uint64_t)mult * iv) {
		printf("[%llu] lid=%u DETECT TIMEOUT (silent %.1fms)\n",
		       (unsigned long long)t, s->lid, sd / 1000.0);
		s->rdisc = 0;
		state_transition(s, ST_DOWN, 1, t, "detect timeout");
	}
}

/* ---- m8b: echo originator ---- */
static uint16_t ip_csum(const void *data, size_t len)
{
	const uint16_t *w = data;
	uint32_t sum = 0;
	while (len > 1) { sum += *w++; len -= 2; }
	if (len) sum += *(const uint8_t *)w;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* Self-addressed UDP/3785 to the neighbour's MAC, TTL 255. The trailing
 * payload word carries a nonce; the return is matched on it for RTT.
 * Detection keys off the outstanding nonce, so if this stalls there is
 * simply no echo outstanding and no timeout can fire. */
static void echo_tx_maybe(struct session *s, uint64_t t)
{
	if (echo_sock < 0 || !s->echo_tx_us || s->state != ST_UP)
		return;
	if (!s->mac_valid || s->family != AF_INET)
		return;
	if (t < s->next_echo_tx_us)
		return;
	if (s->echo_last_send_us) {
		uint64_t gap = t - s->echo_last_send_us;
		if (gap > s->echo_gap_max_us)
			s->echo_gap_max_us = gap;
	}
	s->echo_last_send_us = t;
	s->next_echo_tx_us = t + s->echo_tx_us;

	/* Previous echo never came back before this one is due. */
	if (s->echo_sent_us) {
		s->echo_lost++;
		s->echo_sent_us = 0;
	}

	if (!s->echo_disc_done && echo_disc_fd >= 0 && s->wire_disc) {
		struct session_key dk = {};
		dk.peer  = s->peer;
		dk.local = s->local;
		if (!bpf_map_update_elem(echo_disc_fd, &s->wire_disc, &dk, 0))
			s->echo_disc_done = 1;
	}

	uint8_t frame[66];
	memset(frame, 0, sizeof(frame));

	memcpy(frame + 0, s->peer_mac, 6);
	memcpy(frame + 6, echo_src_mac, 6);
	frame[12] = 0x08;
	frame[13] = 0x00;

	uint8_t *ip = frame + 14;
	uint16_t tot = 20 + 8 + 24;
	ip[0] = 0x45;
	ip[1] = 0xc0;
	ip[2] = tot >> 8;
	ip[3] = tot & 0xff;
	ip[8] = 255;
	ip[9] = 17;
	memcpy(ip + 12, s->local.b + 12, 4);
	memcpy(ip + 16, s->local.b + 12, 4);
	uint16_t ipc = ip_csum(ip, 20);
	memcpy(ip + 10, &ipc, 2);

	uint8_t *udp = frame + 34;
	uint16_t ulen = 8 + 24;
	udp[0] = 3785 >> 8; udp[1] = 3785 & 0xff;
	udp[2] = 3785 >> 8; udp[3] = 3785 & 0xff;
	udp[4] = ulen >> 8; udp[5] = ulen & 0xff;

	uint8_t *b = frame + 42;
	uint32_t v, nonce = ++echo_nonce_ctr;
	b[0] = (1 << 5);
	b[1] = (ST_UP & 0x3) << 6;
	b[2] = s->detect_mult;
	b[3] = 24;
	v = htonl(s->wire_disc); memcpy(b + 4,  &v, 4);
	v = 0;                   memcpy(b + 8,  &v, 4);
	v = htonl(s->min_tx_us); memcpy(b + 12, &v, 4);
	v = htonl(s->min_rx_us); memcpy(b + 16, &v, 4);
	v = htonl(nonce);        memcpy(b + 20, &v, 4);

	uint8_t ps[12 + 8 + 24];
	memcpy(ps + 0, ip + 12, 4);
	memcpy(ps + 4, ip + 16, 4);
	ps[8]  = 0;
	ps[9]  = 17;
	ps[10] = ulen >> 8;
	ps[11] = ulen & 0xff;
	memcpy(ps + 12, udp, 8);
	memcpy(ps + 20, b, 24);
	uint16_t uc = ip_csum(ps, sizeof(ps));
	if (!uc)
		uc = 0xffff;
	memcpy(udp + 6, &uc, 2);

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family  = AF_PACKET;
	sll.sll_ifindex = echo_ifindex;
	sll.sll_halen   = 6;
	memcpy(sll.sll_addr, s->peer_mac, 6);

	if (sendto(echo_sock, frame, sizeof(frame), 0,
		   (struct sockaddr *)&sll, sizeof(sll)) < 0)
		return;

	s->echo_nonce   = nonce;
	s->echo_sent_us = t;
	s->echo_tx_pkts++;

	if (s->echo_tx_pkts % 100 == 0) {
		const uint8_t *lo = s->local.b + 12, *pe = s->peer.b + 12;
		uint64_t avg = s->echo_rtt_n ? s->echo_rtt_sum_us / s->echo_rtt_n : 0;
		printf("echo %u.%u.%u.%u->%u.%u.%u.%u tx=%llu rx=%llu lost=%llu "
		       "rtt last/min/avg/max %llu/%llu/%llu/%llu us win-max %llu gap-max %lluus echo-alive=%d\n",
		       lo[0], lo[1], lo[2], lo[3], pe[0], pe[1], pe[2], pe[3],
		       (unsigned long long)s->echo_tx_pkts,
		       (unsigned long long)s->echo_rx_pkts,
		       (unsigned long long)s->echo_lost,
		       (unsigned long long)s->echo_rtt_last_us,
		       (unsigned long long)s->echo_rtt_min_us,
		       (unsigned long long)avg,
		       (unsigned long long)s->echo_rtt_max_us,
		       (unsigned long long)s->echo_rtt_max_win_us,
		       (unsigned long long)s->echo_gap_max_us,
		       s->echo_alive_k);
		s->echo_gap_max_us = 0;
		s->echo_rtt_max_win_us = 0;
		fflush(stdout);
	}
}


static void fsm_tx(struct session *s, uint64_t t)
{
	if (s->admin_down && s->state != ST_ADMINDOWN)
		state_transition(s, ST_ADMINDOWN, 7, t, "admin shutdown");

	if (s->last_rx_us) {
		uint64_t cur = (s->state == ST_UP)
			? (s->applied_tx_us > s->r_min_rx ? s->applied_tx_us
							  : s->r_min_rx)
			: SLOW_TX_US;
		if (s->next_tx_us > t + cur)
			s->next_tx_us = t + cur;
	}

	int due = (t >= s->next_tx_us) || s->send_final;
	if (use_ktx && s->state == ST_UP && !s->send_final && !s->just_up) {
		/* Kernel echo covers TX only at the peer's pace. If the
		 * peer paces slower than our required rate (its detect
		 * budget for us), transmit from here at the required
		 * pace; otherwise stay silent as before. last_rx_us is
		 * synced from the map, so it tracks kernel echo times. */
		uint64_t pace = s->applied_tx_us > s->r_min_rx ?
				s->applied_tx_us : s->r_min_rx;
		if (t - s->last_rx_us < pace)
			due = 0;
	}
	if (!due)
		return;

	struct bfdpkt o = {0};
	o.vers_diag = (1 << 5) | (s->diag & 0x1f);
	o.flags     = (s->state << 6) |
		      (s->send_final ? F_F : (s->polling ? F_P : 0));
	o.mult      = s->detect_mult;
	o.len       = 24;
	o.my_disc   = htonl(s->wire_disc);
	o.your_disc = htonl(s->rdisc);
	o.min_tx    = htonl(s->state == ST_UP ? s->min_tx_us
					      : (uint32_t)SLOW_TX_US);
	o.min_rx    = htonl(s->min_rx_us);
	o.min_echo  = htonl(s->min_echo_rx_us);

	int txfd = slot_sock((int)(s - sessions), s);
	if (txfd < 0)
		txfd = s->family == AF_INET6 ? tx6_sock : tx_sock;
	if (s->family == AF_INET6) {
		struct sockaddr_in6 dst = { .sin6_family = AF_INET6,
			.sin6_port = htons(s->is_mhop ? BFD_PORT_MHOP : PORT_CTRL) };
		memcpy(&dst.sin6_addr, s->peer.b, 16);
		sendto(txfd, &o, 24, 0, (void *)&dst, sizeof(dst));
	} else {
		struct sockaddr_in dst = { .sin_family = AF_INET,
			.sin_port = htons(s->is_mhop ? BFD_PORT_MHOP : PORT_CTRL) };
		memcpy(&dst.sin_addr.s_addr, &s->peer.b[12], 4);
		sendto(txfd, &o, 24, 0, (void *)&dst, sizeof(dst));
	}
	s->tx_pkts++;
	s->send_final = 0;
	s->just_up = 0;

	if (t >= s->next_tx_us) {
		uint64_t iv;
		if (s->state == ST_UP) {
			iv = s->applied_tx_us > s->r_min_rx ? s->applied_tx_us
							    : s->r_min_rx;
			/* RFC 5880 s6.8.7: jitter the interval to 75-100%,
			 * but only 75-90% when detect_mult is 1. */
			uint64_t span = s->detect_mult == 1 ? iv * 3 / 20
							    : iv / 4;
			iv = iv * 3 / 4 + (random() % (span + 1));
		} else {
			iv = SLOW_TX_US;
		}
		s->next_tx_us = t + iv;
	}
}

/* ---------- dplane socket: inbound handlers ---------- */
static void dp_handle_add(const struct bfddp_message_header *h,
			  const struct bfddp_session_msg *sm, uint64_t t)
{
	uint32_t flags = ntohl(sm->flags);
	uint32_t lid   = ntohl(sm->lid);

	/* Multihop is supported: bfdd sends the negotiated minimum TTL in
	 * the ADD and the XDP parser enforces it per session. Demand mode
	 * is not implemented, so it is still refused. */
	if (flags & SESSION_DEMAND) {
		printf("dplane: ADD lid=%u rejected (unsupported flags 0x%x)\n",
		       lid, flags);
		return;
	}

	struct session *s = sess_by_lid(lid);
	int fresh = 0, adopted = 0;
	if (s)
		s->orphaned = 0;   /* any bfdd message naming this lid proves
		                    * it survived the reconnect; unmark, or the
		                    * reconcile sweep tears down a live session
		                    * (bfdd can reconnect with stable lids) */
	if (!s) {
		struct session *stale = sess_by_addr_pair_local(sm);
		if (stale && dp_hold_us && stale->state == ST_UP) {
			/* Graceful restart: bfdd re-registered this addr
			 * pair under a new lid. Adopt the live session in
			 * place; wire_disc, FSM state, kernel maps and
			 * counters all survive. */
			printf("dplane: ADD lid=%u adopts live session (old lid=%u)\n",
			       lid, stale->lid);
			s = stale;
			s->orphaned = 0;
			adopted = 1;
		} else if (stale) {
			printf("dplane: ADD lid=%u replaces stale lid=%u\n",
			       lid, stale->lid);
			ktx_clear(stale);
			memset(stale, 0, sizeof(*stale));
		}
	}
	if (!s) {
		s = sess_alloc();
		if (!s) {
			printf("dplane: session table full\n");
			return;
		}
		fresh = 1;
	}

	s->lid         = lid;
	if (fresh || !s->wire_disc)
		s->wire_disc = lid;   /* adopted sessions keep their wire
		                       * discriminator (RFC 5880: constant
		                       * while Up) */
	sm_addrs(sm, &s->local, &s->peer, &s->family);
	uint32_t old_tx = s->min_tx_us, old_rx = s->min_rx_us;
	s->min_tx_us   = ntohl(sm->min_tx);
	s->min_rx_us   = ntohl(sm->min_rx);
	s->detect_mult = sm->detect_mult;
	s->passive     = !!(flags & SESSION_PASSIVE);
	s->admin_down  = !!(flags & SESSION_SHUTDOWN);
	s->echo_tx_us  = (flags & SESSION_ECHO) ? ntohl(sm->min_echo_tx) : 0;
	s->min_echo_rx_us = (flags & SESSION_ECHO)
				    ? ntohl(sm->min_echo_rx) : 0;
	s->min_ttl     = sm->ttl ? sm->ttl : 255;
	s->is_mhop     = !!(flags & SESSION_MULTIHOP);
	ktx_update_mhop_flag();
	/* echo policy: track peers of echo-active v4 sessions so the
	 * reflector returns only their echoes, not arbitrary 3785 traffic. */
	if (echo_peers_fd >= 0 && s->family == AF_INET) {
		if (flags & SESSION_ECHO) {
			__u8 one = 1;
			bpf_map_update_elem(echo_peers_fd, &s->peer, &one, 0);
		} else {
			bpf_map_delete_elem(echo_peers_fd, &s->peer);
		}
	}
	if (!fresh && s->state == ST_UP &&
	    (s->min_tx_us != old_tx || s->min_rx_us != old_rx)) {
		/* RFC 5880 s6.8.3: parameter change while Up requires a
		 * Poll sequence. An increased min_tx must not slow actual
		 * TX until the poll terminates; a decrease applies now. */
		s->poll_seq++;
		s->polling = 1;
		if (s->min_tx_us < s->applied_tx_us || !s->applied_tx_us)
			s->applied_tx_us = s->min_tx_us;
	} else {
		s->applied_tx_us = s->min_tx_us;
	}
	if (fresh) {
		s->state = s->admin_down ? ST_ADMINDOWN : ST_DOWN;
		s->diag  = 0;
		s->pushed_valid = 0;
		s->next_tx_us = t;
	}

	if (!fresh && !s->admin_down && s->state == ST_ADMINDOWN) {
		/* SHUTDOWN flag cleared on an existing session: leave
		 * AdminDown and restart the FSM. Entry into AdminDown is
		 * in fsm_tick; without this, the exit never happens. */
		state_transition(s, ST_DOWN, 0, now_us(),
				 "admin shutdown cleared");
		s->next_tx_us = now_us();
	}

	char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
	if (s->family == AF_INET6) {
		inet_ntop(AF_INET6, s->local.b, a, sizeof(a));
		inet_ntop(AF_INET6, s->peer.b, b, sizeof(b));
	} else {
		inet_ntop(AF_INET, &s->local.b[12], a, sizeof(a));
		inet_ntop(AF_INET, &s->peer.b[12], b, sizeof(b));
	}
	printf("dplane: %s session lid=%u %s -> %s tx=%uus rx=%uus mult=%u%s%s\n",
	       fresh ? "ADD" : "UPDATE", lid, a, b,
	       s->min_tx_us, s->min_rx_us, s->detect_mult,
	       s->passive ? " passive" : "",
	       s->admin_down ? " shutdown" : "");
	if (adopted)
		dp_notify_state(s);
	(void)h;
}

static void dp_handle_delete(const struct bfddp_session_msg *sm)
{
	struct session *s = sess_by_lid(ntohl(sm->lid));
	if (!s)
		return;
	printf("dplane: DELETE session lid=%u\n", s->lid);
	ktx_clear(s);
	memset(s, 0, sizeof(*s));
}

static void dp_handle_echo_req(const struct bfddp_message_header *h,
			       const struct bfddp_echo *e)
{
	struct {
		struct bfddp_message_header h;
		struct bfddp_echo           e;
	} __attribute__((packed)) m = {0};

	m.h.version = 1;
	m.h.type    = htons(ECHO_REPLY);
	m.h.id      = h->id;
	m.h.length  = htons(sizeof(m));
	m.e.bfdd_time = e->bfdd_time;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	m.e.dp_time = htobe64((uint64_t)ts.tv_sec * 1000000ull +
			      ts.tv_nsec / 1000);
	dp_send(&m, sizeof(m));
}

static void dp_handle_counters_req(const struct bfddp_message_header *h,
				   const uint32_t *lid_be)
{
	struct {
		struct bfddp_message_header h;
		struct bfddp_counters       c;
	} __attribute__((packed)) m = {0};

	uint32_t lid = ntohl(*lid_be);
	struct session *s = sess_by_lid(lid);

	m.h.version = 1;
	m.h.type    = htons(BFD_SESSION_COUNTERS);
	m.h.id      = h->id;
	m.h.length  = htons(sizeof(m));
	m.c.lid     = htonl(lid);
	if (s) {
		uint64_t rx = 0, ktx = 0;
		if (use_ktx) {
			struct session_key k = {};
			k.peer  = s->peer;
			k.local = s->local;
			struct session_state ms;
			if (!bpf_map_lookup_elem(sess_fd, &k, &ms)) {
				rx  = ms.rx_pkts;
				ktx = ms.tx_pkts;
			}
		}
		uint64_t tx = s->tx_pkts + ktx;
		m.c.control_input_bytes    = htobe64(rx * 24);
		m.c.control_input_packets  = htobe64(rx);
		m.c.control_output_bytes   = htobe64(tx * 24);
		m.c.control_output_packets = htobe64(tx);
	}
	dp_send(&m, sizeof(m));
}

static void dp_process(const uint8_t *buf, size_t len)
{
	const struct bfddp_message_header *h = (const void *)buf;
	uint16_t type = ntohs(h->type);
	const uint8_t *payload = buf + sizeof(*h);
	size_t plen = len - sizeof(*h);
	uint64_t t = now_us();

	switch (type) {
	case DP_ADD_SESSION:
		if (plen >= sizeof(struct bfddp_session_msg))
			dp_handle_add(h, (const void *)payload, t);
		break;
	case DP_DELETE_SESSION:
		if (plen >= sizeof(struct bfddp_session_msg))
			dp_handle_delete((const void *)payload);
		break;
	case ECHO_REQUEST:
		if (plen >= sizeof(struct bfddp_echo))
			dp_handle_echo_req(h, (const void *)payload);
		break;
	case ECHO_REPLY:
		break;   /* our own probes, nothing to do in v0 */
	case DP_REQUEST_SESSION_COUNTERS:
		if (plen >= sizeof(uint32_t))
			dp_handle_counters_req(h, (const void *)payload);
		break;
	default:
		printf("dplane: unhandled message type %u\n", type);
	}
}

static void dp_read(void)
{
	if (dp_conn < 0)
		return;
	ssize_t n = recv(dp_conn, dp_buf + dp_have,
			 sizeof(dp_buf) - dp_have, 0);
	if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
		printf("dplane: bfdd disconnected\n");
		close(dp_conn);
		dp_conn = -1;
		dp_have = 0;
		dp_sessions_orphan("bfdd disconnected");
		return;
	}
	if (n < 0)
		return;
	dp_have += n;

	/* Frame: header.length = total message size including header. */
	size_t off = 0;
	while (dp_have - off >= sizeof(struct bfddp_message_header)) {
		const struct bfddp_message_header *h =
			(const void *)(dp_buf + off);
		uint16_t mlen = ntohs(h->length);
		if (mlen < sizeof(*h) || mlen > sizeof(dp_buf)) {
			/* Framing lost on a byte stream: resetting the buffer
			 * but keeping the connection would resync onto arbitrary
			 * mid-stream bytes. Drop the connection instead and let
			 * bfdd reconnect from a clean boundary. With --dp-hold
			 * the sessions survive the reconnect. */
			printf("dplane: bad frame length %u, dropping connection\n",
			       mlen);
			close(dp_conn);
			dp_conn = -1;
			dp_have = 0;
			dp_sessions_orphan("bad frame length");
			return;
		}
		if (dp_have - off < mlen)
			break;
		dp_process(dp_buf + off, mlen);
		off += mlen;
	}
	if (off) {
		memmove(dp_buf, dp_buf + off, dp_have - off);
		dp_have -= off;
	}
}

static void dp_accept(void)
{
	if (dp_listen < 0)
		return;
	int c = accept(dp_listen, NULL, NULL);
	if (c < 0)
		return;
	if (dp_conn >= 0) {
		printf("dplane: replacing existing bfdd connection\n");
		close(dp_conn);
		dp_have = 0;
		dp_sessions_orphan("connection replaced");
	}
	fcntl(c, F_SETFL, O_NONBLOCK);
	dp_conn = c;
	printf("dplane: bfdd connected\n");
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].orphaned) {
			dp_reconcile_us = now_us() + DP_RECONCILE_US;
			printf("dplane: reconcile sweep armed (%llus)\n",
			       (unsigned long long)(DP_RECONCILE_US / 1000000));
			break;
		}
}

static int dp_listen_init(const char *arg)
{
	/* "<path>" = unix socket; "<port number>" = TCP on 127.0.0.1.
	 * Note: FRR <=10.5 bfdd unixc: client mode passes an oversized
	 * addrlen to connect(2), which AF_UNIX rejects (EINVAL) - use
	 * TCP with those versions. */
	if (arg[0] == '/') {
		dp_listen = socket(AF_UNIX, SOCK_STREAM, 0);
		struct sockaddr_un su = { .sun_family = AF_UNIX };
		strncpy(su.sun_path, arg, sizeof(su.sun_path) - 1);
		unlink(arg);
		if (bind(dp_listen, (void *)&su, sizeof(su)) ||
		    listen(dp_listen, 1)) {
			perror("dplane listen (unix)");
			return -1;
		}
		chmod(arg, 0666);
		printf("dplane: listening on %s (bfdd: unixc:%s)\n",
		       arg, arg);
	} else {
		int port = atoi(arg);
		dp_listen = socket(AF_INET, SOCK_STREAM, 0);
		int one = 1;
		setsockopt(dp_listen, SOL_SOCKET, SO_REUSEADDR, &one,
			   sizeof(one));
		struct sockaddr_in si = {
			.sin_family = AF_INET,
			.sin_port = htons(port),
			.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		};
		if (bind(dp_listen, (void *)&si, sizeof(si)) ||
		    listen(dp_listen, 1)) {
			perror("dplane listen (tcp)");
			return -1;
		}
		printf("dplane: listening on 127.0.0.1:%d (bfdd: ipv4c:127.0.0.1:%d)\n",
		       port, port);
	}
	fcntl(dp_listen, F_SETFL, O_NONBLOCK);
	return 0;
}

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
			"       %s --dplane <port|sock-path> [--kernel-tx <if>] [--dp-hold <sec>]\n",
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

		struct bfdpkt p;
		struct sockaddr_in from;
		struct iovec iov = { .iov_base = &p, .iov_len = sizeof(p) };
		char cbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
		struct msghdr mh = {
			.msg_name = &from, .msg_namelen = sizeof(from),
			.msg_iov = &iov, .msg_iovlen = 1,
			.msg_control = cbuf, .msg_controllen = sizeof(cbuf),
		};
		ssize_t n = recvmsg(rx_sock, &mh, 0);
		uint64_t t = now_us();

		if (n >= 24 && ((p.vers_diag >> 5) & 7) == 1 &&
		    p.mult && p.my_disc) {
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
			struct bfdpkt pm;
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
			if (nm < 24 || ((pm.vers_diag >> 5) & 7) != 1 ||
			    !pm.mult || !pm.my_disc)
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
			struct bfdpkt p6;
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
			if (n6 < 24 || ((p6.vers_diag >> 5) & 7) != 1 ||
			    !p6.mult || !p6.my_disc)
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
			struct bfdpkt pm6;
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
			if (nm6 < 24 || ((pm6.vers_diag >> 5) & 7) != 1 ||
			    !pm6.mult || !pm6.my_disc)
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
