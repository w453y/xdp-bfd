// SPDX-License-Identifier: GPL-2.0
/* Part of the xdp_run test, split by subject (CI-review item 5).
 * Compiled as one unit via tests/unit/xdp_run.c, which carries the
 * includes, the shared globals and main; include order there is the
 * dependency order (harness first, sweep last). */

/* The v4 echo reflector. Five dispositions, five counters.
 *
 * Ordering is the thing worth pinning. The "our own echo coming back" check
 * runs before GTSM and accepts TTL 254, which is what a neighbour's
 * forwarding plane leaves. It is guarded by self-addressing as well, so a
 * 254 frame that is not self-addressed must fall through to the GTSM check
 * rather than through the exception - otherwise the exception is a general
 * TTL bypass. The not-self-at-254 arm below is that test. */
static void build_echo(struct frame *f, uint8_t ttl, const char *src,
		       const char *dst, uint32_t my_disc, uint32_t nonce)
{
	struct bfd_ctrl_pkt p = ctrl_up();

	p.my_disc     = htonl(my_disc);
	p.min_echo_rx = htonl(nonce);
	build_v4(f, ttl, BFD_ECHO_PORT, &p, 0);

	struct iphdr *ip = (void *)(f->b + sizeof(struct ethhdr));
	ip->saddr = inet_addr(src);
	ip->daddr = inet_addr(dst);
	ip->check = 0;
	ip->check = csum16(ip, sizeof(*ip), 0);
}

static void case_echo(const char *name, uint8_t ttl, const char *src,
		      const char *dst, int arm_peer, int arm_disc,
		      int want_v, int slot)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_addr peer = {0};
	unsigned long long before;
	struct frame f;
	int v, bad = 0;
	__u32 one = 1, disc = 0x33333333;

	map_reset();
	arm_session();

	if (arm_peer) {
		__u32 a = inet_addr(src);

		peer.b[10] = 0xff; peer.b[11] = 0xff;
		memcpy(&peer.b[12], &a, 4);
		bpf_map_update_elem(echo_peers_fd, &peer, &one, BPF_ANY);
	}
	if (arm_disc)
		bpf_map_update_elem(echo_disc_fd, &disc, &k, BPF_ANY);

	build_echo(&f, ttl, src, dst, disc, 0xa5a5a5a5);

	before = stat_get(slot);
	v = run_frame(&f, NULL, NULL);

	if (v != want_v) {
		printf("     verdict %s, want %s\n",
		       v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want_v));
		bad = 1;
	}
	if (stat_get(slot) != before + 1) {
		printf("     stat slot %d did not increment\n", slot);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s %s\n", name, verdict_str(want_v));
	}

	if (arm_peer)
		bpf_map_delete_elem(echo_peers_fd, &peer);
	if (arm_disc)
		bpf_map_delete_elem(echo_disc_fd, &disc);
	map_reset();
}

static void run_echo_matrix(void)
{
	/* our own echo returning: 254 and self-addressed, consumed */
	case_echo("echo-returns", 254, "10.0.0.1", "10.0.0.1", 0, 1,
		  XDP_DROP, BFD_STAT_ECHO_RETURNS);
	/* 254 but not self-addressed: the exception in parse.h requires
	 * BOTH, so this is rejected by the parser's GTSM before the echo
	 * path runs. The exception is not a general TTL bypass, which is
	 * what this arm exists to prove. */
	case_echo("echo-254-not-self-rejected", 254, "10.0.0.2", "10.0.0.1",
		  1, 0, XDP_DROP, BFD_STAT_REJECTED);
	/* Off-link echo: same parser GTSM, same disposition. echo.h has its
	 * own ECHO_TTL check, but no v4 frame reaches it while the parser
	 * drops everything that is neither 255 nor the 254 exception. */
	case_echo("echo-off-link-rejected", 200, "10.0.0.2", "10.0.0.2", 1, 0,
		  XDP_DROP, BFD_STAT_REJECTED);
	/* not self-addressed at 255 */
	case_echo("echo-not-self", 255, "10.0.0.2", "10.0.0.1", 1, 0,
		  XDP_PASS, BFD_STAT_NOT_SELF);
	/* self-addressed but the peer is not echo-active: no amplifier */
	case_echo("echo-declined", 255, "10.0.0.2", "10.0.0.2", 0, 0,
		  XDP_PASS, BFD_STAT_DECLINED);
	/* self-addressed and echo-active: reflected */
	case_echo("echo-reflect", 255, "10.0.0.2", "10.0.0.2", 1, 0,
		  XDP_TX, BFD_STAT_REFLECTED);
}

/* The v6 echo reflector and the return path, mirroring run_echo_matrix.
 *
 * The return arm is the one that needs the parser. parse.h's v4 GTSM has a
 * narrow exception for our own echo at TTL 254 and self-addressed; the v6
 * branch needs the same one or echo_reflect_v6's return branch is
 * unreachable and v6 echo RTT never updates. The not-self-at-254 arm is
 * what keeps that exception from becoming a general hop-limit bypass. */
static void build_echo_v6(struct frame *f, uint8_t hlim, const char *src,
			  const char *dst, uint32_t my_disc, uint32_t nonce)
{
	struct bfd_ctrl_pkt p = ctrl_up();

	p.my_disc     = htonl(my_disc);
	p.min_echo_rx = htonl(nonce);
	build_v6(f, hlim, BFD_ECHO_PORT, &p, 0);

	struct ipv6hdr *ip6 = (void *)(f->b + sizeof(struct ethhdr));
	inet_pton(AF_INET6, src, &ip6->saddr);
	inet_pton(AF_INET6, dst, &ip6->daddr);
}

static void case_echo_v6(const char *name, uint8_t hlim, const char *src,
			 const char *dst, int arm_peer, int want_v, int slot)
{
	struct bfd_addr peer = {0};
	unsigned long long before;
	struct frame f;
	int v, bad = 0;
	__u32 one = 1;

	map_reset_v6();
	arm_session_v6();

	if (arm_peer) {
		inet_pton(AF_INET6, src, peer.b);
		bpf_map_update_elem(echo_peers_fd, &peer, &one, BPF_ANY);
	}

	build_echo_v6(&f, hlim, src, dst, 0x33333333, 0xa5a5a5a5);

	before = stat_get(slot);
	v = run_frame(&f, NULL, NULL);

	if (v != want_v) {
		printf("     verdict %s, want %s\n",
		       v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want_v));
		bad = 1;
	}
	if (stat_get(slot) != before + 1) {
		printf("     stat slot %d did not increment\n", slot);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s %s\n", name, verdict_str(want_v));
	}

	if (arm_peer)
		bpf_map_delete_elem(echo_peers_fd, &peer);
	map_reset_v6();
}

/* Our own v6 echo coming back.
 *
 * Two arms, because the map writes are what the userspace RTT plumbing
 * reads and an assertion on them is vacuous without one that must not
 * fire: with the discriminator in echo_disc the frame is consumed and the
 * session's echo fields move; with a discriminator we never sent, the same
 * frame must fall out to the stack and leave them alone. */
static void case_echo_v6_return(int arm_disc, int want_v, const char *name)
{
	struct session_key k = key_v6("fd00::2", "fd00::1");
	struct session_state st;
	unsigned long long before;
	struct frame f;
	int v, bad = 0;
	__u32 disc = 0x33333333, nonce = 0xa5a5a5a5;

	map_reset_v6();
	arm_session_v6();

	if (arm_disc)
		bpf_map_update_elem(echo_disc_fd, &disc, &k, BPF_ANY);

	build_echo_v6(&f, 254, "fd00::1", "fd00::1", disc, nonce);

	before = stat_get(BFD_STAT_ECHO_RETURNS);
	v = run_frame(&f, NULL, NULL);

	if (v != want_v) {
		printf("     verdict %s, want %s\n",
		       v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want_v));
		bad = 1;
	}
	if (stat_get(BFD_STAT_ECHO_RETURNS) != before + (arm_disc ? 1 : 0)) {
		printf("     echo-returns moved by the wrong amount\n");
		bad = 1;
	}
	if (read_state(&k, &st)) {
		unsigned long long want_pkts = arm_disc ? 1 : 0;

		if (st.echo_rx_pkts != want_pkts) {
			printf("     echo_rx_pkts is %llu, want %llu\n",
			       (unsigned long long)st.echo_rx_pkts, want_pkts);
			bad = 1;
		}
		if (arm_disc && st.echo_last_nonce != nonce) {
			printf("     echo_last_nonce is %08x, want %08x\n",
			       st.echo_last_nonce, nonce);
			bad = 1;
		}
		if (arm_disc && !st.echo_last_seen_ns) {
			printf("     echo_last_seen_ns was not stamped\n");
			bad = 1;
		}
	} else {
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s %s\n", name, verdict_str(want_v));
	}

	if (arm_disc)
		bpf_map_delete_elem(echo_disc_fd, &disc);
	map_reset_v6();
}

static void run_echo_v6_matrix(void)
{
	/* our own echo returning: 254 and self-addressed, consumed */
	case_echo_v6_return(1, XDP_DROP, "echo-v6-returns");
	/* same frame, a discriminator we never sent: not ours, hands off */
	case_echo_v6_return(0, XDP_PASS, "echo-v6-return-unknown-disc");
	/* 254 but not self-addressed: the exception requires both, so the
	 * parser's GTSM rejects it before the echo path runs */
	case_echo_v6("echo-v6-254-not-self-rejected", 254, "fd00::2", "fd00::1",
		     1, XDP_DROP, BFD_STAT_REJECTED);
	/* off-link echo: same parser GTSM, same disposition */
	case_echo_v6("echo-v6-off-link-rejected", 200, "fd00::2", "fd00::2",
		     1, XDP_DROP, BFD_STAT_REJECTED);
	/* not self-addressed at 255 */
	case_echo_v6("echo-v6-not-self", 255, "fd00::2", "fd00::1",
		     1, XDP_PASS, BFD_STAT_NOT_SELF);
	/* self-addressed but the peer is not echo-active: no amplifier */
	case_echo_v6("echo-v6-declined", 255, "fd00::2", "fd00::2",
		     0, XDP_PASS, BFD_STAT_DECLINED);
	/* self-addressed and echo-active: reflected. Guards the reflect path
	 * against being swallowed by the return branch above it. */
	case_echo_v6("echo-v6-reflect", 255, "fd00::2", "fd00::2",
		     1, XDP_TX, BFD_STAT_REFLECTED);
}
