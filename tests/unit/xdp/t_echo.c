// SPDX-License-Identifier: GPL-2.0
/* Part of xdp_run.c. */

/* The TTL 254 exception must also require self-addressing, or it is a TTL bypass. */
static void build_echo(struct frame *f, uint8_t ttl, const char *src, const char *dst,
		       uint32_t my_disc, uint32_t nonce)
{
	struct bfd_ctrl_pkt p = ctrl_up();

	p.my_disc = htonl(my_disc);
	p.min_echo_rx = htonl(nonce);
	build_v4(f, ttl, BFD_ECHO_PORT, &p, 0);

	struct iphdr *ip = (void *)(f->b + sizeof(struct ethhdr));

	ip->saddr = inet_addr(src);
	ip->daddr = inet_addr(dst);
	ip->check = 0;
	ip->check = csum16(ip, sizeof(*ip), 0);
}

static void case_echo(const char *name, uint8_t ttl, const char *src, const char *dst,
		      int arm_peer, int arm_disc, int want_v, int slot)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_addr peer = { 0 };
	unsigned long long before;
	struct frame f;
	int v, bad = 0;
	struct echo_peer ep = { .max = 64 };
	__u32 disc = 0x33333333;

	map_reset();
	arm_session();

	if (arm_peer) {
		__u32 a = inet_addr(src);

		peer.b[10] = 0xff;
		peer.b[11] = 0xff;
		memcpy(&peer.b[12], &a, 4);
		bpf_map_update_elem(echo_peers_fd, &peer, &ep, BPF_ANY);
	}
	if (arm_disc)
		bpf_map_update_elem(echo_disc_fd, &disc, &k, BPF_ANY);

	build_echo(&f, ttl, src, dst, disc, 0xa5a5a5a5);

	before = stat_get(slot);
	v = run_frame(&f, NULL, NULL);

	if (v != want_v) {
		printf("     verdict %s, want %s\n", v < 0 ? "syscall-error" : verdict_str(v),
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

/* RFC 5880 s6.8.9: past the peer's budget the reflector drops, so a forger
 * spoofing a known peer cannot fill the transmit ring.
 */
static void case_echo_budget(void)
{
	struct echo_peer ep = { .max = 24 };
	struct bfd_addr peer = { 0 };
	__u32 a = inet_addr("10.0.0.2");
	unsigned long long before = stat_get(BFD_STAT_ECHO_RATELIMITED);
	int tx = 0, drop = 0, bad = 0;
	struct frame f;

	map_reset();
	arm_session();
	peer.b[10] = peer.b[11] = 0xff;
	memcpy(&peer.b[12], &a, 4);
	bpf_map_update_elem(echo_peers_fd, &peer, &ep, BPF_ANY);
	build_echo(&f, 255, "10.0.0.2", "10.0.0.2", 0x44444444, 1);
	for (int i = 0; i < 100; i++) {
		int v = run_frame(&f, NULL, NULL);

		tx += v == XDP_TX;
		drop += v == XDP_DROP;
	}
	if (tx != 24 || drop != 76) {
		printf("     %d reflected, %d dropped; want 24 and 76\n", tx, drop);
		bad = 1;
	}
	if (stat_get(BFD_STAT_ECHO_RATELIMITED) != before + 76) {
		printf("     echo-ratelimited +%llu, want +76\n",
		       stat_get(BFD_STAT_ECHO_RATELIMITED) - before);
		bad = 1;
	}
	usleep(110000);
	if (run_frame(&f, NULL, NULL) != XDP_TX) {
		printf("     the next window was not reflected\n");
		bad = 1;
	}
	bpf_map_delete_elem(echo_peers_fd, &peer);
	map_reset();
	if (bad) {
		printf("FAIL %-40s\n", "echo-budget");
		fails++;
	} else {
		printf("ok   %-40s 24 of 100, then the next window\n", "echo-budget");
	}
}

static void run_echo_matrix(void)
{
	case_echo_budget();
	/* our own echo returning: 254 and self-addressed, consumed */
	case_echo("echo-returns", 254, "10.0.0.1", "10.0.0.1", 0, 1, XDP_DROP,
		  BFD_STAT_ECHO_RETURNS);
	/* The parser's GTSM rejects it. */
	case_echo("echo-254-not-self-rejected", 254, "10.0.0.2", "10.0.0.1", 1, 0, XDP_DROP,
		  BFD_STAT_REJECTED);
	/* The parser's GTSM; echo.h's ECHO_TTL check is never reached. */
	case_echo("echo-off-link-rejected", 200, "10.0.0.2", "10.0.0.2", 1, 0, XDP_DROP,
		  BFD_STAT_REJECTED);
	/* not self-addressed at 255 */
	case_echo("echo-not-self", 255, "10.0.0.2", "10.0.0.1", 1, 0, XDP_PASS, BFD_STAT_NOT_SELF);
	/* self-addressed but the peer is not echo-active: no amplifier */
	case_echo("echo-declined", 255, "10.0.0.2", "10.0.0.2", 0, 0, XDP_PASS, BFD_STAT_DECLINED);
	/* self-addressed and echo-active: reflected */
	case_echo("echo-reflect", 255, "10.0.0.2", "10.0.0.2", 1, 0, XDP_TX, BFD_STAT_REFLECTED);
}

/* As the v4 matrix. */
static void build_echo_v6(struct frame *f, uint8_t hlim, const char *src, const char *dst,
			  uint32_t my_disc, uint32_t nonce)
{
	struct bfd_ctrl_pkt p = ctrl_up();

	p.my_disc = htonl(my_disc);
	p.min_echo_rx = htonl(nonce);
	build_v6(f, hlim, BFD_ECHO_PORT, &p, 0);

	struct ipv6hdr *ip6 = (void *)(f->b + sizeof(struct ethhdr));

	inet_pton(AF_INET6, src, &ip6->saddr);
	inet_pton(AF_INET6, dst, &ip6->daddr);
}

static void case_echo_v6(const char *name, uint8_t hlim, const char *src, const char *dst,
			 int arm_peer, int want_v, int slot)
{
	struct bfd_addr peer = { 0 };
	unsigned long long before;
	struct frame f;
	int v, bad = 0;
	struct echo_peer ep = { .max = 64 };

	map_reset_v6();
	arm_session_v6();

	if (arm_peer) {
		inet_pton(AF_INET6, src, peer.b);
		bpf_map_update_elem(echo_peers_fd, &peer, &ep, BPF_ANY);
	}

	build_echo_v6(&f, hlim, src, dst, 0x33333333, 0xa5a5a5a5);

	before = stat_get(slot);
	v = run_frame(&f, NULL, NULL);

	if (v != want_v) {
		printf("     verdict %s, want %s\n", v < 0 ? "syscall-error" : verdict_str(v),
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

/* bfdd's v6 echo, sent to our address: it must come back to the sender. */
static void case_echo_v6_to_us(void)
{
	const char *name = "echo-v6-to-us-returned-to-sender";
	struct bfd_addr peer = { 0 };
	struct echo_peer ep = { .max = 64 };
	unsigned char out[FRAME_MAX];
	unsigned int out_len = 0;
	struct in6_addr src, dst;
	struct frame f;
	int v, bad = 0;

	map_reset_v6();
	arm_session_v6();
	inet_pton(AF_INET6, "fd00::2", peer.b);
	bpf_map_update_elem(echo_peers_fd, &peer, &ep, BPF_ANY);

	build_echo_v6(&f, 255, "fd00::2", "fd00::1", 0x33333333, 0xa5a5a5a5);
	v = run_frame(&f, out, &out_len);

	struct ethhdr *ein = (void *)f.b, *eout = (void *)out;
	struct ipv6hdr *ip6 = (void *)(out + sizeof(struct ethhdr));

	inet_pton(AF_INET6, "fd00::1", &src);
	inet_pton(AF_INET6, "fd00::2", &dst);
	if (v != XDP_TX) {
		printf("     verdict %s, want XDP_TX\n", v < 0 ? "syscall-error" : verdict_str(v));
		bad = 1;
	} else if (out_len < sizeof(struct ethhdr) + sizeof(*ip6) ||
		   memcmp(&ip6->saddr, &src, 16) || memcmp(&ip6->daddr, &dst, 16)) {
		printf("     not addressed back to the sender\n");
		bad = 1;
	} else if (ip6->hop_limit != 254) {
		printf("     hop limit %u, want 254\n", ip6->hop_limit);
		bad = 1;
	} else if (memcmp(eout->h_dest, ein->h_source, 6) ||
		   memcmp(eout->h_source, ein->h_dest, 6)) {
		printf("     MACs not swapped\n");
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s %s\n", name, verdict_str(XDP_TX));
	}

	bpf_map_delete_elem(echo_peers_fd, &peer);
	map_reset_v6();
}

/* Consumed with a known discriminator, passed with an unknown one. */
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
		printf("     verdict %s, want %s\n", v < 0 ? "syscall-error" : verdict_str(v),
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
			printf("     echo_last_nonce is %08x, want %08x\n", st.echo_last_nonce,
			       nonce);
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
	/* The exception requires both. */
	case_echo_v6("echo-v6-254-not-self-rejected", 254, "fd00::2", "fd00::1", 1, XDP_DROP,
		     BFD_STAT_REJECTED);
	/* off-link echo: same parser GTSM, same disposition */
	case_echo_v6("echo-v6-off-link-rejected", 200, "fd00::2", "fd00::2", 1, XDP_DROP,
		     BFD_STAT_REJECTED);
	/* sent to us for a session we hold, as bfdd does: returned */
	case_echo_v6("echo-v6-to-us", 255, "fd00::2", "fd00::1", 1, XDP_TX, BFD_STAT_REFLECTED);
	case_echo_v6_to_us();
	/* sent to us, but no session holds that pair */
	case_echo_v6("echo-v6-not-self", 255, "fd00::3", "fd00::1", 1, XDP_PASS, BFD_STAT_NOT_SELF);
	/* sent to us for a session whose peer is not echo-active */
	case_echo_v6("echo-v6-to-us-declined", 255, "fd00::2", "fd00::1", 0, XDP_PASS,
		     BFD_STAT_DECLINED);
	/* self-addressed but the peer is not echo-active: no amplifier */
	case_echo_v6("echo-v6-declined", 255, "fd00::2", "fd00::2", 0, XDP_PASS, BFD_STAT_DECLINED);
	/* Not swallowed by the return branch above it. */
	case_echo_v6("echo-v6-reflect", 255, "fd00::2", "fd00::2", 1, XDP_TX, BFD_STAT_REFLECTED);
}
