// SPDX-License-Identifier: GPL-2.0
/* Part of the xdp_run test, split by subject.
 * Compiled as one unit via tests/unit/xdp_run.c, which carries the
 * includes, the shared globals and main; include order there is the
 * dependency order (harness first, sweep last). */

static uint16_t csum16(const void *p, int len, uint32_t seed)
{
	const uint16_t *w = p;
	uint32_t sum = seed;

	for (; len > 1; len -= 2)
		sum += *w++;
	if (len == 1)
		sum += *(const uint8_t *)w;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* A single-hop IPv4 BFD control packet. ttl is a parameter because GTSM is
 * the first thing worth asserting and the whole point is to vary it. */
static void build_v4(struct frame *f, uint8_t ttl, uint16_t dport,
		     const struct bfd_ctrl_pkt *bfd, unsigned int extra)
/* frag_off is set by the caller after building, see case_frag */
{
	static const unsigned char dmac[6] = { 0x02, 0, 0, 0, 0, 1 };
	static const unsigned char smac[6] = { 0x02, 0, 0, 0, 0, 2 };
	unsigned int payload = sizeof(*bfd) + extra;

	memset(f, 0, sizeof(*f));

	struct ethhdr *eth = (void *)f->b;
	memcpy(eth->h_dest, dmac, 6);
	memcpy(eth->h_source, smac, 6);
	eth->h_proto = htons(ETH_P_IP);

	struct iphdr *ip = (void *)(eth + 1);
	ip->version = 4;
	ip->ihl     = 5;
	ip->tot_len = htons(sizeof(*ip) + sizeof(struct udphdr) + payload);
	ip->ttl     = ttl;
	ip->protocol = IPPROTO_UDP;
	ip->saddr   = inet_addr("10.0.0.2");
	ip->daddr   = inet_addr("10.0.0.1");
	ip->check   = csum16(ip, sizeof(*ip), 0);

	struct udphdr *udp = (void *)(ip + 1);
	udp->source = htons(49152);
	udp->dest   = htons(dport);
	udp->len    = htons(sizeof(*udp) + payload);
	udp->check  = 0;   /* v4 UDP checksum is optional */

	memcpy(udp + 1, bfd, sizeof(*bfd));

	f->len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + payload;
}

/* A well-formed Up control packet. Cases mutate the copy they get. */
static struct bfd_ctrl_pkt ctrl_up(void)
{
	struct bfd_ctrl_pkt p = {0};

	p.vers_diag   = 1 << 5;
	p.flags       = ST_UP << 6;
	p.detect_mult = 3;
	p.len         = 24;
	p.my_disc     = htonl(0x11111111);
	p.your_disc   = htonl(0x22222222);
	p.min_tx      = htonl(10000);
	p.min_rx      = htonl(10000);
	p.min_echo_rx = 0;
	return p;
}

/* A single-hop IPv6 BFD control packet. */
/* A v6 frame with exactly one extension header (8 bytes, hdrlen 0) between
 * the IPv6 header and UDP. `ext` is the ip6 next-header (e.g. HOPOPTS),
 * `inner` is the extension header's own next-header. */
static void build_v6_exthdr(struct frame *f, uint8_t ext, uint8_t inner,
			    uint16_t dport, const struct bfd_ctrl_pkt *bfd)
{
	static const unsigned char dmac[6] = { 0x02, 0, 0, 0, 0, 1 };
	static const unsigned char smac[6] = { 0x02, 0, 0, 0, 0, 2 };

	memset(f, 0, sizeof(*f));

	struct ethhdr *eth = (void *)f->b;
	memcpy(eth->h_dest, dmac, 6);
	memcpy(eth->h_source, smac, 6);
	eth->h_proto = htons(ETH_P_IPV6);

	struct ipv6hdr *ip6 = (void *)(eth + 1);
	ip6->version     = 6;
	ip6->payload_len = htons(8 + sizeof(struct udphdr) + sizeof(*bfd));
	ip6->nexthdr     = ext;
	ip6->hop_limit   = 255;
	inet_pton(AF_INET6, "fd00::2", &ip6->saddr);
	inet_pton(AF_INET6, "fd00::1", &ip6->daddr);

	unsigned char *xh = (void *)(ip6 + 1);   /* 8-byte extension header */
	xh[0] = inner;   /* next header */
	xh[1] = 0;       /* hdrlen: (0 + 1) * 8 = 8 bytes */

	struct udphdr *udp = (void *)(xh + 8);
	udp->source = htons(49152);
	udp->dest   = htons(dport);
	udp->len    = htons(sizeof(*udp) + sizeof(*bfd));
	udp->check  = 0xffff;

	memcpy(udp + 1, bfd, sizeof(*bfd));

	f->len = sizeof(*eth) + sizeof(*ip6) + 8 + sizeof(*udp) + sizeof(*bfd);
}

static void build_v6(struct frame *f, uint8_t hlim, uint16_t dport,
		     const struct bfd_ctrl_pkt *bfd, unsigned int extra)
{
	static const unsigned char dmac[6] = { 0x02, 0, 0, 0, 0, 1 };
	static const unsigned char smac[6] = { 0x02, 0, 0, 0, 0, 2 };
	unsigned int payload = sizeof(*bfd) + extra;

	memset(f, 0, sizeof(*f));

	struct ethhdr *eth = (void *)f->b;
	memcpy(eth->h_dest, dmac, 6);
	memcpy(eth->h_source, smac, 6);
	eth->h_proto = htons(ETH_P_IPV6);

	struct ipv6hdr *ip6 = (void *)(eth + 1);
	ip6->version     = 6;
	ip6->payload_len = htons(sizeof(struct udphdr) + payload);
	ip6->nexthdr     = IPPROTO_UDP;
	ip6->hop_limit   = hlim;
	inet_pton(AF_INET6, "fd00::2", &ip6->saddr);
	inet_pton(AF_INET6, "fd00::1", &ip6->daddr);

	struct udphdr *udp = (void *)(ip6 + 1);
	udp->source = htons(49152);
	udp->dest   = htons(dport);
	udp->len    = htons(sizeof(*udp) + payload);
	udp->check  = 0xffff;   /* v6 requires one; the program rewrites it */

	memcpy(udp + 1, bfd, sizeof(*bfd));

	f->len = sizeof(*eth) + sizeof(*ip6) + sizeof(*udp) + payload;
}

/* Verify rather than recompute. Summing the pseudo-header, the UDP header
 * with its checksum field in place, and the payload must fold to 0xffff.
 * That property is independent of how tx.h produced the value, which is
 * the point: reimplementing the same 34-word fold here would only prove
 * the test agrees with itself. */
static int v6_udp_csum_ok(const unsigned char *frm, unsigned int len)
{
	const struct ethhdr *eth = (const void *)frm;
	const struct ipv6hdr *ip6 = (const void *)(eth + 1);
	const struct udphdr *udp = (const void *)(ip6 + 1);
	unsigned int ulen = ntohs(udp->len);
	uint32_t sum = 0;

	if (len < sizeof(*eth) + sizeof(*ip6) + ulen)
		return 0;

	const uint16_t *w = (const uint16_t *)&ip6->saddr;
	for (int i = 0; i < 16; i++)
		sum += w[i];
	sum += udp->len;
	sum += htons(IPPROTO_UDP);

	w = (const uint16_t *)udp;
	for (unsigned int i = 0; i < ulen / 2; i++)
		sum += w[i];
	if (ulen & 1)
		sum += ((const unsigned char *)udp)[ulen - 1];

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum == 0xffff;
}

/* ---------- running ---------- */

static const char *verdict_str(int v)
{
	switch (v) {
	case XDP_ABORTED:  return "ABORTED";
	case XDP_DROP:     return "DROP";
	case XDP_PASS:     return "PASS";
	case XDP_TX:       return "TX";
	case XDP_REDIRECT: return "REDIRECT";
	default:           return "?";
	}
}

/* Returns the verdict, or -1 if the syscall itself failed. out/out_len
 * receive the returned frame when out is non-NULL. */
static int run_frame(const struct frame *f, unsigned char *out,
		     unsigned int *out_len)
{
	unsigned char buf[FRAME_MAX * 2] = {0};
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .data_in    = f->b,
		    .data_size_in = f->len,
		    .data_out   = buf,
		    .data_size_out = sizeof(buf),
		    .repeat     = 1);

	if (bpf_prog_test_run_opts(prog_fd, &topts)) {
		fprintf(stderr, "  test_run failed: %s\n", strerror(errno));
		return -1;
	}
	if (out) {
		unsigned int n = topts.data_size_out;

		if (n > FRAME_MAX)
			n = FRAME_MAX;
		memcpy(out, buf, n);
		*out_len = n;
	}
	return topts.retval;
}

static void expect(const char *name, int got, int want)
{
	if (got == want) {
		printf("ok   %-40s %s\n", name, verdict_str(want));
		return;
	}
	printf("FAIL %-40s want %s got %s\n", name, verdict_str(want),
	       got < 0 ? "syscall-error" : verdict_str(got));
	fails++;
}

/* ---------- map state ---------- */

/* The sweep lives behind a bpf_timer, which does not fire under
 * test_run, so tests/unit/bfd_xdp_test.o carries a second program that
 * drives the same callback through the same helper at a time we choose.
 * Separate object on purpose: no test entry point in shipped bytecode. */

/* Keys are built from the arriving frame's point of view: peer is the
 * source, local is the destination. Getting this backwards produces a
 * silent XDP_PASS rather than an error, so it is worth stating. */
static struct session_key key_v4(const char *peer, const char *local)
{
	struct session_key k = {0};
	__u32 p = inet_addr(peer), l = inet_addr(local);

	k.peer.b[10] = 0xff;  k.peer.b[11] = 0xff;
	k.local.b[10] = 0xff; k.local.b[11] = 0xff;
	memcpy(&k.peer.b[12], &p, 4);
	memcpy(&k.local.b[12], &l, 4);
	return k;
}

/* prog_flags carries two independent bits and they are NOT the same bit:
 * value 1 is the promiscuous PASS in bfd_xdp.c, value 2 is the multihop
 * deferral parse.h reads. The comment in bfd_xdp.c calls the latter
 * "bit 1", meaning index 1, which reads as the same bit as the & 1
 * below it. Nothing here opened this map before, so every earlier case
 * ran at whatever the object's default was; map_reset now clears it. */

static void set_flags(__u32 v)
{
	__u32 zero = 0;

	if (flags_fd < 0) {
		fprintf(stderr, "  no prog_flags fd\n");
		fails++;
		return;
	}
	if (bpf_map_update_elem(flags_fd, &zero, &v, BPF_ANY)) {
		fprintf(stderr, "  prog_flags update failed: %s\n",
		        strerror(errno));
		fails++;
	}
}

static void map_reset(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");

	bpf_map_delete_elem(cfg_fd, &k);
	bpf_map_delete_elem(sess_fd, &k);
	set_flags(0);
}

/* A session the kernel is allowed to answer for. */
static void arm_session(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg = {0};
	struct session_state st = {0};

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = 255;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* arm_session with a chosen min_rx_us, and alive already set.
 * alive matters: the XDP rule's first disjunct is !st->alive, so a
 * session left at alive 0 takes the candidate on every packet and
 * every decrease vector would pass without the rule running. */
static void arm_session_rx(__u32 min_rx_us)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg = {0};
	struct session_state st = {0};

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = min_rx_us;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = 255;

	st.remote_state = ST_UP;
	st.alive        = 1;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  detect map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* Same as arm_session but with a caller-chosen min_ttl. ktx_mirror
 * pushes min_ttl for EVERY session it mirrors - ktx.c never consults
 * is_mhop - so a sub-255 value does reach tx_config and the deferred
 * GTSM branch is live, not dead code. */
static void arm_session_ttl(__u32 min_ttl)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg = {0};
	struct session_state st = {0};

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = min_ttl;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  mhop map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* v6 keys carry the address as-is; only v4 goes through the mapped
 * encoder. Same orientation: peer is the frame source. */
static struct session_key key_v6(const char *peer, const char *local)
{
	struct session_key k = {0};

	inet_pton(AF_INET6, peer, k.peer.b);
	inet_pton(AF_INET6, local, k.local.b);
	return k;
}

static void map_reset_v6(void)
{
	struct session_key k = key_v6("fd00::2", "fd00::1");

	bpf_map_delete_elem(cfg_fd, &k);
	bpf_map_delete_elem(sess_fd, &k);
	set_flags(0);
}

static void arm_session_v6(void)
{
	struct session_key k = key_v6("fd00::2", "fd00::1");
	struct tx_cfg cfg = {0};
	struct session_state st = {0};

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = 255;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  v6 map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* v6 counterpart of arm_session_ttl. */
static void arm_session_v6_ttl(__u32 min_ttl)
{
	struct session_key k = key_v6("fd00::2", "fd00::1");
	struct tx_cfg cfg = {0};
	struct session_state st = {0};

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = min_ttl;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  v6 mhop map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* Read a session's kernel-owned state back after a run. Everything above
 * asserts on the returned frame; the map side is the other half of what
 * the program does, and nothing has checked it yet. */
static int read_state(const struct session_key *k, struct session_state *out)
{
	if (bpf_map_lookup_elem(sess_fd, k, out)) {
		printf("     no session_state for that key: %s\n", strerror(errno));
		return 0;
	}
	return 1;
}

/* bfd_stats is a per-CPU array of __u64; sum the slots the way
 * stats_dump does. This is what makes the malformed cases real
 * assertions: those return XDP_PASS, which an unmatched packet
 * also returns, so the verdict alone would still pass if the
 * header check were deleted. The counter is the witness. */
static unsigned long long stat_get(int slot)
{
	static int ncpu;
	__u32 k = slot;

	if (!ncpu)
		ncpu = libbpf_num_possible_cpus();
	if (stats_fd < 0 || ncpu <= 0)
		return 0;

	__u64 *vals = calloc(ncpu, sizeof(__u64));
	unsigned long long total = 0;

	if (!vals)
		return 0;
	if (!bpf_map_lookup_elem(stats_fd, &k, vals))
		for (int i = 0; i < ncpu; i++)
			total += vals[i];
	free(vals);
	return total;
}

/* Run one sweep pass at a chosen nanosecond time. The frame is nothing
 * but that timestamp. */
static int sweep_at(unsigned long long now_ns)
{
	unsigned char in[sizeof(struct ethhdr) + sizeof(__u64)] = {0};
	__u64 t = now_ns;
	unsigned char out[64] = {0};

	memcpy(in + sizeof(struct ethhdr), &t, sizeof(t));

	LIBBPF_OPTS(bpf_test_run_opts, topts,
		    .data_in = in, .data_size_in = sizeof(in),
		    .data_out = out, .data_size_out = sizeof(out),
		    .repeat = 1);

	if (bpf_prog_test_run_opts(sweep_prog_fd, &topts)) {
		printf("     sweep test_run failed: %s\n", strerror(errno));
		return 0;
	}
	return 1;
}

/* The sweep object has its own maps, so state for these cases goes there
 * rather than into the ones the packet cases use. */
static int sweep_put(const struct session_key *k,
		     const struct session_state *st, const struct tx_cfg *cfg)
{
	if (bpf_map_update_elem(sweep_sess_fd, k, st, BPF_ANY)) {
		printf("     sweep session put failed: %s\n", strerror(errno));
		return 0;
	}
	if (cfg && bpf_map_update_elem(sweep_cfg_fd, k, cfg, BPF_ANY)) {
		printf("     sweep cfg put failed: %s\n", strerror(errno));
		return 0;
	}
	return 1;
}

/* ---------- poll-aware detect basis ---------- */

/* The kernel half of detect_vectors.h. fsm_run drives the same vectors
 * against fsm.c; this drives bfd_xdp.c. The rule exists twice and
 * nothing checked that the two agree until these two drivers.
 *
 * The gap is synthesised by writing last_seen_ns before each run, since
 * the program reads bpf_ktime_get_ns() itself and the harness cannot
 * hand it a clock. Base is CLOCK_MONOTONIC, which is what that helper
 * returns. Cases flagged boundary sit exactly on the comparison and are
 * skipped here: skew between our clock read and the program's would
 * decide them. fsm_run takes those, where the clock is an argument.
 *
 * LOCAL_MIN_RX_US is 10000, the same value arm_session uses, so the
 * cfg-present and cfg-absent floors coincide unless a case says
 * otherwise. */
static __u64 mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ull + (__u64)ts.tv_nsec;
}

/* The rejection paths.
 *
 * Everything else about authentication is checked by watching a session
 * stay up, which only ever exercises the accept path. These are the
 * cases the feature exists for: a forged digest, a replayed sequence, a
 * key id that is not ours. Each has to be refused, and refused without
 * touching the session - an accepted forgery that merely fails later is
 * still a forgery that refreshed liveness.
 *
 * Built as a real keyed-SHA1 packet and then damaged, so every case
 * differs from a packet that would have been accepted by exactly the
 * thing under test.
 */
/* The local detect multiplier the next armed session gets. The replay
 * window is sized from the packet's Detect Mult, so a case sets this
 * apart from the packet's value to prove which of the two is used. */

/* A second key left in the accept set, as a rollover leaves the key the
 * peer has not stopped using yet. Zero id means only one key. */

static void arm_session_auth(__u8 type, __u8 keyid, const char *key)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg = {0};
	struct session_state st = {0};
	unsigned n = (unsigned)strlen(key);

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = 255;
	cfg.auth_type = type;
	cfg.auth_present = 1;
	cfg.auth_keyid = keyid;
	cfg.auth_keylen = (__u8)n;
	memcpy(cfg.auth_kpad, key, n);

	/* What the engine leaves for the receive side: every key a packet
	 * may currently be signed with. One here, unless a case says
	 * otherwise. */
	cfg.auth_nkeys = 1;
	cfg.auth_accept[0].type = type;
	cfg.auth_accept[0].key_id = keyid;
	cfg.auth_accept[0].keylen = (__u8)n;
	memcpy(cfg.auth_accept[0].kpad, key, n);

	if (arm_extra_keyid) {
		unsigned m = (unsigned)strlen(arm_extra_key);

		cfg.auth_nkeys = 2;
		cfg.auth_accept[1].type = type;
		cfg.auth_accept[1].key_id = arm_extra_keyid;
		cfg.auth_accept[1].keylen = (__u8)m;
		memcpy(cfg.auth_accept[1].kpad, arm_extra_key, m);
	}

	st.remote_state = ST_UP;
	st.detect_mult  = arm_local_mult;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  auth map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* A keyed-SHA1 packet signed with `key`, sequence `seq`. */
static void build_sha1_auth(struct frame *f, const char *key, __u8 keyid,
			    __u32 seq, __u8 type)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	__u8 pkt[BFD_MAX_LEN] = {0};
	__u8 kpad[SHA1_BLOCK_LEN] = {0};

	p.flags |= BFD_F_AUTH;
	p.len = BFD_MIN_LEN + BFD_AUTH_SHA1_LEN;
	memcpy(pkt, &p, BFD_MIN_LEN);
	memcpy(kpad, key, strlen(key));
	bfd_auth_build(pkt, type, keyid, (const __u8 *)key,
		       (__u8)strlen(key), kpad, seq);

	/* build_v4 lays down the 24-byte header and reserves the rest of
	 * the payload; the signed section goes in behind it. */
	build_v4(f, 255, BFD_PORT_1HOP, (const struct bfd_ctrl_pkt *)pkt,
		 BFD_AUTH_SHA1_LEN);
	memcpy(f->b + sizeof(struct ethhdr) + sizeof(struct iphdr) +
	       sizeof(struct udphdr) + BFD_MIN_LEN,
	       pkt + BFD_MIN_LEN, BFD_AUTH_SHA1_LEN);
}
