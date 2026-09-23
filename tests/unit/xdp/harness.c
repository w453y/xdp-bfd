// SPDX-License-Identifier: GPL-2.0
/* Part of xdp_run.c. */

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

/* frag_off is set by the caller; see case_frag. */
static void build_v4(struct frame *f, uint8_t ttl, uint16_t dport, const struct bfd_ctrl_pkt *bfd,
		     unsigned int extra)
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
	ip->ihl = 5;
	ip->tot_len = htons(sizeof(*ip) + sizeof(struct udphdr) + payload);
	ip->ttl = ttl;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = inet_addr("10.0.0.2");
	ip->daddr = inet_addr("10.0.0.1");
	ip->check = csum16(ip, sizeof(*ip), 0);

	struct udphdr *udp = (void *)(ip + 1);

	udp->source = htons(49152);
	udp->dest = htons(dport);
	udp->len = htons(sizeof(*udp) + payload);
	udp->check = 0; /* v4 UDP checksum is optional */

	memcpy(udp + 1, bfd, sizeof(*bfd));

	f->len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + payload;
}

/* A well-formed Up control packet. Cases mutate the copy they get. */
static struct bfd_ctrl_pkt ctrl_up(void)
{
	struct bfd_ctrl_pkt p = { 0 };

	p.vers_diag = 1 << 5;
	p.flags = ST_UP << 6;
	p.detect_mult = 3;
	p.len = 24;
	p.my_disc = htonl(0x11111111);
	p.your_disc = htonl(0x22222222);
	p.min_tx = htonl(10000);
	p.min_rx = htonl(10000);
	p.min_echo_rx = 0;
	return p;
}

/* One 8-byte extension header between IPv6 and UDP. ext is the IPv6 next
 * header, inner the extension's.
 */
static void build_v6_exthdr(struct frame *f, uint8_t ext, uint8_t inner, uint16_t dport,
			    const struct bfd_ctrl_pkt *bfd)
{
	static const unsigned char dmac[6] = { 0x02, 0, 0, 0, 0, 1 };
	static const unsigned char smac[6] = { 0x02, 0, 0, 0, 0, 2 };

	memset(f, 0, sizeof(*f));

	struct ethhdr *eth = (void *)f->b;

	memcpy(eth->h_dest, dmac, 6);
	memcpy(eth->h_source, smac, 6);
	eth->h_proto = htons(ETH_P_IPV6);

	struct ipv6hdr *ip6 = (void *)(eth + 1);

	ip6->version = 6;
	ip6->payload_len = htons(8 + sizeof(struct udphdr) + sizeof(*bfd));
	ip6->nexthdr = ext;
	ip6->hop_limit = 255;
	inet_pton(AF_INET6, "fd00::2", &ip6->saddr);
	inet_pton(AF_INET6, "fd00::1", &ip6->daddr);

	unsigned char *xh = (void *)(ip6 + 1); /* 8-byte extension header */

	xh[0] = inner; /* next header */
	xh[1] = 0;     /* hdrlen: (0 + 1) * 8 = 8 bytes */

	struct udphdr *udp = (void *)(xh + 8);

	udp->source = htons(49152);
	udp->dest = htons(dport);
	udp->len = htons(sizeof(*udp) + sizeof(*bfd));
	udp->check = 0xffff;

	memcpy(udp + 1, bfd, sizeof(*bfd));

	f->len = sizeof(*eth) + sizeof(*ip6) + 8 + sizeof(*udp) + sizeof(*bfd);
}

/* An IPv6 BFD control packet with a chosen hop limit. */
static void build_v6(struct frame *f, uint8_t hlim, uint16_t dport, const struct bfd_ctrl_pkt *bfd,
		     unsigned int extra)
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

	ip6->version = 6;
	ip6->payload_len = htons(sizeof(struct udphdr) + payload);
	ip6->nexthdr = IPPROTO_UDP;
	ip6->hop_limit = hlim;
	inet_pton(AF_INET6, "fd00::2", &ip6->saddr);
	inet_pton(AF_INET6, "fd00::1", &ip6->daddr);

	struct udphdr *udp = (void *)(ip6 + 1);

	udp->source = htons(49152);
	udp->dest = htons(dport);
	udp->len = htons(sizeof(*udp) + payload);
	udp->check = 0xffff; /* v6 requires one; the program rewrites it */

	memcpy(udp + 1, bfd, sizeof(*bfd));

	f->len = sizeof(*eth) + sizeof(*ip6) + sizeof(*udp) + payload;
}

/* The pseudo-header, UDP header and payload must fold to 0xffff. */
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


static const char *verdict_str(int v)
{
	switch (v) {
	case XDP_ABORTED:
		return "ABORTED";
	case XDP_DROP:
		return "DROP";
	case XDP_PASS:
		return "PASS";
	case XDP_TX:
		return "TX";
	case XDP_REDIRECT:
		return "REDIRECT";
	default:
		return "?";
	}
}

/* -1 if the syscall failed. out receives the returned frame if non-NULL. */
static int run_frame(const struct frame *f, unsigned char *out, unsigned int *out_len)
{
	unsigned char buf[FRAME_MAX * 2] = { 0 };

	LIBBPF_OPTS(bpf_test_run_opts, topts, .data_in = f->b, .data_size_in = f->len,
		    .data_out = buf, .data_size_out = sizeof(buf), .repeat = 1);

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


/* Peer is the frame's source. Backwards gives a silent XDP_PASS. */
static struct session_key key_v4(const char *peer, const char *local)
{
	struct session_key k = { 0 };
	__u32 p = inet_addr(peer), l = inet_addr(local);

	k.peer.b[10] = 0xff;
	k.peer.b[11] = 0xff;
	k.local.b[10] = 0xff;
	k.local.b[11] = 0xff;
	memcpy(&k.peer.b[12], &p, 4);
	memcpy(&k.local.b[12], &l, 4);
	return k;
}

/* FLAG_PROMISC, FLAG_MHOP; map_reset clears them. */

static void set_flags(__u32 v)
{
	__u32 zero = 0;

	if (flags_fd < 0) {
		fprintf(stderr, "  no prog_flags fd\n");
		fails++;
		return;
	}
	if (bpf_map_update_elem(flags_fd, &zero, &v, BPF_ANY)) {
		fprintf(stderr, "  prog_flags update failed: %s\n", strerror(errno));
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
	struct tx_cfg cfg = { 0 };
	struct session_state st = { 0 };

	cfg.enable = 1;
	cfg.my_disc = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state = ST_UP;
	cfg.mult = 3;
	cfg.min_ttl = 255;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* With alive 0 every packet takes the candidate and the decrease rule never runs. */
static void arm_session_rx(__u32 min_rx_us)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg = { 0 };
	struct session_state st = { 0 };

	cfg.enable = 1;
	cfg.my_disc = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = min_rx_us;
	cfg.state = ST_UP;
	cfg.mult = 3;
	cfg.min_ttl = 255;

	st.remote_state = ST_UP;
	st.alive = 1;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  detect map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* ktx_mirror pushes min_ttl for every session, so the deferred GTSM branch is live. */
static void arm_session_ttl(__u32 min_ttl)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg = { 0 };
	struct session_state st = { 0 };

	cfg.enable = 1;
	cfg.my_disc = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state = ST_UP;
	cfg.mult = 3;
	cfg.min_ttl = min_ttl;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  mhop map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* v6 keys are the address as is. */
static struct session_key key_v6(const char *peer, const char *local)
{
	struct session_key k = { 0 };

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
	struct tx_cfg cfg = { 0 };
	struct session_state st = { 0 };

	cfg.enable = 1;
	cfg.my_disc = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state = ST_UP;
	cfg.mult = 3;
	cfg.min_ttl = 255;

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
	struct tx_cfg cfg = { 0 };
	struct session_state st = { 0 };

	cfg.enable = 1;
	cfg.my_disc = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state = ST_UP;
	cfg.mult = 3;
	cfg.min_ttl = min_ttl;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  v6 mhop map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* Read a session's kernel-owned state back after a run. */
static int read_state(const struct session_key *k, struct session_state *out)
{
	if (bpf_map_lookup_elem(sess_fd, k, out)) {
		printf("     no session_state for that key: %s\n", strerror(errno));
		return 0;
	}
	return 1;
}

/* Across CPUs; the witness where the verdict cannot tell rejections apart. */
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

/* bpf_timer does not fire under test_run, so bfd_xdp_test.o drives the callback. */
static int sweep_at(unsigned long long now_ns)
{
	unsigned char in[sizeof(struct ethhdr) + sizeof(__u64)] = { 0 };
	__u64 t = now_ns;
	unsigned char out[64] = { 0 };

	memcpy(in + sizeof(struct ethhdr), &t, sizeof(t));

	LIBBPF_OPTS(bpf_test_run_opts, topts, .data_in = in, .data_size_in = sizeof(in),
		    .data_out = out, .data_size_out = sizeof(out), .repeat = 1);

	if (bpf_prog_test_run_opts(sweep_prog_fd, &topts)) {
		printf("     sweep test_run failed: %s\n", strerror(errno));
		return 0;
	}
	return 1;
}

/* The sweep object has its own maps. */
static int sweep_put(const struct session_key *k, const struct session_state *st,
		     const struct tx_cfg *cfg)
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


/* CLOCK_MONOTONIC, the clock bpf_ktime_get_ns reads. */
static __u64 mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ull + (__u64)ts.tv_nsec;
}

static void arm_session_auth(__u8 type, __u8 keyid, const char *key)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg = { 0 };
	struct session_state st = { 0 };
	unsigned int n = (unsigned int)strlen(key);

	cfg.enable = 1;
	cfg.my_disc = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state = ST_UP;
	cfg.mult = 3;
	cfg.min_ttl = 255;
	cfg.auth_type = type;
	cfg.auth_present = 1;
	cfg.auth_keyid = keyid;
	cfg.auth_keylen = (__u8)n;
	memcpy(cfg.auth_kpad, key, n);

	/* The accept set: one key, unless the case adds a second. */
	cfg.auth_nkeys = 1;
	cfg.auth_accept[0].type = type;
	cfg.auth_accept[0].key_id = keyid;
	cfg.auth_accept[0].keylen = (__u8)n;
	memcpy(cfg.auth_accept[0].kpad, key, n);

	if (arm_extra_keyid) {
		unsigned int m = (unsigned int)strlen(arm_extra_key);

		cfg.auth_nkeys = 2;
		cfg.auth_accept[1].type = type;
		cfg.auth_accept[1].key_id = arm_extra_keyid;
		cfg.auth_accept[1].keylen = (__u8)m;
		memcpy(cfg.auth_accept[1].kpad, arm_extra_key, m);
	}

	st.remote_state = ST_UP;
	st.detect_mult = arm_local_mult;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		fprintf(stderr, "  auth map update failed: %s\n", strerror(errno));
		fails++;
	}
}

/* A keyed-SHA1 packet signed with `key`, sequence `seq`. */
static void build_sha1_auth(struct frame *f, const char *key, __u8 keyid, __u32 seq, __u8 type)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	__u8 pkt[BFD_MAX_LEN] = { 0 };
	__u8 kpad[SHA1_BLOCK_LEN] = { 0 };

	p.flags |= BFD_F_AUTH;
	p.len = BFD_MIN_LEN + BFD_AUTH_SHA1_LEN;
	memcpy(pkt, &p, BFD_MIN_LEN);
	memcpy(kpad, key, strlen(key));
	bfd_auth_build(pkt, type, keyid, (const __u8 *)key, (__u8)strlen(key), kpad, seq);

	/* The signed section goes in behind the 24-byte header. */
	build_v4(f, 255, BFD_PORT_1HOP, (const struct bfd_ctrl_pkt *)pkt, BFD_AUTH_SHA1_LEN);
	memcpy(f->b + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) +
		       BFD_MIN_LEN,
	       pkt + BFD_MIN_LEN, BFD_AUTH_SHA1_LEN);
}
