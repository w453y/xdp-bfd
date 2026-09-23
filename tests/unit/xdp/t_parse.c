// SPDX-License-Identifier: GPL-2.0
/* Part of xdp_run.c. */

/* Deferred GTSM: below 255 only for a configured session whose min_ttl admits it. */
static void case_deferred_gtsm(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	map_reset();
	set_flags(FLAG_MHOP);
	arm_session_ttl(32);

	build_v4(&f, 64, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-low-ttl-accepted", run_frame(&f, NULL, NULL), XDP_TX);

	build_v4(&f, 32, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-exact-min-accepted", run_frame(&f, NULL, NULL), XDP_TX);

	build_v4(&f, 16, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-below-min-drops", run_frame(&f, NULL, NULL), XDP_DROP);

	/* Deferred by parse_l3, so only the cfg check catches it. */
	map_reset();
	set_flags(FLAG_MHOP);
	build_v4(&f, 64, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-unconfigured-drops", run_frame(&f, NULL, NULL), XDP_DROP);
	map_reset();

	/* With FLAG_MHOP clear, parse_l3 drops it early; guards set_flags. */
	map_reset();
	set_flags(0);
	arm_session_ttl(32);
	build_v4(&f, 64, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-flag-clear-drops", run_frame(&f, NULL, NULL), XDP_DROP);
}


/* Nothing to do with BFD. The program must not claim it. */
static void case_not_bfd(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	build_v4(&f, 255, 1234, &p, 0);
	expect("non-bfd-port-passes", run_frame(&f, NULL, NULL), XDP_PASS);
}

/* RFC 5881 s5: TTL 255, dropped rather than passed to the socket. */
static void case_gtsm_v4(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	build_v4(&f, 200, BFD_PORT_1HOP, &p, 0);
	expect("gtsm-v4-low-ttl-drops", run_frame(&f, NULL, NULL), XDP_DROP);
}

/* v6 counterpart of case_gtsm_v4, plus the v6 arm of the deferred gate. */
static void case_gtsm_v6(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	map_reset_v6();
	build_v6(&f, 200, BFD_PORT_1HOP, &p, 0);
	expect("gtsm-v6-low-hlim-drops", run_frame(&f, NULL, NULL), XDP_DROP);

	/* Deferred: a configured v6 session whose minimum admits it. */
	set_flags(FLAG_MHOP);
	arm_session_v6_ttl(32);
	build_v6(&f, 64, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-v6-accepted", run_frame(&f, NULL, NULL), XDP_TX);

	build_v6(&f, 16, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-v6-below-min-drops", run_frame(&f, NULL, NULL), XDP_DROP);

	/* Negative arm for the flag on the v6 path specifically. */
	set_flags(0);
	build_v6(&f, 64, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-v6-flag-clear-drops", run_frame(&f, NULL, NULL), XDP_DROP);
	map_reset_v6();
	set_flags(0);
}

/* Kernel half of detect_vectors.h; the gap is synthesised through last_seen_ns. */
static void dv_row_xdp(const struct dv_case *c)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state st = { 0 };
	struct frame f;
	int bad = 0;

	map_reset();
	arm_session_rx(c->local_min_rx_us);

	for (int i = 0; i < c->nsteps; i++) {
		const struct dv_step *s = &c->steps[i];

		if (!read_state(&k, &st))
			return;
		if (i == 0) {
			/* No prior interval, as in the engine driver. */
			st.detect_iv_us = 0;
			st.last_seen_ns = 0;
			st.alive = 0;
		} else {
			st.last_seen_ns = mono_ns() - (__u64)s->gap_us * 1000ull;
			st.alive = 1;
		}
		if (bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
			printf("     state write failed: %s\n", strerror(errno));
			fails++;
			return;
		}

		p.min_tx = htonl(s->adv_min_tx_us);
		build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
		run_frame(&f, NULL, NULL);

		if (!read_state(&k, &st))
			return;
		if (st.detect_iv_us != s->want_iv_us) {
			printf("     step %d: detect_iv_us %u, want %u\n", i, st.detect_iv_us,
			       s->want_iv_us);
			bad = 1;
		}
	}

	if (bad) {
		printf("FAIL %-40s\n", c->name);
		fails++;
	} else {
		printf("ok   %-40s iv %u\n", c->name, st.detect_iv_us);
	}
	map_reset();
}

static void case_detect_vectors(void)
{
	for (int i = 0; i < DV_NCASES; i++) {
		if (dv_cases[i].boundary)
			continue;
		dv_row_xdp(&dv_cases[i]);
	}
}

/* One case per bfd_ctrl_check reject, both families: dropped, rx_pkts unmoved. */
static void case_malformed(int v6, const char *name, void (*mutate)(struct bfd_ctrl_pkt *),
			   int want_v, int slot)
{
	struct session_key k = v6 ? key_v6("fd00::2", "fd00::1") : key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after = { 0 };
	char full[80];
	struct frame f;
	int v, bad = 0;

	snprintf(full, sizeof(full), "%s-%s", name, v6 ? "v6" : "v4");

	if (v6) {
		map_reset_v6();
		arm_session_v6();
	} else {
		map_reset();
		arm_session();
	}

	mutate(&p);
	if (v6)
		build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	else
		build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);

	unsigned long long before = stat_get(slot);

	v = run_frame(&f, NULL, NULL);
	if (stat_get(slot) != before + 1) {
		printf("     stat slot %d did not increment\n", slot);
		bad = 1;
	}
	if (v != want_v) {
		printf("     verdict %s, want %s\n", v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want_v));
		bad = 1;
	}
	if (read_state(&k, &after) && after.rx_pkts != 0) {
		printf("     rx_pkts is %llu, a reject refreshed liveness\n",
		       (unsigned long long)after.rx_pkts);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", full);
		fails++;
	} else {
		printf("ok   %-40s %s, no state write\n", full, verdict_str(want_v));
	}

	if (v6)
		map_reset_v6();
	else
		map_reset();
}

static void mut_version(struct bfd_ctrl_pkt *p)
{
	p->vers_diag = (2 << 5);
}

static void mut_len_short(struct bfd_ctrl_pkt *p)
{
	p->len = 23;
}

static void mut_len_long(struct bfd_ctrl_pkt *p)
{
	p->len = 200;
}

static void mut_mult_zero(struct bfd_ctrl_pkt *p)
{
	p->detect_mult = 0;
}

static void mut_disc_zero(struct bfd_ctrl_pkt *p)
{
	p->my_disc = 0;
}

static void mut_auth(struct bfd_ctrl_pkt *p)
{
	p->flags |= BFD_F_AUTH;
}

static void mut_mp(struct bfd_ctrl_pkt *p)
{
	p->flags |= BFD_F_MP;
}

static void run_malformed_matrix(void)
{
	for (int v6 = 0; v6 < 2; v6++) {
		case_malformed(v6, "malformed-version", mut_version, XDP_DROP, BFD_STAT_MALFORMED);
		case_malformed(v6, "malformed-len-short", mut_len_short, XDP_DROP,
			       BFD_STAT_MALFORMED);
		case_malformed(v6, "malformed-len-long", mut_len_long, XDP_DROP,
			       BFD_STAT_MALFORMED);
		case_malformed(v6, "malformed-mult-zero", mut_mult_zero, XDP_DROP,
			       BFD_STAT_MALFORMED);
		case_malformed(v6, "malformed-disc-zero", mut_disc_zero, XDP_DROP,
			       BFD_STAT_MALFORMED);
		/* Counted against the session, which has no key (RFC 5880 s6.8.6). */
		case_malformed(v6, "auth-bit-no-key", mut_auth, XDP_DROP, BFD_STAT_AUTH_MISMATCH);
		case_malformed(v6, "unsupported-mp", mut_mp, XDP_DROP, BFD_STAT_UNSUPPORTED_FLAGS);
	}
}

/* RFC 5880 s6.8.6: rejects must not refresh liveness, so each arm checks rx_pkts. */
static void case_demux(int v6, const char *name, uint32_t ydisc, uint8_t peer_state, int want_v,
		       uint64_t want_rx)
{
	struct session_key k = v6 ? key_v6("fd00::2", "fd00::1") : key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after = { 0 };
	unsigned long long before;
	char full[80];
	struct frame f;
	int v, bad = 0;

	snprintf(full, sizeof(full), "%s-%s", name, v6 ? "v6" : "v4");

	if (v6) {
		map_reset_v6();
		arm_session_v6();
	} else {
		map_reset();
		arm_session();
	}

	p.your_disc = htonl(ydisc);
	p.flags = (peer_state << 6);

	if (v6)
		build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	else
		build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);

	before = stat_get(BFD_STAT_REJECTED);
	v = run_frame(&f, NULL, NULL);

	if (v != want_v) {
		printf("     verdict %s, want %s\n", v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want_v));
		bad = 1;
	}
	if (want_v == XDP_DROP && stat_get(BFD_STAT_REJECTED) != before + 1) {
		printf("     rejected counter did not increment\n");
		bad = 1;
	}
	if (read_state(&k, &after) && after.rx_pkts != want_rx) {
		printf("     rx_pkts is %llu, want %llu\n", (unsigned long long)after.rx_pkts,
		       (unsigned long long)want_rx);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", full);
		fails++;
	} else {
		printf("ok   %-40s %s, rx %llu\n", full, verdict_str(want_v),
		       (unsigned long long)want_rx);
	}

	if (v6)
		map_reset_v6();
	else
		map_reset();
}

static void run_demux_matrix(void)
{
	for (int v6 = 0; v6 < 2; v6++) {
		/* names our session: accepted, and bounced since it is Up */
		case_demux(v6, "demux-match", 0x22222222, ST_UP, XDP_TX, 1);
		/* no fallback to the address pair on a miss */
		case_demux(v6, "demux-wrong-disc", 0x99999999, ST_UP, XDP_DROP, 0);
		/* the restart case; no bounce below Init */
		case_demux(v6, "demux-zero-peer-down", 0, ST_DOWN, XDP_PASS, 1);
		/* zero with the peer Up: not the restart case, rejected */
		case_demux(v6, "demux-zero-peer-up", 0, ST_UP, XDP_DROP, 0);
	}
}

/* RFC 5880 s6.8.6: omitting authentication must not downgrade a keyed session. */
static void case_auth_required(int v6)
{
	struct session_key k = v6 ? key_v6("fd00::2", "fd00::1") : key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct tx_cfg cfg = { 0 };
	struct frame f;
	unsigned long long before;
	const char *name = v6 ? "auth-required-v6" : "auth-required-v4";
	int v;

	map_reset();
	if (v6)
		arm_session_v6();
	else
		arm_session();

	/* Same session, now carrying a key. */
	if (bpf_map_lookup_elem(cfg_fd, &k, &cfg)) {
		printf("FAIL %-40s no cfg\n", name);
		fails++;
		return;
	}
	cfg.auth_type = BFD_AUTH_KEYED_SHA1;
	cfg.auth_present = 1;
	bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY);

	before = stat_get(BFD_STAT_AUTH_MISMATCH);
	if (v6)
		build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	else
		build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	v = run_frame(&f, NULL, NULL);

	if (v != XDP_DROP) {
		printf("     verdict %s, want DROP\n", v < 0 ? "syscall-error" : verdict_str(v));
		printf("FAIL %-40s\n", name);
		fails++;
	} else if (stat_get(BFD_STAT_AUTH_MISMATCH) != before + 1) {
		printf("     auth-mismatch did not move\n");
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s DROP\n", name);
	}
	map_reset();
}

/* Only a first fragment to a BFD port is dropped; later ones have no UDP header. */
static void case_frag(const char *name, uint16_t frag_off, uint16_t dport, int want_v,
		      uint64_t want_rx)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after = { 0 };
	unsigned long long before;
	struct frame f;
	int v, bad = 0;

	map_reset();
	arm_session();
	build_v4(&f, 255, dport, &p, 0);

	struct iphdr *ip = (void *)(f.b + sizeof(struct ethhdr));

	ip->frag_off = htons(frag_off);
	ip->check = 0;
	ip->check = csum16(ip, sizeof(*ip), 0);

	before = stat_get(BFD_STAT_REJECTED);
	v = run_frame(&f, NULL, NULL);

	if (v != want_v) {
		printf("     verdict %s, want %s\n", v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want_v));
		bad = 1;
	}
	if (want_v == XDP_DROP && stat_get(BFD_STAT_REJECTED) != before + 1) {
		printf("     rejected counter did not increment\n");
		bad = 1;
	}
	if (read_state(&k, &after) && after.rx_pkts != want_rx) {
		printf("     rx_pkts is %llu, want %llu\n", (unsigned long long)after.rx_pkts,
		       (unsigned long long)want_rx);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s %s, rx %llu\n", name, verdict_str(want_v),
		       (unsigned long long)want_rx);
	}
	map_reset();
}

static void run_frag_matrix(void)
{
	/* first fragment (MF, offset 0) at a BFD port: dropped */
	case_frag("frag-first-bfd-port", 0x2000, BFD_PORT_1HOP, XDP_DROP, 0);
	/* non-first fragment: passed, the port bytes are not a UDP header */
	case_frag("frag-nonfirst-passes", 0x0064, BFD_PORT_1HOP, XDP_PASS, 0);
	/* first fragment at a port we do not serve: passed */
	case_frag("frag-first-other-port", 0x2000, 1234, XDP_PASS, 0);
	/* DF set is not a fragment at all: normal handling, so a bounce */
	case_frag("frag-df-not-a-fragment", 0x4000, BFD_PORT_1HOP, XDP_TX, 1);
}

/* Dropped as malformed, without refreshing liveness. */
static void case_bad_envelope(const char *name, int which)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after;
	unsigned long long before;
	struct frame f;
	int v, bad = 0;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);

	struct iphdr *ip = (void *)(f.b + sizeof(struct ethhdr));
	struct udphdr *udp = (void *)(ip + 1);

	if (which == 0)
		udp->len = htons(208); /* more UDP than arrived */
	else
		ip->tot_len = htons(400); /* more IP than arrived */

	ip->check = 0;
	ip->check = csum16(ip, sizeof(*ip), 0);

	before = stat_get(BFD_STAT_MALFORMED);
	v = run_frame(&f, NULL, NULL);

	if (v != XDP_DROP) {
		printf("     verdict %s, want DROP\n", v < 0 ? "syscall-error" : verdict_str(v));
		bad = 1;
	}
	if (stat_get(BFD_STAT_MALFORMED) != before + 1) {
		printf("     malformed counter did not move\n");
		bad = 1;
	}
	if (read_state(&k, &after) && after.rx_pkts != 0) {
		printf("     rx_pkts is %llu, a lying envelope refreshed liveness\n",
		       (unsigned long long)after.rx_pkts);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s DROP, no state write\n", name);
	}
	map_reset();
}

/* Dropped for a BFD port, passed otherwise. */
static void case_ip_options(const char *name, uint16_t dport, int want, int want_counter)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned long long before;
	struct frame f;
	int v, bad = 0;

	map_reset();
	arm_session();
	build_v4(&f, 255, dport, &p, 0);

	struct ethhdr *eth = (void *)f.b;
	struct iphdr *ip = (void *)(eth + 1);
	unsigned char *opt = (unsigned char *)(ip + 1);
	unsigned int moved = sizeof(struct udphdr) + sizeof(p);

	/* NOP, NOP, NOP, EOL; everything after shifts. */
	memmove(opt + 4, opt, moved);
	opt[0] = 1;
	opt[1] = 1;
	opt[2] = 1;
	opt[3] = 0;
	f.len += 4;

	ip->ihl = 6;
	ip->tot_len = htons(ntohs(ip->tot_len) + 4);
	ip->check = 0;
	ip->check = csum16(ip, 6 * 4, 0);

	before = stat_get(BFD_STAT_IP_OPTIONS);
	v = run_frame(&f, NULL, NULL);

	if (v != want) {
		printf("     verdict %s, want %s\n", v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want));
		bad = 1;
	}
	if (stat_get(BFD_STAT_IP_OPTIONS) != before + want_counter) {
		printf("     ip-options counter moved by %llu, want %d\n",
		       stat_get(BFD_STAT_IP_OPTIONS) - before, want_counter);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s %s\n", name, verdict_str(want));
	}
	map_reset();
}

/* Passed: the parser and the stack read the same wrong bytes. */
static void case_ip_options_lying(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;
	int v;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);

	struct iphdr *ip = (void *)(f.b + sizeof(struct ethhdr));

	ip->ihl = 6; /* the UDP header is still at twenty bytes */
	ip->check = 0;
	ip->check = csum16(ip, 6 * 4, 0);

	v = run_frame(&f, NULL, NULL);
	expect("ip-options-declared-not-present", v, XDP_PASS);
	map_reset();
}

/* The BFD rules are gated on the port. */
static void case_not_bfd_ttl(uint8_t ttl)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	char name[64];
	struct frame f;

	map_reset();
	arm_session();
	build_v4(&f, ttl, 1234, &p, 0);
	snprintf(name, sizeof(name), "non-bfd-v4-ttl-%u-passes", ttl);
	expect(name, run_frame(&f, NULL, NULL), XDP_PASS);
	map_reset();
}

static void case_not_bfd_v6_hlim(uint8_t hlim)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	char name[64];
	struct frame f;

	map_reset();
	arm_session();
	build_v6(&f, hlim, 1234, &p, 0);
	snprintf(name, sizeof(name), "non-bfd-v6-hlim-%u-passes", hlim);
	expect(name, run_frame(&f, NULL, NULL), XDP_PASS);
	map_reset();
}

/* Dropped and counted; the promiscuous flag passes it uncounted. */
static void case_unknown_session(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;
	unsigned long long u0, u1;

	map_reset();
	u0 = stat_get(BFD_STAT_UNKNOWN_SESSION);
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	expect("unknown-session-v4-drops", run_frame(&f, NULL, NULL), XDP_DROP);
	u1 = stat_get(BFD_STAT_UNKNOWN_SESSION);
	if (u1 - u0 != 1) {
		printf("FAIL %-40s unknown-session+%llu, want +1\n", "unknown-session-v4-counter",
		       u1 - u0);
		fails++;
	} else
		printf("ok   %-40s unknown-session+1\n", "unknown-session-v4-counter");

	map_reset_v6();
	u0 = stat_get(BFD_STAT_UNKNOWN_SESSION);
	build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	expect("unknown-session-v6-drops", run_frame(&f, NULL, NULL), XDP_DROP);
	u1 = stat_get(BFD_STAT_UNKNOWN_SESSION);
	if (u1 - u0 != 1) {
		printf("FAIL %-40s unknown-session+%llu, want +1\n", "unknown-session-v6-counter",
		       u1 - u0);
		fails++;
	} else
		printf("ok   %-40s unknown-session+1\n", "unknown-session-v6-counter");

	/* Promiscuous observer still passes it, and does not count it. */
	map_reset();
	set_flags(FLAG_PROMISC);
	u0 = stat_get(BFD_STAT_UNKNOWN_SESSION);
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	expect("unknown-session-promisc-passes", run_frame(&f, NULL, NULL), XDP_PASS);
	u1 = stat_get(BFD_STAT_UNKNOWN_SESSION);
	if (u1 - u0 != 0) {
		printf("FAIL %-40s unknown-session+%llu under promisc, want +0\n",
		       "unknown-session-promisc-counter", u1 - u0);
		fails++;
	} else
		printf("ok   %-40s no unknown-session count under promisc\n",
		       "unknown-session-promisc-counter");
	map_reset();
}

/* Dropped for a BFD port; a non-BFD port and ICMPv6 (ND) pass. */
static void case_v6_exthdr(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;
	unsigned long long e0, e1;

	map_reset_v6();

	/* hop-by-hop then UDP to a BFD port: dropped and counted. */
	e0 = stat_get(BFD_STAT_V6_EXTHDR);
	build_v6_exthdr(&f, IPPROTO_HOPOPTS, IPPROTO_UDP, BFD_PORT_1HOP, &p);
	expect("v6-exthdr-hopopts-bfd-drops", run_frame(&f, NULL, NULL), XDP_DROP);
	e1 = stat_get(BFD_STAT_V6_EXTHDR);
	if (e1 - e0 != 1) {
		printf("FAIL %-40s v6-exthdr+%llu, want +1\n", "v6-exthdr-counter", e1 - e0);
		fails++;
	} else
		printf("ok   %-40s v6-exthdr+1\n", "v6-exthdr-counter");

	/* dest-opts then UDP to a non-BFD port: passes, not counted. */
	e0 = stat_get(BFD_STAT_V6_EXTHDR);
	build_v6_exthdr(&f, IPPROTO_DSTOPTS, IPPROTO_UDP, 1234, &p);
	expect("v6-exthdr-nonbfd-passes", run_frame(&f, NULL, NULL), XDP_PASS);
	e1 = stat_get(BFD_STAT_V6_EXTHDR);
	if (e1 != e0) {
		printf("FAIL %-40s counted a non-BFD-port pass\n", "v6-exthdr-nonbfd-counter");
		fails++;
	} else
		printf("ok   %-40s not counted\n", "v6-exthdr-nonbfd-counter");

	/* ICMPv6 is not an extension header: ND must pass. */
	build_v6_exthdr(&f, IPPROTO_ICMPV6, 0, BFD_PORT_1HOP, &p);
	expect("v6-icmp6-nd-passes", run_frame(&f, NULL, NULL), XDP_PASS);

	map_reset_v6();
}
