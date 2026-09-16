// SPDX-License-Identifier: GPL-2.0
/* Part of the xdp_run test, split by subject (CI-review item 5).
 * Compiled as one unit via tests/unit/xdp_run.c, which carries the
 * includes, the shared globals and main; include order there is the
 * dependency order (harness first, sweep last). */

/* Deferred GTSM (087c9af). A packet below 255 is acceptable only if it
 * names a configured session whose min_ttl admits it. Four arms: above
 * the minimum, exactly at it (pttl < mt is strict), below it, and the
 * null-cfg arm that must drop even with the multihop flag set - which is
 * why the gate sits ABOVE the promiscuous PASS rather than after it.
 *
 * No leak case is written: the session key is address-only, so a
 * single-hop and a multihop session on one pair are the same tx_config
 * entry and there is no per-port state to leak. */
static void case_deferred_gtsm(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	map_reset();
	set_flags(FLAG_MHOP);
	arm_session_ttl(32);

	build_v4(&f, 64, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-low-ttl-accepted", run_frame(&f, NULL, NULL),
	       XDP_TX);

	build_v4(&f, 32, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-exact-min-accepted", run_frame(&f, NULL, NULL),
	       XDP_TX);

	build_v4(&f, 16, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-below-min-drops", run_frame(&f, NULL, NULL),
	       XDP_DROP);

	/* Nothing configured, multihop flag set: parse_l3 deferred the
	 * verdict, so only the cfg check can catch this one. */
	map_reset();
	set_flags(FLAG_MHOP);
	build_v4(&f, 64, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-unconfigured-drops", run_frame(&f, NULL, NULL),
	       XDP_DROP);
	map_reset();

	/* Negative arm for the flag itself. With FLAG_MHOP clear, parse_l3
	 * rejects a sub-255 packet before the deferred gate is reached, so
	 * the first case's frame must DROP. Without this, a set_flags that
	 * silently wrote nothing would leave both DROP arms vacuous. */
	map_reset();
	set_flags(0);
	arm_session_ttl(32);
	build_v4(&f, 64, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-flag-clear-drops", run_frame(&f, NULL, NULL),
	       XDP_DROP);
}

/* ---------- cases ---------- */

/* Nothing to do with BFD. The program must not claim it. */
static void case_not_bfd(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	build_v4(&f, 255, 1234, &p, 0);
	expect("non-bfd-port-passes", run_frame(&f, NULL, NULL), XDP_PASS);
}

/* RFC 5881 s5: a single-hop control packet must arrive at TTL 255. The
 * reject must be XDP_DROP specifically, not XDP_PASS: a reject that
 * passes leaks the packet to the userspace socket. */
static void case_gtsm_v4(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	build_v4(&f, 200, BFD_PORT_1HOP, &p, 0);
	expect("gtsm-v4-low-ttl-drops", run_frame(&f, NULL, NULL), XDP_DROP);
}

/* v6 counterpart of case_gtsm_v4, plus the v6 arm of the deferred gate.
 * parse.h reads the multihop flag at two sites, one per family, and only
 * the v4 side had a case. The v6-only IPV6_MINHOPCOUNT defect the netns
 * rig found is the reason this asymmetry is worth closing. */
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
	expect("deferred-gtsm-v6-below-min-drops", run_frame(&f, NULL, NULL),
	       XDP_DROP);

	/* Negative arm for the flag on the v6 path specifically. */
	set_flags(0);
	build_v6(&f, 64, BFD_PORT_MHOP, &p, 0);
	expect("deferred-gtsm-v6-flag-clear-drops", run_frame(&f, NULL, NULL),
	       XDP_DROP);
	map_reset_v6();
	set_flags(0);
}

static void dv_row_xdp(const struct dv_case *c)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state st = {0};
	struct frame f;
	int bad = 0;

	map_reset();
	arm_session_rx(c->local_min_rx_us);

	for (int i = 0; i < c->nsteps; i++) {
		const struct dv_step *s = &c->steps[i];

		if (!read_state(&k, &st))
			return;
		if (i == 0) {
			/* No prior interval: the first packet must take the
			 * !detect_iv_us branch, as in the engine driver. */
			st.detect_iv_us = 0;
			st.last_seen_ns = 0;
			st.alive        = 0;
		} else {
			st.last_seen_ns = mono_ns() - (__u64)s->gap_us * 1000ull;
			st.alive        = 1;
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
			printf("     step %d: detect_iv_us %u, want %u\n",
			       i, st.detect_iv_us, s->want_iv_us);
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

/* bfd_ctrl_check's reject conditions, one case each, both families.
 *
 * Two assertions per case, not one. The verdict must be XDP_DROP
 * specifically, since a reject that returns XDP_PASS leaks the packet to
 * the userspace socket. And rx_pkts must not move, because a rejected
 * packet must not refresh liveness - a peer sending garbage would
 * otherwise hold the session up forever. */
static void case_malformed(int v6, const char *name,
			   void (*mutate)(struct bfd_ctrl_pkt *), int want_v,
			   int slot)
{
	struct session_key k = v6 ? key_v6("fd00::2", "fd00::1")
			  : key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after = {0};
	char full[80];
	struct frame f;
	int v, bad = 0;

	snprintf(full, sizeof(full), "%s-%s", name, v6 ? "v6" : "v4");

	if (v6) { map_reset_v6(); arm_session_v6(); }
	else    { map_reset();    arm_session();    }

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
		printf("     verdict %s, want %s\n",
		       v < 0 ? "syscall-error" : verdict_str(v),
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
		printf("ok   %-40s %s, no state write\n", full,
		       verdict_str(want_v));
	}

	if (v6) map_reset_v6(); else map_reset();
}

static void mut_version(struct bfd_ctrl_pkt *p)  { p->vers_diag = (2 << 5); }

static void mut_len_short(struct bfd_ctrl_pkt *p){ p->len = 23; }

static void mut_len_long(struct bfd_ctrl_pkt *p) { p->len = 200; }

static void mut_mult_zero(struct bfd_ctrl_pkt *p){ p->detect_mult = 0; }

static void mut_disc_zero(struct bfd_ctrl_pkt *p){ p->my_disc = 0; }

static void mut_auth(struct bfd_ctrl_pkt *p)     { p->flags |= BFD_F_AUTH; }

static void mut_mp(struct bfd_ctrl_pkt *p)       { p->flags |= BFD_F_MP; }

static void run_malformed_matrix(void)
{
	for (int v6 = 0; v6 < 2; v6++) {
		case_malformed(v6, "malformed-version",   mut_version, XDP_DROP,
			       BFD_STAT_MALFORMED);
		case_malformed(v6, "malformed-len-short", mut_len_short, XDP_DROP,
			       BFD_STAT_MALFORMED);
		case_malformed(v6, "malformed-len-long",  mut_len_long, XDP_DROP,
			       BFD_STAT_MALFORMED);
		case_malformed(v6, "malformed-mult-zero", mut_mult_zero, XDP_DROP,
			       BFD_STAT_MALFORMED);
		case_malformed(v6, "malformed-disc-zero", mut_disc_zero, XDP_DROP,
			       BFD_STAT_MALFORMED);
		/* Still dropped, but attributed to the session rather than
		 * to the flag: the A bit is only unacceptable because this
		 * session has no key. RFC 5880 s6.8.6. */
		case_malformed(v6, "auth-bit-no-key",     mut_auth, XDP_DROP,
			       BFD_STAT_AUTH_MISMATCH);
		case_malformed(v6, "unsupported-mp",      mut_mp, XDP_DROP,
			       BFD_STAT_UNSUPPORTED_FLAGS);
	}
}

/* Demux, RFC 5880 s6.8.6. your_disc must name our session, or be zero
 * with the peer in Down or AdminDown (it lost state, or is restarting).
 *
 * The reject must not refresh liveness: that is how spoofed traffic keeps
 * a dead session up, and it is why each arm checks rx_pkts as well as the
 * verdict. tests/netns_userspace.py found the userspace path falling back
 * to the address pair on any miss; these arms pin the kernel side of the
 * same rule. */
static void case_demux(int v6, const char *name, uint32_t ydisc,
		       uint8_t peer_state, int want_v, uint64_t want_rx)
{
	struct session_key k = v6 ? key_v6("fd00::2", "fd00::1")
			  : key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after = {0};
	unsigned long long before;
	char full[80];
	struct frame f;
	int v, bad = 0;

	snprintf(full, sizeof(full), "%s-%s", name, v6 ? "v6" : "v4");

	if (v6) { map_reset_v6(); arm_session_v6(); }
	else    { map_reset();    arm_session();    }

	p.your_disc = htonl(ydisc);
	p.flags = (peer_state << 6);

	if (v6)
		build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	else
		build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);

	before = stat_get(BFD_STAT_REJECTED);
	v = run_frame(&f, NULL, NULL);

	if (v != want_v) {
		printf("     verdict %s, want %s\n",
		       v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want_v));
		bad = 1;
	}
	if (want_v == XDP_DROP && stat_get(BFD_STAT_REJECTED) != before + 1) {
		printf("     rejected counter did not increment\n");
		bad = 1;
	}
	if (read_state(&k, &after) && after.rx_pkts != want_rx) {
		printf("     rx_pkts is %llu, want %llu\n",
		       (unsigned long long)after.rx_pkts,
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

	if (v6) map_reset_v6(); else map_reset();
}

static void run_demux_matrix(void)
{
	for (int v6 = 0; v6 < 2; v6++) {
		/* names our session: accepted, and bounced since it is Up */
		case_demux(v6, "demux-match", 0x22222222, ST_UP, XDP_TX, 1);
		/* names something else: rejected even though the address
		 * pair is in the map - no fallback on a miss */
		case_demux(v6, "demux-wrong-disc", 0x99999999, ST_UP,
			   XDP_DROP, 0);
		/* zero with the peer Down: the restart case, accepted.
		 * No bounce: rx_clocked_tx needs rstate >= Init. */
		case_demux(v6, "demux-zero-peer-down", 0, ST_DOWN, XDP_PASS, 1);
		/* zero with the peer Up: not the restart case, rejected */
		case_demux(v6, "demux-zero-peer-up", 0, ST_UP, XDP_DROP, 0);
	}
}

/* The other half of RFC 5880 s6.8.6, and the half that matters: a
 * session with a key must reject a packet that arrives without one.
 * Without this rule a peer downgrades the session simply by omitting
 * authentication, which is the whole attack authentication exists to
 * stop - and it would look like an ordinary healthy session.
 */
static void case_auth_required(int v6)
{
	struct session_key k = v6 ? key_v6("fd00::2", "fd00::1")
				  : key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct tx_cfg cfg = {0};
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
		printf("     verdict %s, want DROP\n",
		       v < 0 ? "syscall-error" : verdict_str(v));
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

/* IPv4 fragmentation.
 *
 * The rule in parse.h is narrower than "drop fragments": only a FIRST
 * fragment (offset 0, MF set) aimed at a BFD port is dropped. A non-first
 * fragment PASSes, because at that point the bytes where the UDP header
 * would be are payload, so the port comparison would be meaningless - the
 * offset is checked first for exactly that reason.
 *
 * IPv6 needs no equivalent: a fragment header makes nexthdr != UDP and the
 * frame falls out of dispatch before any of this. */
static void case_frag(const char *name, uint16_t frag_off, uint16_t dport,
		      int want_v, uint64_t want_rx)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after = {0};
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
		printf("     verdict %s, want %s\n",
		       v < 0 ? "syscall-error" : verdict_str(v),
		       verdict_str(want_v));
		bad = 1;
	}
	if (want_v == XDP_DROP && stat_get(BFD_STAT_REJECTED) != before + 1) {
		printf("     rejected counter did not increment\n");
		bad = 1;
	}
	if (read_state(&k, &after) && after.rx_pkts != want_rx) {
		printf("     rx_pkts is %llu, want %llu\n",
		       (unsigned long long)after.rx_pkts,
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

/* An envelope that does not describe the frame.
 *
 * bfd_ctrl_check takes the payload length from udp->len, which is whatever
 * the sender wrote, and nothing compared it against what actually arrived.
 * A 66 byte frame claiming a UDP length of 208 was accepted: no overread,
 * because every field read afterwards is inside the 24 bytes already
 * bounds-checked, but it refreshed liveness and could acknowledge a Poll
 * on a packet that is not what it says it is.
 *
 * Worse on the way out. The bounce trimmed and rewrote the lengths only
 * when there was a tail to trim, so a frame with nothing spare went back
 * out still claiming 208 - built by this engine, with a length its own
 * receive path would now refuse.
 *
 * MALFORMED, and now dropped (HARDENING_PLAN G2), like any broken BFD
 * header on ports only our socket consumes. It still must not refresh
 * liveness, and must not leave on the wire under our name.
 */
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
		udp->len = htons(208);          /* more UDP than arrived */
	else
		ip->tot_len = htons(400);       /* more IP than arrived */

	ip->check = 0;
	ip->check = csum16(ip, sizeof(*ip), 0);

	before = stat_get(BFD_STAT_MALFORMED);
	v = run_frame(&f, NULL, NULL);

	if (v != XDP_DROP) {
		printf("     verdict %s, want DROP\n",
		       v < 0 ? "syscall-error" : verdict_str(v));
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

/* IP options.
 *
 * A BFD control packet never carries them, and with them the UDP header is
 * at an offset the fixed-offset reads in the parser would get wrong, so one
 * aimed at a BFD port is dropped rather than passed: passing it would skip
 * GTSM and demux and leak it to the userspace socket unvalidated.
 *
 * The rule is about BFD, so it is gated on the port like every other rule
 * here. An optioned packet going anywhere else is not ours and reaches the
 * stack untouched, which the other-port arm pins.
 *
 * The frame is built properly, with the options actually present between
 * the IP header and the UDP header rather than declared in `ihl` and not
 * there. The earlier version of this case set `ihl` alone, which the parser
 * could not have distinguished from a lie and which no real sender emits.
 */
static void case_ip_options(const char *name, uint16_t dport, int want,
			    int want_counter)
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

	/* Open four bytes after the IP header and fill them with a real
	 * option: NOP, NOP, NOP, End of Option List. Everything after
	 * shifts, which is what makes this an optioned packet rather than
	 * a claim of one. */
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
		printf("     verdict %s, want %s\n",
		       v < 0 ? "syscall-error" : verdict_str(v),
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

/* An `ihl` that claims options the frame does not carry.
 *
 * The parser reads the port where the header says the payload starts, and
 * so does the stack, so both look at the same wrong bytes and neither
 * delivers it to a BFD socket. Passing it is therefore not a bypass, and
 * dropping it would mean dropping on a declared length alone, which is how
 * unrelated traffic got caught before.
 */
static void case_ip_options_lying(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;
	int v;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);

	struct iphdr *ip = (void *)(f.b + sizeof(struct ethhdr));

	ip->ihl = 6;   /* the UDP header is still at twenty bytes */
	ip->check = 0;
	ip->check = csum16(ip, 6 * 4, 0);

	v = run_frame(&f, NULL, NULL);
	expect("ip-options-declared-not-present", v, XDP_PASS);
	map_reset();
}

/* Traffic that is not BFD, at the TTLs real traffic arrives with.
 *
 * Every BFD rejection rule is about BFD. Before they were gated on the
 * port, a DNS reply at TTL 57 was dropped in the driver whenever no
 * multihop session existed, which is most deployments.
 */
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

/* G3 (HARDENING_PLAN 3.1): a well-formed control packet at TTL 255 for an
 * address pair with no tx_config entry is dropped in XDP and counted, not
 * passed to the socket. Our socket is the only consumer of the BFD ports,
 * so passing it is the widest flood path to recvmsg. The promiscuous flag
 * keeps XDP_PASS for the standalone observer, which does not count it. */
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
		printf("FAIL %-40s unknown-session+%llu, want +1\n",
		       "unknown-session-v4-counter", u1 - u0);
		fails++;
	} else
		printf("ok   %-40s unknown-session+1\n",
		       "unknown-session-v4-counter");

	map_reset_v6();
	u0 = stat_get(BFD_STAT_UNKNOWN_SESSION);
	build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	expect("unknown-session-v6-drops", run_frame(&f, NULL, NULL), XDP_DROP);
	u1 = stat_get(BFD_STAT_UNKNOWN_SESSION);
	if (u1 - u0 != 1) {
		printf("FAIL %-40s unknown-session+%llu, want +1\n",
		       "unknown-session-v6-counter", u1 - u0);
		fails++;
	} else
		printf("ok   %-40s unknown-session+1\n",
		       "unknown-session-v6-counter");

	/* Promiscuous observer still passes it, and does not count it. */
	map_reset();
	set_flags(FLAG_PROMISC);
	u0 = stat_get(BFD_STAT_UNKNOWN_SESSION);
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	expect("unknown-session-promisc-passes", run_frame(&f, NULL, NULL),
	       XDP_PASS);
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

/* G1 (HARDENING_PLAN 3.3): UDP behind one v6 extension header aimed at a
 * BFD port is dropped and counted; the same behind a non-BFD port, and a
 * plain ICMPv6 packet (neighbour discovery), still pass. */
static void case_v6_exthdr(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;
	unsigned long long e0, e1;

	map_reset_v6();

	/* hop-by-hop then UDP to a BFD port: dropped and counted. */
	e0 = stat_get(BFD_STAT_V6_EXTHDR);
	build_v6_exthdr(&f, IPPROTO_HOPOPTS, IPPROTO_UDP, BFD_PORT_1HOP, &p);
	expect("v6-exthdr-hopopts-bfd-drops", run_frame(&f, NULL, NULL),
	       XDP_DROP);
	e1 = stat_get(BFD_STAT_V6_EXTHDR);
	if (e1 - e0 != 1) {
		printf("FAIL %-40s v6-exthdr+%llu, want +1\n",
		       "v6-exthdr-counter", e1 - e0);
		fails++;
	} else
		printf("ok   %-40s v6-exthdr+1\n", "v6-exthdr-counter");

	/* dest-opts then UDP to a non-BFD port: passes, not counted. */
	e0 = stat_get(BFD_STAT_V6_EXTHDR);
	build_v6_exthdr(&f, IPPROTO_DSTOPTS, IPPROTO_UDP, 1234, &p);
	expect("v6-exthdr-nonbfd-passes", run_frame(&f, NULL, NULL), XDP_PASS);
	e1 = stat_get(BFD_STAT_V6_EXTHDR);
	if (e1 != e0) {
		printf("FAIL %-40s counted a non-BFD-port pass\n",
		       "v6-exthdr-nonbfd-counter");
		fails++;
	} else
		printf("ok   %-40s not counted\n", "v6-exthdr-nonbfd-counter");

	/* plain ICMPv6 (nexthdr 58, not an extension header): passes. This
	 * is neighbour discovery, and G1 must never touch it. */
	build_v6_exthdr(&f, IPPROTO_ICMPV6, 0, BFD_PORT_1HOP, &p);
	expect("v6-icmp6-nd-passes", run_frame(&f, NULL, NULL), XDP_PASS);

	map_reset_v6();
}
