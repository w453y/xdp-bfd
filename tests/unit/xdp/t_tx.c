// SPDX-License-Identifier: GPL-2.0
/* Part of xdp_run, split by subject; compiled as one unit via
 * tests/unit/xdp_run.c. */

/* An Up packet from an armed peer must be bounced, not passed. This is
 * the gate in bfd_xdp.c: cfg->enable and the peer at Init or better. */
static void case_bounce_v4(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	struct frame f;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	expect("bounce-v4-up", run_frame(&f, NULL, NULL), XDP_TX);
	map_reset();
}

/* The verdict says the program chose to bounce. This says the frame it
 * produced is the one tx.h describes. Checked field by field rather than
 * memcmp against a whole expected frame, so a failure names what moved. */
static void case_bounce_v4_frame(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned char out[FRAME_MAX];
	unsigned int out_len = 0;
	struct frame f;
	int v;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	v = run_frame(&f, out, &out_len);
	if (v != XDP_TX) {
		printf("FAIL %-40s no bounce to inspect\n", "bounce-v4-frame");
		fails++;
		map_reset();
		return;
	}

	const struct ethhdr *ie = (const void *)f.b;
	const struct ethhdr *oe = (const void *)out;
	const struct iphdr *ii = (const void *)(ie + 1);
	const struct iphdr *oi = (const void *)(oe + 1);
	const struct udphdr *ou = (const void *)(oi + 1);
	const struct bfd_ctrl_pkt *ob = (const void *)(ou + 1);
	unsigned int want_len = sizeof(*oe) + sizeof(*oi) + sizeof(*ou) + 24;
	int bad = 0;

#define CHK(cond, what) do { if (!(cond)) { \
	printf("     %s\n", what); bad = 1; } } while (0)

	CHK(out_len == want_len, "frame length not eth+ip+udp+24");
	CHK(!memcmp(oe->h_dest, ie->h_source, 6), "dest MAC is not the arriving source");
	CHK(!memcmp(oe->h_source, ie->h_dest, 6), "source MAC is not the arriving dest");
	CHK(oi->saddr == ii->daddr, "source IP is not the arriving dest");
	CHK(oi->daddr == ii->saddr, "dest IP is not the arriving source");
	CHK(oi->ttl == 255, "TTL is not 255");
	CHK(ntohs(oi->tot_len) == want_len - sizeof(*oe), "tot_len not updated");
	CHK(csum16(oi, sizeof(*oi), 0) == 0, "IP checksum does not verify");
	CHK(ntohs(ou->source) == BFD_SRC_PORT, "source port is not BFD_SRC_PORT");
	CHK(ntohs(ou->dest) == BFD_PORT_1HOP, "dest port is not the arriving port");
	CHK(ntohs(ou->len) == (int)(sizeof(*ou) + 24), "udp len not updated");
	CHK(ob->len == 24, "bfd len field is not 24");
	CHK((ob->flags >> 6) == ST_UP, "state is not Up");
	CHK(!(ob->flags & (BFD_F_POLL | BFD_F_FINAL)), "P or F set on a plain reply");
	CHK(ntohl(ob->my_disc) == 0x22222222, "my_disc not from tx_cfg");
	CHK(ntohl(ob->your_disc) == 0x11111111, "your_disc not from tx_cfg");
	CHK(ob->detect_mult == 3, "detect_mult not from tx_cfg");
#undef CHK

	if (bad) {
		printf("FAIL %-40s\n", "bounce-v4-frame");
		fails++;
	} else {
		printf("ok   %-40s %u bytes\n", "bounce-v4-frame", out_len);
	}
	map_reset();
}

/* The D bit on an RX-clocked reply: the engine decides it, the program carries
 * it, and it accompanies a Final (s6.5). in_flags sets what the arriving frame
 * carries. */
static void case_demand_bit_out(uint8_t cfg_demand, uint8_t in_flags,
				uint8_t want_set, uint8_t want_final,
				const char *name)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned char out[FRAME_MAX];
	unsigned int out_len = 0;
	struct tx_cfg cfg = {0};
	struct frame f;
	int v, bad = 0;

	map_reset();
	arm_session();
	if (bpf_map_lookup_elem(cfg_fd, &k, &cfg)) {
		printf("FAIL %-40s no cfg\n", name);
		fails++;
		return;
	}
	cfg.demand = cfg_demand;
	bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY);

	p.flags |= in_flags;
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	v = run_frame(&f, out, &out_len);
	if (v != XDP_TX) {
		printf("FAIL %-40s no bounce (%s)\n", name,
		       v < 0 ? "syscall-error" : verdict_str(v));
		fails++;
		map_reset();
		return;
	}

	const struct ethhdr *oe = (const void *)out;
	const struct iphdr *oi = (const void *)(oe + 1);
	const struct udphdr *ou = (const void *)(oi + 1);
	const struct bfd_ctrl_pkt *ob = (const void *)(ou + 1);
	uint8_t got = !!(ob->flags & BFD_F_DEMAND);
	uint8_t gotf = !!(ob->flags & BFD_F_FINAL);

	if (got != want_set) {
		printf("     D bit is %u, want %u\n", got, want_set);
		bad = 1;
	}
	if (gotf != want_final) {
		printf("     F bit is %u, want %u\n", gotf, want_final);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s D %u F %u\n", name, got, gotf);
	}
	map_reset();
}

/* Dead-man gate: the fast path answers only while the engine's heartbeat is
 * fresh. `hb_ns` is the heartbeat written against the program's own clock;
 * margins are whole seconds. A zero bound and a zero heartbeat must both
 * answer. */
static void case_deadman(const char *name, __u64 bound_ns, __u64 hb_ns,
			 int want_tx)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned char out[FRAME_MAX];
	unsigned int out_len = 0;
	struct frame f;
	unsigned long long held0, held1;
	__u32 zero = 0;
	__u32 tk = BFD_TUNE_DEADMAN_NS;
	int v, want;

	if (tune_fd < 0 || hb_fd < 0) {
		printf("FAIL %-40s no tunables/heartbeat map\n", name);
		fails++;
		return;
	}
	map_reset();
	arm_session();
	bpf_map_update_elem(tune_fd, &tk, &bound_ns, BPF_ANY);
	bpf_map_update_elem(hb_fd, &zero, &hb_ns, BPF_ANY);

	held0 = stat_get(BFD_STAT_DEADMAN_HOLD);
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	v = run_frame(&f, out, &out_len);
	held1 = stat_get(BFD_STAT_DEADMAN_HOLD);

	/* Withholding the reply is XDP_PASS, as for an unconfigured session,
	 * so the counter is the witness. */
	want = want_tx ? XDP_TX : XDP_PASS;
	if (v != want || (held1 - held0) != (unsigned long long)!want_tx) {
		printf("FAIL %-40s want %s hold+%d, got %s hold+%llu\n",
		       name, verdict_str(want), !want_tx,
		       v < 0 ? "syscall-error" : verdict_str(v),
		       held1 - held0);
		fails++;
	} else {
		printf("ok   %-40s %s, hold+%llu\n", name, verdict_str(v),
		       held1 - held0);
	}

	bound_ns = 0;
	hb_ns = 0;
	bpf_map_update_elem(tune_fd, &tk, &bound_ns, BPF_ANY);
	bpf_map_update_elem(hb_fd, &zero, &hb_ns, BPF_ANY);
	map_reset();
}

/* The v6 bounce, the independent check on tx.h's checksum fold. */
static void case_bounce_v6_frame(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned char out[FRAME_MAX];
	unsigned int out_len = 0;
	struct frame f;
	int v;

	map_reset_v6();
	arm_session_v6();
	build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	v = run_frame(&f, out, &out_len);
	if (v != XDP_TX) {
		printf("FAIL %-40s want TX got %s\n", "bounce-v6-frame",
		       v < 0 ? "syscall-error" : verdict_str(v));
		fails++;
		map_reset_v6();
		return;
	}

	const struct ipv6hdr *oi = (const void *)(out + sizeof(struct ethhdr));
	const struct udphdr *ou = (const void *)(oi + 1);
	unsigned int want_len = sizeof(struct ethhdr) + sizeof(*oi) +
				sizeof(*ou) + 24;
	int bad = 0;

	if (out_len != want_len) {
		printf("     frame is %u bytes, want %u\n", out_len, want_len);
		bad = 1;
	}
	if (oi->hop_limit != 255) {
		printf("     hop limit is not 255\n");
		bad = 1;
	}
	if (ntohs(oi->payload_len) != (int)(sizeof(*ou) + 24)) {
		printf("     payload_len not updated\n");
		bad = 1;
	}
	if (ou->check == 0) {
		printf("     UDP checksum is zero, illegal in v6\n");
		bad = 1;
	}
	if (!v6_udp_csum_ok(out, out_len)) {
		printf("     UDP checksum does not verify\n");
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", "bounce-v6-frame");
		fails++;
	} else {
		printf("ok   %-40s %u bytes, csum 0x%04x\n", "bounce-v6-frame",
		       out_len, ntohs(ou->check));
	}
	map_reset_v6();
}

/* A peer frame with more than 24 bytes of BFD must go back out trimmed. The v6
 * arm checks the checksum fold, which runs before the trim. */
static void case_trim(int v6, unsigned int extra)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned char out[FRAME_MAX];
	unsigned int out_len = 0;
	char name[64];
	struct frame f;
	int v, bad = 0;

	snprintf(name, sizeof(name), "trim-%s-plus-%u", v6 ? "v6" : "v4", extra);

	if (v6) {
		map_reset_v6();
		arm_session_v6();
		build_v6(&f, 255, BFD_PORT_1HOP, &p, 0);
	} else {
		map_reset();
		arm_session();
		build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	}

	v = run_frame(&f, out, &out_len);
	if (v != XDP_TX) {
		printf("FAIL %-40s want TX got %s\n", name,
		       v < 0 ? "syscall-error" : verdict_str(v));
		fails++;
		goto out;
	}

	unsigned int l3 = v6 ? sizeof(struct ipv6hdr) : sizeof(struct iphdr);
	unsigned int want_len = sizeof(struct ethhdr) + l3 +
				sizeof(struct udphdr) + 24;
	const struct udphdr *ou =
		(const void *)(out + sizeof(struct ethhdr) + l3);

	if (out_len != want_len) {
		printf("     frame is %u bytes, want %u (not trimmed)\n",
		       out_len, want_len);
		bad = 1;
	}
	if (ntohs(ou->len) != (int)(sizeof(*ou) + 24)) {
		printf("     udp len is %u, want %zu\n", ntohs(ou->len),
		       sizeof(*ou) + 24);
		bad = 1;
	}
	if (v6) {
		const struct ipv6hdr *oi =
			(const void *)(out + sizeof(struct ethhdr));

		if (ntohs(oi->payload_len) != (int)(sizeof(*ou) + 24)) {
			printf("     payload_len is %u, want %zu\n",
			       ntohs(oi->payload_len), sizeof(*ou) + 24);
			bad = 1;
		}
		if (!v6_udp_csum_ok(out, out_len)) {
			printf("     UDP checksum does not verify after trim\n");
			bad = 1;
		}
	} else {
		const struct iphdr *oi =
			(const void *)(out + sizeof(struct ethhdr));

		if (ntohs(oi->tot_len) != (int)(l3 + sizeof(*ou) + 24)) {
			printf("     tot_len is %u, want %zu\n", ntohs(oi->tot_len),
			       l3 + sizeof(*ou) + 24);
			bad = 1;
		}
		if (csum16(oi, sizeof(*oi), 0) != 0) {
			printf("     IP checksum does not verify after trim\n");
			bad = 1;
		}
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s %u bytes\n", name, out_len);
	}
out:
	if (v6)
		map_reset_v6();
	else
		map_reset();
}

/* RFC 5880 s6.8.4 poll termination: the peer's F is acked in final_seq. The
 * guard is cfg->poll && F, so all three arms are reachable. */
static void case_poll_final(uint8_t in_flags, uint32_t cfg_poll,
			    uint32_t poll_seq, uint32_t want_seq,
			    const char *name)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state st = {0};
	struct tx_cfg cfg = {0};
	struct frame f;

	map_reset();

	cfg.enable    = 1;
	cfg.my_disc   = 0x22222222;
	cfg.your_disc = 0x11111111;
	cfg.min_tx_us = 10000;
	cfg.min_rx_us = 10000;
	cfg.state     = ST_UP;
	cfg.mult      = 3;
	cfg.min_ttl   = 255;
	cfg.poll      = cfg_poll;
	cfg.poll_seq  = poll_seq;

	st.remote_state = ST_UP;

	if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) ||
	    bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY)) {
		printf("FAIL %-40s map setup: %s\n", name, strerror(errno));
		fails++;
		return;
	}

	p.flags |= in_flags;
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	run_frame(&f, NULL, NULL);

	struct session_state after = {0};
	if (!read_state(&k, &after)) {
		printf("FAIL %-40s\n", name);
		fails++;
		map_reset();
		return;
	}

	if (after.final_seq != want_seq) {
		printf("     final_seq is %u, want %u\n", after.final_seq,
		       want_seq);
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s final_seq %u\n", name, after.final_seq);
	}
	map_reset();
}

/* Liveness and the RX counter are map-side effects nothing has checked. */
static void case_rx_state(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct bfd_ctrl_pkt p = ctrl_up();
	struct session_state after = {0};
	struct frame f;
	int bad = 0;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);
	run_frame(&f, NULL, NULL);

	if (!read_state(&k, &after)) {
		printf("FAIL %-40s\n", "rx-updates-state");
		fails++;
		map_reset();
		return;
	}

	if (!after.last_seen_ns) {
		printf("     last_seen_ns not set\n");
		bad = 1;
	}
	if (after.rx_pkts != 1) {
		printf("     rx_pkts is %llu, want 1\n",
		       (unsigned long long)after.rx_pkts);
		bad = 1;
	}
	if ((unsigned)after.alive != 1) {
		printf("     alive is %u, want 1\n", (unsigned)after.alive);
		bad = 1;
	}
	if (after.remote_disc != 0x11111111) {
		printf("     remote_disc is %08x\n", after.remote_disc);
		bad = 1;
	}

	if (bad) {
		printf("FAIL %-40s\n", "rx-updates-state");
		fails++;
	} else {
		printf("ok   %-40s rx %llu alive %u\n", "rx-updates-state",
		       (unsigned long long)after.rx_pkts, (unsigned)after.alive);
	}
	map_reset();
}

/* Whatever came in, the reply's envelope says 24 bytes of BFD. */
static void case_bounce_envelope_is_ours(void)
{
	struct bfd_ctrl_pkt p = ctrl_up();
	unsigned char out[256];
	unsigned out_len = 0;
	struct frame f;
	int v, bad = 0;

	map_reset();
	arm_session();
	build_v4(&f, 255, BFD_PORT_1HOP, &p, 0);

	v = run_frame(&f, out, &out_len);
	if (v != XDP_TX) {
		printf("     verdict %s, want TX\n",
		       v < 0 ? "syscall-error" : verdict_str(v));
		bad = 1;
	} else {
		const struct iphdr *oi = (void *)(out + sizeof(struct ethhdr));
		const struct udphdr *ou = (void *)(oi + 1);
		unsigned want_udp = sizeof(*ou) + BFD_MIN_LEN;
		unsigned want_ip = sizeof(*oi) + want_udp;

		if (ntohs(ou->len) != want_udp) {
			printf("     reply udp->len %u, want %u\n",
			       ntohs(ou->len), want_udp);
			bad = 1;
		}
		if (ntohs(oi->tot_len) != want_ip) {
			printf("     reply tot_len %u, want %u\n",
			       ntohs(oi->tot_len), want_ip);
			bad = 1;
		}
		if (out_len != sizeof(struct ethhdr) + want_ip) {
			printf("     reply is %u bytes, want %zu\n",
			       out_len, sizeof(struct ethhdr) + want_ip);
			bad = 1;
		}
	}

	if (bad) {
		printf("FAIL %-40s\n", "bounce-envelope-is-ours");
		fails++;
	} else {
		printf("ok   %-40s lengths rewritten\n",
		       "bounce-envelope-is-ours");
	}
	map_reset();
}
