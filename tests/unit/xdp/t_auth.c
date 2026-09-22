// SPDX-License-Identifier: GPL-2.0
/* Part of xdp_run, split by subject; compiled as one unit via
 * tests/unit/xdp_run.c.
 */

/* A session that must authenticate but has no key it may send under, as with a
 * gap in send lifetimes or keys not yet arrived. Packets the accept set can
 * verify must still be accepted.
 */
static void case_auth_present_without_send_key(void)
{
	const char *name = "auth-accepted-with-no-send-key";
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct tx_cfg cfg;
	struct frame f;
	unsigned long long mism;
	int v;

	map_reset();
	arm_session_auth(BFD_AUTH_KEYED_SHA1, 7, "topsecret");

	/* Exactly the state above: the accept set is untouched, the send key
	 * is gone, and the session still has to authenticate.
	 */
	if (bpf_map_lookup_elem(cfg_fd, &k, &cfg)) {
		printf("FAIL %-40s no cfg\n", name);
		fails++;
		return;
	}
	cfg.auth_type = 0;
	cfg.auth_keyid = 0;
	cfg.auth_keylen = 0;
	cfg.auth_present = 1;
	bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY);

	mism = stat_get(BFD_STAT_AUTH_MISMATCH);
	build_sha1_auth(&f, "topsecret", 7, 100, BFD_AUTH_KEYED_SHA1);
	v = run_frame(&f, NULL, NULL);

	/* PASS, not TX: with no send key the fast path must not answer
	 * either, or it bounces a bare packet the peer must reject. The
	 * packet still has to reach userspace.
	 */
	if (v != XDP_PASS || stat_get(BFD_STAT_AUTH_MISMATCH) != mism) {
		printf("FAIL %-40s want PASS no-mismatch, got %s mismatch+%llu\n", name,
		       v < 0 ? "syscall-error" : verdict_str(v),
		       stat_get(BFD_STAT_AUTH_MISMATCH) - mism);
		fails++;
	} else {
		printf("ok   %-40s accepted, not an A-bit mismatch\n", name);
	}

	/* The digest is still checked: PASS alone is equally consistent with
	 * skipping verification.
	 */
	name = "auth-verified-with-no-send-key";
	{
		unsigned long long bad = stat_get(BFD_STAT_AUTH_BAD);

		build_sha1_auth(&f, "topsecret", 7, 101, BFD_AUTH_KEYED_SHA1);
		f.b[f.len - 1] ^= 0xff;
		v = run_frame(&f, NULL, NULL);
		if (v != XDP_DROP || stat_get(BFD_STAT_AUTH_BAD) != bad + 1) {
			printf("FAIL %-40s want DROP auth-bad+1, got %s auth-bad+%llu\n", name,
			       v < 0 ? "syscall-error" : verdict_str(v),
			       stat_get(BFD_STAT_AUTH_BAD) - bad);
			fails++;
		} else {
			printf("ok   %-40s corrupt digest still refused\n", name);
		}
	}
	map_reset();
}

/* Rejection paths: a keyed-SHA1 packet damaged in exactly one way
 * (digest, sequence, key id) must be refused without touching the
 * session.
 */
static void case_auth_reject(const char *name, __u8 type, const char *key, __u8 keyid, __u32 seq,
			     int corrupt_digest, __u32 pre_seq, int want_accept)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct session_state st;
	struct frame f;
	unsigned long long before;
	int v, bad = 0;

	map_reset();
	arm_session_auth(type, 7, "topsecret");

	/* A window the case can replay into. */
	if (pre_seq) {
		if (bpf_map_lookup_elem(sess_fd, &k, &st)) {
			printf("FAIL %-40s no state\n", name);
			fails++;
			return;
		}
		st.auth_rx_seq = pre_seq;
		st.auth_rx_seen = 1;
		bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY);
	}

	build_sha1_auth(&f, key, keyid, seq, type);
	if (corrupt_digest)
		f.b[f.len - 1] ^= 0xff;

	before = stat_get(BFD_STAT_AUTH_BAD);
	v = run_frame(&f, NULL, NULL);

	if (want_accept) {
		if (v != XDP_TX) {
			printf("     verdict %s, want TX\n",
			       v < 0 ? "syscall-error" : verdict_str(v));
			bad = 1;
		}
	} else {
		if (v != XDP_DROP) {
			printf("     verdict %s, want DROP\n",
			       v < 0 ? "syscall-error" : verdict_str(v));
			bad = 1;
		}
		if (stat_get(BFD_STAT_AUTH_BAD) != before + 1) {
			printf("     auth-bad did not move\n");
			bad = 1;
		}
		/* A refused packet must leave no trace of having arrived. */
		if (!bpf_map_lookup_elem(sess_fd, &k, &st) && st.rx_pkts) {
			printf("     rx_pkts moved on a refused packet\n");
			bad = 1;
		}
	}

	if (bad) {
		printf("FAIL %-40s\n", name);
		fails++;
	} else {
		printf("ok   %-40s %s\n", name, want_accept ? "accepted" : "DROP, no state write");
	}
	map_reset();
}

/* The shared HMAC-SHA1 in the kernel, on the vectors hmac_run checks on the
 * host.
 */
struct hmac_scratch_u {
	__u8 kpad[SHA1_BLOCK_LEN];
	__u8 mblk[SHA1_BLOCK_LEN];
	__u8 out[SHA1_DIGEST_LEN];
	__u32 msglen;
	__u32 ok;
};

static void case_hmac(const struct hmac_vec *v)
{
	struct hmac_scratch_u sc = { 0 };
	unsigned char in[64] = { 0 }, out[64] = { 0 };
	__u32 zero = 0;

	if (hmac_prog_fd < 0) {
		printf("FAIL %-40s no hmac program\n", v->name);
		fails++;
		return;
	}

	memcpy(sc.kpad, v->key, v->keylen);
	memcpy(sc.mblk, v->msg, v->msglen);
	sc.msglen = v->msglen;
	if (bpf_map_update_elem(hmac_map_fd, &zero, &sc, BPF_ANY)) {
		printf("FAIL %-40s scratch put\n", v->name);
		fails++;
		return;
	}

	LIBBPF_OPTS(bpf_test_run_opts, topts, .data_in = in, .data_size_in = sizeof(in),
		    .data_out = out, .data_size_out = sizeof(out), .repeat = 1);
	if (bpf_prog_test_run_opts(hmac_prog_fd, &topts) ||
	    bpf_map_lookup_elem(hmac_map_fd, &zero, &sc)) {
		printf("FAIL %-40s test_run\n", v->name);
		fails++;
		return;
	}
	if (!sc.ok) {
		printf("FAIL %-40s kernel refused key %u msg %u\n", v->name, v->keylen, v->msglen);
		fails++;
		return;
	}
	if (memcmp(sc.out, v->want, SHA1_DIGEST_LEN)) {
		printf("     want ");
		for (int i = 0; i < SHA1_DIGEST_LEN; i++)
			printf("%02x", v->want[i]);
		printf("\n     got  ");
		for (int i = 0; i < SHA1_DIGEST_LEN; i++)
			printf("%02x", sc.out[i]);
		printf("\n");
		printf("FAIL %-40s\n", v->name);
		fails++;
		return;
	}
	printf("ok   %-40s key %2u msg %2u\n", v->name, v->keylen, v->msglen);
}

/* Bound the forced HMAC: of more than BFD_AUTH_FAIL_MAX bad digests in one
 * interval, the first BFD_AUTH_FAIL_MAX fail (auth-bad) and the rest are
 * dropped before the digest (auth-ratelimited).
 */
static void case_auth_ratelimit(void)
{
	struct session_key k = key_v4("10.0.0.2", "10.0.0.1");
	struct session_state st;
	struct frame f;
	unsigned long long b0, b1, r0, r1;
	int bad = 0, v;

	map_reset();
	arm_session_auth(BFD_AUTH_KEYED_SHA1, 7, "topsecret");

	/* Pin the window to a second so a dozen test-run syscalls stay
	 * inside one interval.
	 */
	if (bpf_map_lookup_elem(sess_fd, &k, &st)) {
		printf("FAIL auth-ratelimit (no state)\n");
		fails++;
		return;
	}
	st.detect_iv_us = 1000000;
	bpf_map_update_elem(sess_fd, &k, &st, BPF_ANY);

	b0 = stat_get(BFD_STAT_AUTH_BAD);
	r0 = stat_get(BFD_STAT_AUTH_RATELIMITED);

	for (int i = 0; i < BFD_AUTH_FAIL_MAX + 4; i++) {
		build_sha1_auth(&f, "topsecret", 7, 100 + i, BFD_AUTH_KEYED_SHA1);
		f.b[f.len - 1] ^= 0xff; /* corrupt the digest */
		v = run_frame(&f, NULL, NULL);
		if (v != XDP_DROP) {
			printf("     packet %d verdict %s, want DROP\n", i,
			       v < 0 ? "syscall-error" : verdict_str(v));
			bad = 1;
		}
	}
	b1 = stat_get(BFD_STAT_AUTH_BAD);
	r1 = stat_get(BFD_STAT_AUTH_RATELIMITED);

	if (b1 - b0 != BFD_AUTH_FAIL_MAX) {
		printf("     auth-bad +%llu, want +%d\n", b1 - b0, BFD_AUTH_FAIL_MAX);
		bad = 1;
	}
	if (r1 - r0 != 4) {
		printf("     auth-ratelimited +%llu, want +4\n", r1 - r0);
		bad = 1;
	}
	if (bad) {
		printf("FAIL auth-ratelimit-bounds-digest\n");
		fails++;
	} else
		printf("ok   %-40s %d digests then rate-limited\n", "auth-ratelimit-bounds-digest",
		       BFD_AUTH_FAIL_MAX);
	map_reset();
}
