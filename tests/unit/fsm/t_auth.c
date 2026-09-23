// SPDX-License-Identifier: GPL-2.0
/* Part of fsm_run, split by subject; compiled as one unit via
 * tests/unit/fsm_run.c.
 */

/* End to end on the host: the packet tx_one signs, captured through
 * fsm_send_hook, must pass bfd_auth_check.
 */
static void case_authenticated_output_verifies(void)
{
	static const char key[] = "correcthorsebattery";
	struct session *s;
	__u32 rx_seq = 0;
	int rx_seen = 0;
	int bad = 0;

	s = sess_init(ST_UP);
	s->rdisc = 0x33333333;
	s->r_state = ST_UP;
	s->send_final = 1; /* force one packet out of fsm_tx */
	s->next_tx_us = 0;
	s->auth_present = 1;
	s->auth_type = BFD_AUTH_KEYED_SHA1;
	s->auth_keyid = 5;
	s->auth_keylen = (uint8_t)strlen(key);
	memcpy(s->auth_key, key, strlen(key));
	/* kpad is the key in one SHA1 block, zero past it, which is how
	 * dplane.c hands it over.
	 */
	memset(s->auth_kpad, 0, sizeof(s->auth_kpad));
	memcpy(s->auth_kpad, key, strlen(key));

	sent_calls = 0;
	sent_len = 0;
	memset(sent_buf, 0, sizeof(sent_buf));
	fsm_send_hook = capture_send;
	fsm_tx(s, 2000000);
	fsm_send_hook = NULL;

	if (sent_calls != 1) {
		printf("     %d sends, wanted exactly 1\n", sent_calls);
		report("auth-output-verifies", 1, NULL);
		return;
	}
	if (!(sent_buf[1] & BFD_F_AUTH)) {
		printf("     the A bit is not set on an authenticated session\n");
		bad = 1;
	}
	if (sent_buf[3] != bfd_auth_pkt_len(s->auth_type, s->auth_keylen) ||
	    sent_len != sent_buf[3]) {
		printf("     length %u, datagram %zu, want %u\n", sent_buf[3], sent_len,
		       bfd_auth_pkt_len(s->auth_type, s->auth_keylen));
		bad = 1;
	}
	if (sent_buf[BFD_MIN_LEN + 2] != s->auth_keyid) {
		printf("     section names key id %u, sent under %u\n", sent_buf[BFD_MIN_LEN + 2],
		       s->auth_keyid);
		bad = 1;
	}
	/* The receiver's own predicate, over the bytes that would have
	 * gone out. rx_seen is zero, so this is the first-packet case that
	 * sets the replay window rather than being judged against it.
	 */
	if (bfd_auth_check(sent_buf, sent_buf[3], s->auth_type, s->auth_keyid, s->auth_kpad,
			   s->auth_keylen, s->auth_kpad, &rx_seq, &rx_seen,
			   sent_buf[2]) != BFD_AUTH_OK) {
		printf("     the receiver refused our own signed packet\n");
		bad = 1;
	}
	report("auth-output-verifies", bad, "tx_one signs what rx accepts");

	/* And the same bytes with one digest byte moved must not verify,
	 * or the check above proves nothing.
	 */
	sent_buf[BFD_MIN_LEN + BFD_AUTH_SHA1_DIG_OFF] ^= 0xff;
	rx_seq = 0;
	rx_seen = 0;
	report("auth-output-tamper-refused",
	       bfd_auth_check(sent_buf, sent_buf[3], s->auth_type, s->auth_keyid, s->auth_kpad,
			      s->auth_keylen, s->auth_kpad, &rx_seq, &rx_seen,
			      sent_buf[2]) == BFD_AUTH_OK,
	       "one flipped digest byte");
}

/* A session that must authenticate and has no key it may send under
 * sends nothing at all: a bare packet there is the one thing the peer
 * must reject. The counterpart of the tx_cfg rule in ktx_cfg_run.
 */
static void case_no_sendable_key_sends_nothing(void)
{
	struct session *s = sess_init(ST_UP);

	s->rdisc = 0x33333333;
	s->r_state = ST_UP;
	s->send_final = 1;
	s->next_tx_us = 0;
	s->auth_present = 1;
	s->auth_type = 0; /* nothing sendable right now */

	sent_calls = 0;
	fsm_send_hook = capture_send;
	fsm_tx(s, 2000000);
	fsm_send_hook = NULL;

	report("auth-no-sendable-key-sends-nothing", sent_calls != 0,
	       "silence beats a packet the peer must reject");
}
