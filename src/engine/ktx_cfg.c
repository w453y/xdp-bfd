// SPDX-License-Identifier: GPL-2.0
/* ktx_cfg.c - what the fast path is told about a session.
 *
 * Everything ktx_mirror does before the map write is a pure function of
 * struct session and the clock: which discriminators and intervals the
 * program transmits under, whether it answers at all, whether the demand
 * bits go out, and which authentication keys are acceptable right now.
 * One of the last round's findings lived in that derivation, and reaching
 * it needed a loaded program and a live map.
 *
 * Split out so it can be driven directly (tests/unit/ktx_cfg_run.c). No
 * libbpf here: the map write stays in ktx.c.
 */
#define _GNU_SOURCE
#include <string.h>

#include "bfd_shared.h"
#include "session.h"
#include "ktx.h"

/* Derive the program's view of this session: `c` is what tx_config
 * carries and `k` the address pair it is keyed on. `now` is seconds, the
 * clock the key lifetimes are judged against, passed in so the caller
 * owns it and a test can sit on either side of a boundary. */
void ktx_cfg_for(const struct session *s, int64_t now, struct tx_cfg *c,
		 struct session_key *k)
{
	/* RX-clocked TX answers every accepted packet, so leaving it armed
	 * while the peer is demanding would transmit at exactly the pace
	 * s6.8.7 says to stop - the peer's. Disarming hands those frames to
	 * userspace instead, which still answers a Poll with a Final and
	 * stays silent otherwise. Polls are rare and the session is idle by
	 * construction, so the slow path is the right place for them. */
	*c = (struct tx_cfg){
		.echo_iv_us = s->echo_tx_us,
		.min_echo_rx_us = s->min_echo_rx_us,
		.min_ttl   = s->min_ttl,
		.auth_type = auth_fast_capable(s) ? s->auth_type : 0,
		.auth_keyid = s->auth_keyid,
		.auth_keylen = s->auth_keylen,
		.auth_present = s->auth_present,
		.enable    = ktx_answers(s),
		.demand      = demand_bit_out(s),
		.demand_hold = demand_sweep_held(s),
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
	memcpy(c->auth_kpad, s->auth_kpad, sizeof(c->auth_kpad));

	/* Leave the program every key a packet may currently be signed
	 * with, not just the one we transmit under. The lifetimes are
	 * evaluated here because the program has no clock: it can compare
	 * a key id, it cannot decide whether a period has passed. */
	{
		unsigned i;

		for (i = 0; i < s->auth_nkeys && c->auth_nkeys < BFD_AUTH_ACCEPT_MAX;
		     i++) {
			const struct auth_key *ak = &s->auth_keys[i];

			if (!s->auth_present || !auth_key_acceptable(ak, now))
				continue;

			c->auth_accept[c->auth_nkeys].type = ak->type;
			c->auth_accept[c->auth_nkeys].key_id = ak->key_id;
			c->auth_accept[c->auth_nkeys].keylen = ak->keylen;
			memcpy(c->auth_accept[c->auth_nkeys].kpad, ak->kpad,
			       sizeof(c->auth_accept[0].kpad));
			c->auth_nkeys++;
		}
	}

	*k = (struct session_key){};

	k->peer  = s->peer;
	k->local = s->local;
}
