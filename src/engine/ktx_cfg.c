// SPDX-License-Identifier: GPL-2.0
/* ktx_cfg.c - the tx_cfg a session maps to; pure, so ktx_cfg_run.c drives it. */
#define _GNU_SOURCE
#include <string.h>

#include "bfd_shared.h"
#include "session.h"
#include "ktx.h"

/* now is wall-clock seconds, for key lifetimes. */
void ktx_cfg_for(const struct session *s, int64_t now, struct tx_cfg *c, struct session_key *k)
{
	/* Disarmed while the peer demands (s6.8.7); userspace answers Polls. */
	*c = (struct tx_cfg){
		.echo_iv_us = echo_interval(s),
		.min_echo_rx_us = s->min_echo_rx_us,
		.min_ttl = s->min_ttl,
		.auth_type = auth_fast_capable(s) ? s->auth_type : 0,
		.auth_keyid = s->auth_keyid,
		.auth_keylen = s->auth_keylen,
		.auth_present = s->auth_present,
		.enable = ktx_answers(s),
		.demand = demand_bit_out(s),
		.demand_hold = demand_sweep_held(s),
		.my_disc = s->wire_disc,
		.your_disc = s->rdisc,
		.min_tx_us = s->min_tx_us,
		.min_rx_us = s->min_rx_us,
		.src_port = (__u16)(SRC_PORT + (s - sessions)),
		.state = s->state,
		.diag = s->diag,
		.mult = s->detect_mult,
		.poll = (s->polling && s->state == ST_UP) ? 1 : 0,
		.poll_seq = s->poll_seq,
	};
	memcpy(c->auth_kpad, s->auth_kpad, sizeof(c->auth_kpad));

	/* Lifetimes are wall-clock, which the program cannot read. */
	{
		unsigned int i;

		for (i = 0; i < s->auth_nkeys && c->auth_nkeys < BFD_AUTH_ACCEPT_MAX; i++) {
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

	k->peer = s->peer;
	k->local = s->local;
}
