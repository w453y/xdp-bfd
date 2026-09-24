// SPDX-License-Identifier: GPL-2.0
/* ktx_cfg_run.c - ktx_cfg_for driven directly; the clock is a parameter, so
 * lifetime rows sit either side of a boundary.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "bfd_shared.h"
#include "session.h"
#include "ktx.h"

/* ktx_cfg_for indexes the session table to derive the source port. */
static struct session table[BFD_MAX_SESSIONS];
struct session *sessions = table;
int sess_max = BFD_MAX_SESSIONS;

static int fails;

static void report(const char *name, int bad, const char *detail)
{
	if (bad) {
		printf("FAIL %-44s %s\n", name, detail ? detail : "");
		fails++;
	} else {
		printf("ok   %-44s %s\n", name, detail ? detail : "");
	}
}

#define NOW 1000000 /* an arbitrary fixed second */

/* A plain Up session the fast path would answer for. */
static struct session *arm(void)
{
	struct session *s = &sessions[0];

	memset(sessions, 0, (size_t)sess_max * sizeof(*sessions));
	s->used = 1;
	s->lid = 7;
	s->wire_disc = 0xaabbccdd;
	s->rdisc = 0x11223344;
	s->state = ST_UP;
	s->r_state = ST_UP;
	s->detect_mult = 3;
	s->min_tx_us = 50000;
	s->min_rx_us = 50000;
	s->r_min_rx = 50000;
	s->min_ttl = 255;
	key_set_v4(&s->peer, inet_addr("10.0.0.2"));
	key_set_v4(&s->local, inet_addr("10.0.0.1"));
	return s;
}

int main(void)
{
	struct tx_cfg c;
	struct session_key k;
	struct session *s;

	/* --- the key and the identifiers --- */
	s = arm();
	ktx_cfg_for(s, NOW, &c, &k);
	report("key-is-the-address-pair",
	       memcmp(&k.peer, &s->peer, sizeof(k.peer)) ||
		       memcmp(&k.local, &s->local, sizeof(k.local)),
	       "peer and local");
	report("discriminators-mirrored", c.my_disc != s->wire_disc || c.your_disc != s->rdisc,
	       "my_disc from wire_disc, your_disc from rdisc");
	report("intervals-mirrored",
	       c.min_tx_us != s->min_tx_us || c.min_rx_us != s->min_rx_us ||
		       c.mult != s->detect_mult || c.min_ttl != s->min_ttl,
	       "");

	report("key-carried-in-cfg", memcmp(&c.key, &k, sizeof(k)), "checked by the program");
	report("port-before-first-send", c.src_port != SRC_PORT || c.slot != 0, "the slot's own");

	s = &sessions[5];
	*s = sessions[0];
	s->tx_port = SRC_PORT - 2;
	ktx_cfg_for(s, NOW, &c, &k);
	report("port-follows-userspace", c.src_port != SRC_PORT - 2 || c.slot != 5,
	       "the port sent from; slot 5 kept for auth_seq");
	s = arm();
	ktx_cfg_for(s, NOW, &c, &k);

	report("echo-budget-for",
	       echo_budget_for(50000) != 24 || echo_budget_for(10000) != 56 ||
		       echo_budget_for(1000) != 56 || echo_budget_for(1000000) != 20,
	       "four times the RFC rate plus 16, 10ms floor");

	/* --- enable: exactly ktx_answers --- */
	report("enable-up-unauthenticated", c.enable != 1,
	       "an Up session the program can answer for");

	s = arm();
	s->state = ST_DOWN;
	ktx_cfg_for(s, NOW, &c, &k);
	report("enable-off-when-down", c.enable != 0, "");

	/* Answering every packet would transmit at the rate demand mode exists to stop. */
	s = arm();
	s->r_flags = BFD_F_DEMAND;
	s->demand_announced = DEMAND_ANNOUNCE_N;
	ktx_cfg_for(s, NOW, &c, &k);
	report("enable-off-while-peer-demands", c.enable != 0,
	       "RX-clocked TX disarmed for a demanding peer");

	/* Required Min RX zero is the other way to ask for silence. */
	s = arm();
	s->r_min_rx = 0;
	s->last_rx_us = 1;
	ktx_cfg_for(s, NOW, &c, &k);
	report("enable-off-on-zero-min-rx", c.enable != 0, "");

	/* --- auth_present versus auth_type --- */
	s = arm();
	s->auth_present = 1;
	s->auth_type = 0; /* must authenticate, nothing to sign with */
	ktx_cfg_for(s, NOW, &c, &k);
	report("auth-required-without-a-key-disarms", c.enable != 0 || c.auth_type != 0,
	       "no key to sign with: the program must not answer");

	s = arm();
	s->auth_present = 1;
	s->auth_type = BFD_AUTH_KEYED_SHA1;
	s->auth_keyid = 3;
	s->auth_keylen = 8;
	ktx_cfg_for(s, NOW, &c, &k);
	report("auth-usable-is-carried",
	       c.enable != 1 || c.auth_type != BFD_AUTH_KEYED_SHA1 || c.auth_keyid != 3,
	       "keyed sha1 rides the fast path");

	/* --- the accept list at a lifetime boundary --- */
	s = arm();
	s->auth_present = 1;
	s->auth_type = BFD_AUTH_KEYED_SHA1;
	s->auth_nkeys = 2;
	s->auth_keys[0].type = BFD_AUTH_KEYED_SHA1;
	s->auth_keys[0].key_id = 1;
	s->auth_keys[0].keylen = 4;
	s->auth_keys[0].accept_start = 1;
	s->auth_keys[0].accept_end = NOW - 1; /* expired */
	s->auth_keys[1].type = BFD_AUTH_KEYED_SHA1;
	s->auth_keys[1].key_id = 2;
	s->auth_keys[1].keylen = 4;
	s->auth_keys[1].accept_start = NOW + 100; /* not open yet */
	s->auth_keys[1].accept_end = -1;

	ktx_cfg_for(s, NOW, &c, &k);
	report("accept-list-excludes-closed-keys", c.auth_nkeys != 0,
	       "one expired, one not yet open");

	ktx_cfg_for(s, NOW - 10, &c, &k);
	report("accept-list-before-the-boundary", c.auth_nkeys != 1 || c.auth_accept[0].key_id != 1,
	       "only the key whose period is open");

	ktx_cfg_for(s, NOW + 200, &c, &k);
	report("accept-list-after-the-boundary", c.auth_nkeys != 1 || c.auth_accept[0].key_id != 2,
	       "the rollover key, once its period opens");

	/* Whatever a stale chain left behind. */
	s->auth_present = 0;
	ktx_cfg_for(s, NOW - 10, &c, &k);
	report("accept-list-empty-without-auth", c.auth_nkeys != 0, "");

	/* --- demand bits and poll --- */
	s = arm();
	s->demand = 1;
	ktx_cfg_for(s, NOW, &c, &k);
	report("demand-bits-when-both-ends-up", !c.demand || !c.demand_hold,
	       "D bit and sweep hold need both ends Up");

	s = arm();
	s->demand = 1;
	s->r_state = ST_DOWN;
	ktx_cfg_for(s, NOW, &c, &k);
	report("demand-bits-need-the-peer-up", c.demand || c.demand_hold, "");

	s = arm();
	s->polling = 1;
	s->poll_seq = 9;
	ktx_cfg_for(s, NOW, &c, &k);
	report("poll-carried-while-up", !c.poll || c.poll_seq != 9, "");

	s = arm();
	s->polling = 1;
	s->poll_seq = 9;
	s->state = ST_DOWN;
	ktx_cfg_for(s, NOW, &c, &k);
	report("poll-not-carried-while-down", c.poll != 0, "a Poll belongs to an Up session");

	/* --- rate (RFC 5880 s6.8.7): replies go at the peer's pace --- */
	s = arm();
	s->min_tx_us = 300000;
	s->applied_tx_us = 300000;
	s->min_rx_us = 100000;
	s->r_min_tx = 100000;
	s->r_min_rx = 100000;
	ktx_cfg_for(s, NOW, &c, &k);
	report("enable-off-when-peer-outpaces-us", c.enable != 0,
	       "peer every 100ms, we may send every 300ms");

	s = arm();
	s->min_tx_us = 100000;
	s->applied_tx_us = 100000;
	s->min_rx_us = 300000;
	s->r_min_tx = 100000;
	s->r_min_rx = 100000;
	ktx_cfg_for(s, NOW, &c, &k);
	report("enable-on-when-peer-is-slower", c.enable != 1, "peer every 300ms, ours 100ms");

	/* --- echo (RFC 5880 s6.8.9) --- */
	s = arm();
	s->echo_on = 1;
	s->echo_tx_us = 20000;
	s->r_min_echo = 0;
	ktx_cfg_for(s, NOW, &c, &k);
	report("echo-off-when-peer-refuses", c.echo_iv_us != 0, "peer Required Min Echo RX 0");

	s = arm();
	s->echo_on = 1;
	s->echo_tx_us = 20000;
	s->r_min_echo = 50000;
	ktx_cfg_for(s, NOW, &c, &k);
	report("echo-no-faster-than-peer-asks", c.echo_iv_us != 50000, "max(ours, peer's)");

	s = arm();
	s->echo_on = 1;
	s->echo_tx_us = 20000;
	s->r_min_echo = 10000;
	s->is_mhop = 1;
	s->min_ttl = 250;
	ktx_cfg_for(s, NOW, &c, &k);
	report("echo-never-multihop", c.echo_iv_us != 0, "RFC 5883");

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
