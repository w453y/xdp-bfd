// SPDX-License-Identifier: GPL-2.0
/* ktx_cfg_run.c - what the fast path is told about a session.
 *
 * ktx_mirror derives a tx_cfg and a session_key from a session and the
 * clock, then writes them to a map. Everything before the write is
 * ktx_cfg_for, and this drives it directly: no program loaded, no map,
 * no root. One of the last round's findings lived in that derivation
 * (a session that must authenticate but has nothing to sign with was
 * still told to answer), and reaching it needed the whole kernel rig.
 *
 * The clock is a parameter, so the key-lifetime rows can sit on either
 * side of a boundary without waiting for one.
 *
 *     make test-ktxcfg
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "bfd_shared.h"
#include "session.h"
#include "ktx.h"

/* ktx_cfg_for indexes the session table to derive the source port. */
struct session sessions[MAX_SESSIONS];

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

#define NOW 1000000   /* an arbitrary fixed second */

/* A plain Up session the fast path would answer for. */
static struct session *arm(void)
{
	struct session *s = &sessions[0];

	memset(sessions, 0, sizeof(sessions));
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
	       memcmp(&k.local, &s->local, sizeof(k.local)), "peer and local");
	report("discriminators-mirrored",
	       c.my_disc != s->wire_disc || c.your_disc != s->rdisc,
	       "my_disc from wire_disc, your_disc from rdisc");
	report("intervals-mirrored",
	       c.min_tx_us != s->min_tx_us || c.min_rx_us != s->min_rx_us ||
	       c.mult != s->detect_mult || c.min_ttl != s->min_ttl, "");

	/* --- enable: exactly ktx_answers --- */
	report("enable-up-unauthenticated", c.enable != 1,
	       "an Up session the program can answer for");

	s = arm();
	s->state = ST_DOWN;
	ktx_cfg_for(s, NOW, &c, &k);
	report("enable-off-when-down", c.enable != 0, "");

	/* A peer that asked us to go quiet: answering every accepted packet
	 * would transmit at exactly the rate demand mode exists to stop. */
	s = arm();
	s->r_flags = BFD_F_DEMAND;
	s->demand_announced = DEMAND_ANNOUNCE_N;
	ktx_cfg_for(s, NOW, &c, &k);
	report("enable-off-while-peer-demands", c.enable != 0,
	       "RX-clocked TX disarmed for a demanding peer");

	/* A peer advertising Required Min RX of zero has asked for silence
	 * in the other spelling. */
	s = arm();
	s->r_min_rx = 0;
	s->last_rx_us = 1;
	ktx_cfg_for(s, NOW, &c, &k);
	report("enable-off-on-zero-min-rx", c.enable != 0, "");

	/* --- auth_present versus auth_type: the finding --- */
	s = arm();
	s->auth_present = 1;
	s->auth_type = 0;          /* must authenticate, nothing to sign with */
	ktx_cfg_for(s, NOW, &c, &k);
	report("auth-required-without-a-key-disarms",
	       c.enable != 0 || c.auth_type != 0,
	       "no key to sign with: the program must not answer");

	s = arm();
	s->auth_present = 1;
	s->auth_type = BFD_AUTH_KEYED_SHA1;
	s->auth_keyid = 3;
	s->auth_keylen = 8;
	ktx_cfg_for(s, NOW, &c, &k);
	report("auth-usable-is-carried",
	       c.enable != 1 || c.auth_type != BFD_AUTH_KEYED_SHA1 ||
	       c.auth_keyid != 3, "keyed sha1 rides the fast path");

	/* --- the accept list at a lifetime boundary --- */
	s = arm();
	s->auth_present = 1;
	s->auth_type = BFD_AUTH_KEYED_SHA1;
	s->auth_nkeys = 2;
	s->auth_keys[0].type = BFD_AUTH_KEYED_SHA1;
	s->auth_keys[0].key_id = 1;
	s->auth_keys[0].keylen = 4;
	s->auth_keys[0].accept_start = 1;
	s->auth_keys[0].accept_end = NOW - 1;          /* expired */
	s->auth_keys[1].type = BFD_AUTH_KEYED_SHA1;
	s->auth_keys[1].key_id = 2;
	s->auth_keys[1].keylen = 4;
	s->auth_keys[1].accept_start = NOW + 100;      /* not open yet */
	s->auth_keys[1].accept_end = -1;

	ktx_cfg_for(s, NOW, &c, &k);
	report("accept-list-excludes-closed-keys", c.auth_nkeys != 0,
	       "one expired, one not yet open");

	ktx_cfg_for(s, NOW - 10, &c, &k);
	report("accept-list-before-the-boundary",
	       c.auth_nkeys != 1 || c.auth_accept[0].key_id != 1,
	       "only the key whose period is open");

	ktx_cfg_for(s, NOW + 200, &c, &k);
	report("accept-list-after-the-boundary",
	       c.auth_nkeys != 1 || c.auth_accept[0].key_id != 2,
	       "the rollover key, once its period opens");

	/* A session that does not authenticate hands over no keys at all,
	 * whatever a stale key chain left behind. */
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
	report("demand-bits-need-the-peer-up", c.demand || c.demand_hold,
	       "");

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
	report("poll-not-carried-while-down", c.poll != 0,
	       "a Poll belongs to an Up session");

	printf("\n%d failure(s)\n", fails);
	return fails ? 1 : 0;
}
