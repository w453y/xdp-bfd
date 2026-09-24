// SPDX-License-Identifier: GPL-2.0
/* static.c - one session from the command line, without bfdd. \see static.h */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "bfd_shared.h"
#include "bfd_auth.h"
#include "util.h"
#include "log.h"
#include "session.h"
#include "ktx.h"
#include "static.h"

/* --auth <type>:<keyid>:<key>, a key without lifetime. */
static int static_auth_apply(struct session *s, const char *spec)
{
	const char *c1 = strchr(spec, ':');
	const char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
	struct auth_key *k = &s->auth_keys[0];
	char type[24];
	unsigned long keyid;
	size_t tlen, klen;

	if (!c1 || !c2 || c1 == spec) {
		log_err("--auth wants <type>:<keyid>:<key>\n");
		return -1;
	}
	tlen = (size_t)(c1 - spec);
	if (tlen >= sizeof(type)) {
		log_err("--auth: unknown type\n");
		return -1;
	}
	memcpy(type, spec, tlen);
	type[tlen] = 0;

	memset(s->auth_keys, 0, sizeof(s->auth_keys));
	if (!strcmp(type, "simple"))
		k->type = BFD_AUTH_SIMPLE;
	else if (!strcmp(type, "keyed-sha1"))
		k->type = BFD_AUTH_KEYED_SHA1;
	else if (!strcmp(type, "meticulous-sha1"))
		k->type = BFD_AUTH_METICULOUS_SHA1;
	else {
		log_err("--auth: type must be simple, keyed-sha1 or meticulous-sha1\n");
		return -1;
	}

	keyid = strtoul(c1 + 1, NULL, 0);
	if (keyid > 255) {
		log_err("--auth: key id %lu is out of range\n", keyid);
		return -1;
	}
	klen = strlen(c2 + 1);
	if (!klen || klen > sizeof(k->kpad) ||
	    (k->type == BFD_AUTH_SIMPLE && klen > BFD_AUTH_SIMPLE_MAXKEY)) {
		log_err("--auth: key length %zu is unusable for this type\n", klen);
		return -1;
	}

	k->key_id = (uint8_t)keyid;
	k->keylen = (uint8_t)klen;
	memcpy(k->kpad, c2 + 1, klen);

	s->auth_present = 1;
	s->auth_nkeys = 1;
	auth_seq_seed(s, (uint32_t)random());
	/* As the dplane path does when keys arrive. */
	session_auth_evaluate(s, (int64_t)time(NULL));
	if (!s->auth_type) {
		log_err("--auth: no key is sendable, nothing would go out\n");
		return -1;
	}
	return 0;
}

/* A colon means v6; both must be one family. */
static int static_addrs(struct session *s, const char *local, const char *peer)
{
	int fam = strchr(local, ':') ? AF_INET6 : AF_INET;

	if ((strchr(peer, ':') != NULL) != (fam == AF_INET6)) {
		log_err("static: %s and %s are different families\n", local, peer);
		return -1;
	}
	if (fam == AF_INET6) {
		struct in6_addr l6, p6;

		if (inet_pton(AF_INET6, local, &l6) != 1 || inet_pton(AF_INET6, peer, &p6) != 1) {
			log_err("static: bad IPv6 address\n");
			return -1;
		}
		key_set_v6(&s->local, &l6);
		key_set_v6(&s->peer, &p6);
	} else {
		uint32_t l4, p4;

		if (inet_pton(AF_INET, local, &l4) != 1 || inet_pton(AF_INET, peer, &p4) != 1) {
			log_err("static: bad IPv4 address\n");
			return -1;
		}
		key_set_v4(&s->local, l4);
		key_set_v4(&s->peer, p4);
	}
	s->family = fam;
	return 0;
}

int static_session_add(const struct opts *o)
{
	struct session *s = sess_alloc();

	if (static_addrs(s, o->local, o->peer))
		return -1;
	s->lid = (random() & 0x7fffffff) | 1;
	s->wire_disc = s->lid;
	sess_reindex(s);
	s->min_tx_us = DEF_MIN_TX;
	s->applied_tx_us = DEF_MIN_TX;
	s->min_rx_us = DEF_MIN_RX;
	s->detect_mult = DEF_MULT;
	s->state = ST_DOWN;
	s->demand = o->demand;
	s->pushed_valid = 0;
	s->next_tx_us = now_us();
	if (o->auth && static_auth_apply(s, o->auth))
		return -1;
	log_info("bfd_tx: static session lid=%u %s -> %s%s\n", s->lid, o->local, o->peer,
		 use_ktx ? " (kernel-tx)" : "");
	return 0;
}
