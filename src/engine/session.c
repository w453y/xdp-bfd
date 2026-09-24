// SPDX-License-Identifier: GPL-2.0
/* session.c - session table allocation and lookup. */
#define _GNU_SOURCE
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "bfd_shared.h"
#include "bfddp.h"
#include "session.h"

struct session sessions[MAX_SESSIONS];

/* Lookup caches over the table, one per key, WAYS entries per bucket holding
 * slot + 1. A cache: every hit is checked against the session, and a miss
 * falls back to the scan, so a stale or missing entry costs time, never an
 * answer. sess_reindex keeps them warm.
 */
#define IX_BITS 12
#define IX_WAYS 4
#define IX_SIZE (1u << IX_BITS)

enum { IX_LID, IX_WIRE, IX_ADDR, IX_N };

static uint16_t ix[IX_N][IX_SIZE][IX_WAYS];

static uint32_t ix_u32(uint32_t v)
{
	return (v * 0x9e3779b1u) >> (32 - IX_BITS);
}

/* murmur3's finalizer, so every input bit reaches the bucket bits. */
static uint64_t ix_mix(uint64_t h)
{
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdull;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ull;
	return h ^ (h >> 33);
}

static uint32_t ix_pair(const struct bfd_addr *peer, const struct bfd_addr *local)
{
	uint64_t w[4], h = 0;

	memcpy(w, peer->b, 16);
	memcpy(w + 2, local->b, 16);
	for (int i = 0; i < 4; i++)
		h = ix_mix(h ^ w[i]);
	return ix_u32((uint32_t)h);
}

static int ix_match(int k, const struct session *s, uint32_t v, const struct bfd_addr *peer,
		    const struct bfd_addr *local)
{
	if (!s->used)
		return 0;
	switch (k) {
	case IX_LID:
		return s->lid == v;
	case IX_WIRE:
		return s->wire_disc == v;
	default:
		return !memcmp(&s->peer, peer, 16) && !memcmp(&s->local, local, 16);
	}
}

static void ix_put(int k, uint32_t h, const struct session *s)
{
	uint16_t *b = ix[k][h];
	uint16_t slot = (uint16_t)(s - sessions + 1);
	int free = -1;

	for (int w = 0; w < IX_WAYS; w++) {
		if (b[w] == slot)
			return;
		if (free < 0 && (!b[w] || !sessions[b[w] - 1].used))
			free = w;
	}
	if (free < 0) {
		/* Full of live entries: the oldest makes room. */
		memmove(b, b + 1, (IX_WAYS - 1) * sizeof(*b));
		free = IX_WAYS - 1;
	}
	b[free] = slot;
}

static struct session *ix_get(int k, uint32_t v, const struct bfd_addr *peer,
			      const struct bfd_addr *local)
{
	uint32_t h = k == IX_ADDR ? ix_pair(peer, local) : ix_u32(v);

	for (int w = 0; w < IX_WAYS; w++) {
		uint16_t e = ix[k][h][w];

		if (e && ix_match(k, &sessions[e - 1], v, peer, local))
			return &sessions[e - 1];
	}
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (ix_match(k, &sessions[i], v, peer, local)) {
			ix_put(k, h, &sessions[i]);
			return &sessions[i];
		}
	return NULL;
}

void sess_reindex(const struct session *s)
{
	if (!s->used)
		return;
	if (s->lid)
		ix_put(IX_LID, ix_u32(s->lid), s);
	if (s->wire_disc)
		ix_put(IX_WIRE, ix_u32(s->wire_disc), s);
	ix_put(IX_ADDR, ix_pair(&s->peer, &s->local), s);
}

struct session *sess_alloc(void)
{
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (!sessions[i].used) {
			memset(&sessions[i], 0, sizeof(sessions[i]));
			sessions[i].used = 1;
			return &sessions[i];
		}
	return NULL;
}

struct session *sess_by_lid(uint32_t lid)
{
	return lid ? ix_get(IX_LID, lid, NULL, NULL) : NULL;
}

struct session *sess_by_wire(uint32_t disc)
{
	return disc ? ix_get(IX_WIRE, disc, NULL, NULL) : NULL;
}

void sm_addrs(const struct bfddp_session_msg *sm, struct bfd_addr *l, struct bfd_addr *p,
	      int *family)
{
	if (ntohl(sm->flags) & SESSION_IPV6) {
		memcpy(l->b, &sm->src, 16);
		memcpy(p->b, &sm->dst, 16);
		*family = AF_INET6;
	} else {
		uint32_t lip, pip;

		memcpy(&lip, &sm->src.s6_addr[0], 4);
		memcpy(&pip, &sm->dst.s6_addr[0], 4);
		key_set_v4(l, lip);
		key_set_v4(p, pip);
		*family = AF_INET;
	}
}

struct session *sess_by_addr_pair_local(const struct bfddp_session_msg *sm)
{
	struct bfd_addr l, p;
	int fam;

	sm_addrs(sm, &l, &p, &fam);
	return sess_by_addr(&p, &l);
}

struct session *sess_by_addr(const struct bfd_addr *peer, const struct bfd_addr *local)
{
	return ix_get(IX_ADDR, 0, peer, local);
}

static void auth_note_boundary(int64_t at, int64_t now, int64_t *soonest)
{
	/* 0 means always and -1 never: not instants. */
	if (at <= 0 || at <= now)
		return;
	if (*soonest == 0 || at < *soonest)
		*soonest = at;
}

/* Non-zero if the send key changed. */
int session_auth_evaluate(struct session *s, int64_t now)
{
	uint8_t type = 0, key_id = 0, keylen = 0;
	const struct auth_key *chosen = NULL;
	int64_t soonest = 0;
	unsigned int i;
	int changed;

	for (i = 0; i < s->auth_nkeys; i++) {
		const struct auth_key *k = &s->auth_keys[i];

		auth_note_boundary(k->send_start, now, &soonest);
		auth_note_boundary(k->send_end, now, &soonest);
		auth_note_boundary(k->accept_start, now, &soonest);
		auth_note_boundary(k->accept_end, now, &soonest);

		/* First match wins, as bfdd picks. */
		if (chosen == NULL && s->auth_present && auth_key_sendable(k, now))
			chosen = k;
	}

	if (chosen) {
		type = chosen->type;
		key_id = chosen->key_id;
		keylen = chosen->keylen;
	}

	changed = (type != s->auth_type || key_id != s->auth_keyid || keylen != s->auth_keylen ||
		   (keylen && memcmp(s->auth_kpad, chosen->kpad, sizeof(s->auth_kpad))));

	if (changed) {
		memset(s->auth_key, 0, sizeof(s->auth_key));
		memset(s->auth_kpad, 0, sizeof(s->auth_kpad));
		if (chosen) {
			memcpy(s->auth_key, chosen->kpad, keylen);
			memcpy(s->auth_kpad, chosen->kpad, sizeof(s->auth_kpad));
		}
		s->auth_type = type;
		s->auth_keyid = key_id;
		s->auth_keylen = keylen;
		/* The next gap gets its own log line. */
		if (type)
			s->auth_gap_warned = 0;
	}

	s->auth_next_change = soonest;
	return changed;
}

/* Any acceptable key counts, so a rollover does not refuse the peer. */
const struct auth_key *session_auth_key_for(const struct session *s, uint8_t key_id, int64_t now)
{
	unsigned int i;

	if (!s->auth_present)
		return NULL;

	for (i = 0; i < s->auth_nkeys; i++) {
		const struct auth_key *k = &s->auth_keys[i];

		if (k->key_id == key_id && auth_key_acceptable(k, now))
			return k;
	}
	return NULL;
}
