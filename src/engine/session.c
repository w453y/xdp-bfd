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

/* ---------- session table ---------- */
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
	if (!lid)
		return NULL;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].lid == lid)
			return &sessions[i];
	return NULL;
}

struct session *sess_by_wire(uint32_t disc)
{
	if (!disc)
		return NULL;
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used && sessions[i].wire_disc == disc)
			return &sessions[i];
	return NULL;
}

void sm_addrs(const struct bfddp_session_msg *sm,
		     struct bfd_addr *l, struct bfd_addr *p, int *family)
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

struct session *sess_by_addr_pair_local(
	const struct bfddp_session_msg *sm)
{
	struct bfd_addr l, p;
	int fam;
	sm_addrs(sm, &l, &p, &fam);
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used &&
		    !memcmp(&sessions[i].local, &l, 16) &&
		    !memcmp(&sessions[i].peer, &p, 16))
			return &sessions[i];
	return NULL;
}

struct session *sess_by_addr(const struct bfd_addr *peer,
				    const struct bfd_addr *local)
{
	for (int i = 0; i < MAX_SESSIONS; i++)
		if (sessions[i].used &&
		    !memcmp(&sessions[i].peer, peer, 16) &&
		    !memcmp(&sessions[i].local, local, 16))
			return &sessions[i];
	return NULL;
}

/* Consider a boundary for the soonest one still ahead of us. */
static void auth_note_boundary(int64_t at, int64_t now, int64_t *soonest)
{
	/* Zero means "always", -1 means "never expires": neither is an
	 * instant at which anything changes. */
	if (at <= 0 || at <= now)
		return;
	if (*soonest == 0 || at < *soonest)
		*soonest = at;
}

/* Pick the key to transmit with, and work out when that choice could
 * next change.
 *
 * The control plane sends every key the chain holds and leaves the
 * choosing here, because a rollover happens on a clock rather than on a
 * configuration change and only this side sees the packets.
 *
 * Returns non-zero when the transmit key changed, so the caller knows
 * the fast path is holding a stale one.
 */
int session_auth_evaluate(struct session *s, int64_t now)
{
	uint8_t type = 0, key_id = 0, keylen = 0;
	const struct auth_key *chosen = NULL;
	int64_t soonest = 0;
	unsigned i;
	int changed;

	for (i = 0; i < s->auth_nkeys; i++) {
		const struct auth_key *k = &s->auth_keys[i];

		auth_note_boundary(k->send_start, now, &soonest);
		auth_note_boundary(k->send_end, now, &soonest);
		auth_note_boundary(k->accept_start, now, &soonest);
		auth_note_boundary(k->accept_end, now, &soonest);

		/* First match wins, which is the order the chain was sent
		 * in and so the same key the control plane would pick. */
		if (chosen == NULL && s->auth_present &&
		    auth_key_sendable(k, now))
			chosen = k;
	}

	if (chosen) {
		type = chosen->type;
		key_id = chosen->key_id;
		keylen = chosen->keylen;
	}

	changed = (type != s->auth_type || key_id != s->auth_keyid ||
		   keylen != s->auth_keylen ||
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
	}

	s->auth_next_change = soonest;
	return changed;
}

/* The key a received packet says it was signed with, or NULL.
 *
 * Looked up across everything still acceptable rather than compared
 * against the key being transmitted with: during a rollover the peer is
 * still sending under the old key, and refusing it is exactly the
 * breakage the lifetimes exist to avoid.
 */
const struct auth_key *session_auth_key_for(const struct session *s,
					    uint8_t key_id, int64_t now)
{
	unsigned i;

	if (!s->auth_present)
		return NULL;

	for (i = 0; i < s->auth_nkeys; i++) {
		const struct auth_key *k = &s->auth_keys[i];

		if (k->key_id == key_id && auth_key_acceptable(k, now))
			return k;
	}
	return NULL;
}
