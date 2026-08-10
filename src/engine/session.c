// SPDX-License-Identifier: GPL-2.0
/* session.c - session table allocation and lookup. */
#define _GNU_SOURCE
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "bfd_shared.h"
#include "bffdp.h"
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
