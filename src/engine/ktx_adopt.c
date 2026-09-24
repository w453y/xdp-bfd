// SPDX-License-Identifier: GPL-2.0
/* ktx_adopt.c - after a restart over pinned maps, the sessions the program is
 * still answering for, rebuilt from them and held as orphans until bfdd
 * re-adds them (dp_add_find adopts a live orphan by its address pair).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/bpf.h>

#include "bfd_shared.h"
#include "util.h"
#include "log.h"
#include "session.h"
#include "ktx.h"

static int is_v4(const struct bfd_addr *a)
{
	static const uint8_t pre[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

	return !memcmp(a->b, pre, sizeof(pre));
}

/* The interface holding our address, for echo, which bfdd names in the ADD.
 * One getifaddrs for all: a call costs 0.2ms on a host with 1000 addresses,
 * and the sessions wait for the whole adoption before their first send.
 */
static uint32_t ifindex_of(struct ifaddrs *ifs, const struct bfd_addr *a, int family)
{
	for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
		if (!i->ifa_addr || i->ifa_addr->sa_family != family)
			continue;
		if (family == AF_INET &&
		    !memcmp(&((struct sockaddr_in *)i->ifa_addr)->sin_addr, &a->b[12], 4))
			return if_nametoindex(i->ifa_name);
		if (family == AF_INET6 &&
		    !memcmp(&((struct sockaddr_in6 *)i->ifa_addr)->sin6_addr, a->b, 16))
			return if_nametoindex(i->ifa_name);
	}
	return 0;
}

static void adopt_one(struct session *s, const struct session_key *k, const struct tx_cfg *c,
		      const struct session_state *st, struct ifaddrs *ifs, uint64_t t,
		      uint64_t hold_us)
{
	s->peer = k->peer;
	s->local = k->local;
	s->family = is_v4(&k->peer) ? AF_INET : AF_INET6;
	s->ifindex = c->mhop ? 0 : ifindex_of(ifs, &k->local, s->family);
	s->is_mhop = c->mhop;
	s->min_ttl = (uint8_t)(c->min_ttl ? c->min_ttl : 255);
	s->wire_disc = c->my_disc;
	s->rdisc = c->your_disc;
	s->state = c->state;
	s->diag = c->diag;
	s->detect_mult = c->mult;
	s->min_tx_us = s->applied_tx_us = c->min_tx_us;
	s->min_rx_us = c->min_rx_us;
	s->echo_on = c->echo_iv_us != 0;
	s->echo_tx_us = c->echo_iv_us;
	s->min_echo_rx_us = c->min_echo_rx_us;
	s->demand = c->demand;
	s->polling = c->poll;
	s->poll_seq = c->poll_seq;
	s->tx_port = c->src_port;

	/* The keys as the program holds them; bfdd's DP_SESSION_AUTH brings the
	 * lifetimes back.
	 */
	s->auth_present = c->auth_present;
	s->auth_type = c->auth_type;
	s->auth_keyid = c->auth_keyid;
	s->auth_keylen = c->auth_keylen;
	memcpy(s->auth_kpad, c->auth_kpad, sizeof(s->auth_kpad));
	memcpy(s->auth_key, c->auth_kpad, c->auth_keylen);
	for (int i = 0; i < c->auth_nkeys && i < BFDDP_AUTH_KEY_COUNT_MAX; i++) {
		struct auth_key *ak = &s->auth_keys[i];
		const struct xdp_auth_key *xk = &c->auth_accept[i];
		int sends = c->auth_type && xk->key_id == c->auth_keyid;

		ak->type = xk->type;
		ak->key_id = xk->key_id;
		ak->keylen = xk->keylen;
		memcpy(ak->kpad, xk->kpad, sizeof(ak->kpad));
		ak->accept_start = 0;
		ak->send_start = sends ? 0 : -1;
		ak->send_end = sends ? -1 : 0;
		s->auth_nkeys++;
	}

	if (st) {
		s->r_state = st->remote_state;
		s->r_min_tx = st->min_tx_us;
		s->r_min_rx = st->min_rx_us;
		s->r_min_echo = st->remote_min_echo_us;
		s->r_mult = st->detect_mult;
		s->r_flags = st->remote_flags;
		s->detect_iv_us = st->detect_iv_us;
		s->last_rx_us = s->ktx_seen_us = s->last_ktx_us = st->last_seen_ns / 1000;
		s->ktx_tx_pkts = st->tx_pkts;
		s->auth_rx_seq = st->auth_rx_seq;
		s->auth_rx_seen = (int)st->auth_rx_seen;
		memcpy(s->peer_mac, st->peer_mac, 6);
		s->mac_valid = st->mac_valid;
	}

	/* Already in the map; the first mirror pushes only a difference. */
	s->pushed_cfg = *c;
	s->pushed_valid = 1;
	s->next_tx_us = t;
	s->orphaned = 1;
	s->orphan_deadline_us = t + hold_us;
	sess_reindex(s);
}

int ktx_adopt(uint64_t hold_us)
{
	struct session_key k, next;
	struct session_state st;
	struct tx_cfg c;
	uint64_t t = now_us();
	struct ifaddrs *ifs = NULL;
	void *prev = NULL;
	int n = 0, up = 0;

	if (!ktx_reused || ktx_cfg_fd < 0)
		return 0;
	if (getifaddrs(&ifs))
		ifs = NULL;
	while (!bpf_map_get_next_key(ktx_cfg_fd, prev, &next)) {
		struct session *s;

		k = next;
		prev = &k;
		if (bpf_map_lookup_elem(ktx_cfg_fd, &k, &c))
			continue;
		s = sess_alloc_at(c.slot);
		if (!s) {
			log_err("--pin: a pinned session's slot %u is taken; not adopted\n",
				c.slot);
			continue;
		}
		adopt_one(s, &k, &c, bpf_map_lookup_elem(sess_fd, &k, &st) ? NULL : &st, ifs, t,
			  hold_us);
		n++;
		up += s->state == ST_UP;
	}
	if (ifs)
		freeifaddrs(ifs);
	log_info("--pin: adopted %d session(s), %d Up, in %llums; holding them %llus for bfdd\n",
		 n, up, (unsigned long long)((now_us() - t) / 1000),
		 (unsigned long long)(hold_us / 1000000));
	return n;
}
