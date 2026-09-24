// SPDX-License-Identifier: GPL-2.0
/* opts.c - command line. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <linux/if_link.h>

#include "log.h"
#include "session.h"
#include "dplane.h"
#include "fsm.h"
#include "ktx.h"
#include "stats.h"
#include "opts.h"

/* "10s" must not parse as 10. Nonzero if not a whole number. */
static int num(const char *a, unsigned long long *v)
{
	char *end;

	*v = strtoull(a, &end, 10);
	return end == a || *end;
}

/* The account bfdd runs as. */
static int dp_peer(const char *a)
{
	const struct passwd *pw = getpwnam(a);
	unsigned long long v;

	if (pw) {
		dp_set_peer_uid(pw->pw_uid);
		return 0;
	}
	if (num(a, &v) || v > (unsigned int)-2) {
		log_err("--dp-peer: no such user and not a uid: '%s'\n", a);
		return -1;
	}
	dp_set_peer_uid((uid_t)v);
	return 0;
}

static int log_level(const char *a)
{
	if (!strcmp(a, "error"))
		bfd_log_level = BFD_LOG_ERROR;
	else if (!strcmp(a, "info"))
		bfd_log_level = BFD_LOG_INFO;
	else if (!strcmp(a, "debug"))
		bfd_log_level = BFD_LOG_DEBUG;
	else {
		log_err("--log-level: expected error|info|debug, got '%s'\n", a);
		return -1;
	}
	return 0;
}

static int xdp_mode(const char *m)
{
	if (!strcmp(m, "generic") || !strcmp(m, "skb"))
		ktx_xdp_flags = XDP_FLAGS_SKB_MODE;
	else if (!strcmp(m, "drv") || !strcmp(m, "native"))
		ktx_xdp_flags = XDP_FLAGS_DRV_MODE;
	else {
		log_err("--xdp-mode: expected drv or generic, got '%s'\n", m);
		return -1;
	}
	return 0;
}

static int opt_value(const char *opt, const char *a, struct opts *o)
{
	unsigned long long v;

	if (!strcmp(opt, "--dplane"))
		o->dplane = a;
	else if (!strcmp(opt, "--kernel-tx"))
		o->ktx_if = a;
	else if (!strcmp(opt, "--bpf-obj"))
		ktx_obj_path = a;
	else if (!strcmp(opt, "--stats-dump"))
		stats_path = a;
	else if (!strcmp(opt, "--auth"))
		o->auth = a;
	else if (!strcmp(opt, "--log-level"))
		return log_level(a);
	else if (!strcmp(opt, "--xdp-mode"))
		return xdp_mode(a);
	else if (!strcmp(opt, "--dp-peer"))
		return dp_peer(a);
	else if (!strcmp(opt, "--sweep-us")) {
		/* Under 0.5ms the timer churns; over 100ms beats any detect budget. */
		if (num(a, &v) || v < 500 || v > 100000) {
			log_err("--sweep-us: expected 500-100000, got '%s'\n", a);
			return -1;
		}
		ktx_sweep_ns = v * 1000ull;
	} else if (!strcmp(opt, "--deadman-us")) {
		/* 0 is off; 50ms is above the worst loop gap measured. */
		if (num(a, &v) || (v && (v < 50000 || v > 60000000))) {
			log_err("--deadman-us: expected 0 (off) or 50000-60000000, got '%s'\n", a);
			return -1;
		}
		ktx_deadman_ns = v * 1000ull;
	} else if (!strcmp(opt, "--demand-poll-us")) {
		/* 0 is off; the floor only catches typos, the detect budget raises it. */
		if (num(a, &v) || (v && (v < 10000 || v > 600000000))) {
			log_err("--demand-poll-us: expected 0 (off) or 10000-600000000, got '%s'\n",
				a);
			return -1;
		}
		demand_poll_us = v;
	} else if (!strcmp(opt, "--tick-us")) {
		/* Each pass walks every session. */
		if (num(a, &v) || v < 200 || v > 100000) {
			log_err("--tick-us: expected 200-100000, got '%s'\n", a);
			return -1;
		}
		o->tick_us = (unsigned int)v;
	} else if (!strcmp(opt, "--dp-hold")) {
		if (num(a, &v) || v > 86400) {
			log_err("--dp-hold: expected seconds (0-86400), got '%s'\n", a);
			return -1;
		}
		dp_hold_us = v * 1000000ull;
	} else
		return 1;
	return 0;
}

int opts_parse(int argc, char **argv, struct opts *o)
{
	memset(o, 0, sizeof(*o));
	o->tick_us = TICK_US_DEFAULT;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		int rc;

		if (!strcmp(a, "--version")) {
			printf("xdp-bfd %s\n", BFD_XDP_VERSION);
			return 1;
		}
		if (!strcmp(a, "--demand")) {
			o->demand = 1;
			continue;
		}
		if (!strcmp(a, "--check")) {
			o->check = 1;
			continue;
		}
		if (a[0] == '-' && i + 1 < argc) {
			rc = opt_value(a, argv[i + 1], o);
			if (rc < 0)
				return -1;
			if (rc == 0) {
				i++;
				continue;
			}
		}
		/* Before they are taken as addresses. */
		if (a[0] == '-') {
			log_err("unrecognised option '%s', or an option missing its value\n", a);
			return -1;
		}
		if (!o->local)
			o->local = a;
		else if (!o->peer)
			o->peer = a;
		else {
			log_err("unexpected argument '%s'\n", a);
			return -1;
		}
	}
	return 0;
}

int opts_complete(const struct opts *o, const char *argv0)
{
	if (o->local && !o->peer) {
		log_err("static: %s given without a peer address\n", o->local);
		return 0;
	}
	if (!o->dplane && (!o->local || !o->peer)) {
		log_err("usage: %s <local-ip> <peer-ip> [--kernel-tx <if>]\n"
			"       %s --dplane <port|sock-path> [--kernel-tx <if>] [--dp-hold <sec>]\n"
			"       [--dp-peer <user|uid>]  (the account bfdd runs as)\n"
			"       [--bpf-obj <path>] [--xdp-mode drv|generic]\n"
			"       [--stats-dump <path>]   (SIGUSR1 writes it)\n"
			"       [--sweep-us <500-100000>]\n"
			"       [--tick-us <200-100000>]\n"
			"       [--deadman-us <0|50000-60000000>]  (0 = off)\n"
			"       [--demand] [--demand-poll-us <0|10000-600000000>]\n"
			"       [--log-level error|info|debug]\n",
			argv0, argv0);
		return 0;
	}
	return 1;
}
