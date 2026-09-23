// SPDX-License-Identifier: GPL-2.0
/* opts.h - command line. */
#ifndef BFD_ENGINE_OPTS_H
#define BFD_ENGINE_OPTS_H

#ifndef BFD_XDP_VERSION
#define BFD_XDP_VERSION "0.0.0-dev"
#endif

/* --tick-us */
#define TICK_US_DEFAULT 2000

struct opts {
	const char *dplane; /* --dplane port or socket path */
	const char *ktx_if; /* --kernel-tx */
	const char *local, *peer;
	const char *auth; /* --auth <type>:<keyid>:<key> */
	int demand;	  /* --demand; bfdd sends it per session */
	int check;	  /* --check */
	unsigned int tick_us;
};

/* Options owned by other modules are stored there. 0 to run, 1 to exit 0
 * (--version), -1 to exit 1.
 */
int opts_parse(int argc, char **argv, struct opts *o);

/* Prints usage if there is nothing to run. */
int opts_complete(const struct opts *o, const char *argv0);

#endif /* BFD_ENGINE_OPTS_H */
