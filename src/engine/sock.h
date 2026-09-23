// SPDX-License-Identifier: GPL-2.0
/* sock.h - the engine's UDP sockets: control RX on 3784 and 4784, and the
 * fallback TX sockets.
 */
#ifndef BFD_ENGINE_SOCK_H
#define BFD_ENGINE_SOCK_H

#include <stdint.h>

/* One control RX socket. Drained in table order. */
struct rx_sock {
	int fd;
	int family;
	int mhop;
	const char *sock_err; /* perror prefix if socket() fails */
	const char *bind_err; /* perror prefix if bind() fails */
};

#define RX_NSOCK 4
extern struct rx_sock rx_socks[RX_NSOCK];

/* Open the RX sockets. Single-hop is required; multihop is left at -1 on
 * failure. -1 if a single-hop socket could not be opened.
 */
int rx_open_all(void);

/* Read up to budget packets from r and hand accepted ones to fsm_rx. Returns
 * the number read.
 */
int rx_drain(const struct rx_sock *r, uint64_t t, int budget);

/* Unbound TX sockets for sessions without a slot socket. */
void tx_open_fallback(void);

#endif /* BFD_ENGINE_SOCK_H */
