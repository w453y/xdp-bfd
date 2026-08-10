// SPDX-License-Identifier: GPL-2.0
/* wire.h - wire format, macros and tunables.
 *
 * Split out of bfd_xdp.c. Include order matters: maps.h must precede
 * any header whose helpers reference a map by symbol.
 */
#ifndef BFD_XDP_WIRE_H
#define BFD_XDP_WIRE_H

#define LOCAL_MIN_RX_US 10000  /* fallback required-min-rx: promiscuous
                                 * observer only; configured sessions use
                                 * tx_config.min_rx_us */
#define SWEEP_NS        (5 * 1000 * 1000ull)   /* 5ms sweep */

struct bfdhdr {
	__u8  vers_diag;
	__u8  flags;
	__u8  detect_mult;
	__u8  len;
	__be32 my_disc;
	__be32 your_disc;
	__be32 min_tx;
	__be32 min_rx;
	__be32 min_echo_rx;
} __attribute__((packed));

#define BFD_VERS(h)   (((h)->vers_diag >> 5) & 0x7)
#define BFD_DIAG(h)   ((h)->vers_diag & 0x1f)
#define BFD_STATE(h)  (((h)->flags >> 6) & 0x3)

#endif /* BFD_XDP_WIRE_H */
