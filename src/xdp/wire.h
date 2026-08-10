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


#endif /* BFD_XDP_WIRE_H */
