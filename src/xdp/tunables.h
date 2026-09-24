// SPDX-License-Identifier: GPL-2.0
/* tunables.h - kernel-side constants. */
#ifndef BFD_XDP_TUNABLES_H
#define BFD_XDP_TUNABLES_H

/* For the promiscuous observer; sessions use tx_config.min_rx_us. */
#define LOCAL_MIN_RX_US 10000
/* The tunables map overrides it (--sweep-us). */
#define SWEEP_NS BFD_SWEEP_NS_DEFAULT
/* Packets per CPU per window passed up for a known discriminator from an
 * unknown pair: a moved peer needs one per detect time, a flood gets no more.
 */
/* One change announcement per session per this; a later change waits for the
 * session's next packet.
 */
#define CHANGE_MIN_NS 1000000ull
#define MOVED_MAX     256
#define MOVED_WIN_NS  100000000ull


#endif /* BFD_XDP_TUNABLES_H */
