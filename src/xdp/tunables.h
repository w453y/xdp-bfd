// SPDX-License-Identifier: GPL-2.0
/* tunables.h - kernel-side constants. */
#ifndef BFD_XDP_TUNABLES_H
#define BFD_XDP_TUNABLES_H

/* For the promiscuous observer; sessions use tx_config.min_rx_us. */
#define LOCAL_MIN_RX_US 10000
/* The tunables map overrides it (--sweep-us). */
#define SWEEP_NS BFD_SWEEP_NS_DEFAULT


#endif /* BFD_XDP_TUNABLES_H */
