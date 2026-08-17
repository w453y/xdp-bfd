// SPDX-License-Identifier: GPL-2.0
/* tunables.h - observer-path constants.
 *
 * The wire format itself lives in include/bfd_shared.h, shared with
 * the userspace engine; only these two knobs are kernel-side. */
#ifndef BFD_XDP_TUNABLES_H
#define BFD_XDP_TUNABLES_H

#define LOCAL_MIN_RX_US 10000  /* fallback required-min-rx: promiscuous
                                 * observer only; configured sessions use
                                 * tx_config.min_rx_us */
/* Default only; sweep_interval() prefers the tunables map, which the
 * engine writes from --sweep-us between load and attach. */
#define SWEEP_NS        BFD_SWEEP_NS_DEFAULT


#endif /* BFD_XDP_TUNABLES_H */
