// SPDX-License-Identifier: GPL-2.0
/* tunables.h - kernel-side constants. The wire format is in
 * include/bfd_shared.h.
 */
#ifndef BFD_XDP_TUNABLES_H
#define BFD_XDP_TUNABLES_H

/* Fallback required-min-rx for the promiscuous observer; configured
 * sessions use tx_config.min_rx_us.
 */
#define LOCAL_MIN_RX_US 10000
/* Default only; sweep_interval() prefers the tunables map, which the
 * engine writes from --sweep-us between load and attach.
 */
#define SWEEP_NS BFD_SWEEP_NS_DEFAULT


#endif /* BFD_XDP_TUNABLES_H */
