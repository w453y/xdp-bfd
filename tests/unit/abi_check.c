// SPDX-License-Identifier: GPL-2.0
/* Layout pins for the structs both planes share, compiled for the host and for
 * BPF. Regenerate with abi_probe.c after a deliberate change.
 */
#include <bfd_shared.h>
#include <hmac_sha1.h>
#include <stddef.h>

/* Layout, as printed by abi_probe.c. */
_Static_assert(sizeof(struct bfd_ctrl_pkt) == 24, "sizeof(struct bfd_ctrl_pkt)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, vers_diag) == 0,
	       "offsetof(struct bfd_ctrl_pkt, vers_diag)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, flags) == 1, "offsetof(struct bfd_ctrl_pkt, flags)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, detect_mult) == 2,
	       "offsetof(struct bfd_ctrl_pkt, detect_mult)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, len) == 3, "offsetof(struct bfd_ctrl_pkt, len)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, my_disc) == 4,
	       "offsetof(struct bfd_ctrl_pkt, my_disc)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, your_disc) == 8,
	       "offsetof(struct bfd_ctrl_pkt, your_disc)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, min_tx) == 12,
	       "offsetof(struct bfd_ctrl_pkt, min_tx)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, min_rx) == 16,
	       "offsetof(struct bfd_ctrl_pkt, min_rx)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, min_echo_rx) == 20,
	       "offsetof(struct bfd_ctrl_pkt, min_echo_rx)");

_Static_assert(sizeof(struct bfd_addr) == 16, "sizeof(struct bfd_addr)");

_Static_assert(sizeof(struct session_key) == 32, "sizeof(struct session_key)");
_Static_assert(offsetof(struct session_key, peer) == 0, "offsetof(struct session_key, peer)");
_Static_assert(offsetof(struct session_key, local) == 16, "offsetof(struct session_key, local)");

_Static_assert(sizeof(struct session_state) == 136, "sizeof(struct session_state)");
_Static_assert(offsetof(struct session_state, last_seen_ns) == 0,
	       "offsetof(struct session_state, last_seen_ns)");
_Static_assert(offsetof(struct session_state, rx_pkts) == 8,
	       "offsetof(struct session_state, rx_pkts)");
_Static_assert(offsetof(struct session_state, tx_pkts) == 16,
	       "offsetof(struct session_state, tx_pkts)");
_Static_assert(offsetof(struct session_state, remote_disc) == 24,
	       "offsetof(struct session_state, remote_disc)");
_Static_assert(offsetof(struct session_state, local_disc) == 28,
	       "offsetof(struct session_state, local_disc)");
_Static_assert(offsetof(struct session_state, min_tx_us) == 32,
	       "offsetof(struct session_state, min_tx_us)");
_Static_assert(offsetof(struct session_state, min_rx_us) == 36,
	       "offsetof(struct session_state, min_rx_us)");
_Static_assert(offsetof(struct session_state, detect_iv_us) == 40,
	       "offsetof(struct session_state, detect_iv_us)");
_Static_assert(offsetof(struct session_state, remote_state) == 44,
	       "offsetof(struct session_state, remote_state)");
_Static_assert(offsetof(struct session_state, remote_diag) == 45,
	       "offsetof(struct session_state, remote_diag)");
_Static_assert(offsetof(struct session_state, detect_mult) == 46,
	       "offsetof(struct session_state, detect_mult)");
_Static_assert(offsetof(struct session_state, remote_flags) == 47,
	       "offsetof(struct session_state, remote_flags)");
_Static_assert(offsetof(struct session_state, alive) == 48,
	       "offsetof(struct session_state, alive)");
_Static_assert(offsetof(struct session_state, final_seq) == 56,
	       "offsetof(struct session_state, final_seq)");
_Static_assert(offsetof(struct session_state, peer_mac) == 60,
	       "offsetof(struct session_state, peer_mac)");
_Static_assert(offsetof(struct session_state, mac_valid) == 66,
	       "offsetof(struct session_state, mac_valid)");
_Static_assert(offsetof(struct session_state, echo_rx_pkts) == 72,
	       "offsetof(struct session_state, echo_rx_pkts)");
_Static_assert(offsetof(struct session_state, echo_last_seen_ns) == 80,
	       "offsetof(struct session_state, echo_last_seen_ns)");
_Static_assert(offsetof(struct session_state, echo_last_nonce) == 88,
	       "offsetof(struct session_state, echo_last_nonce)");
_Static_assert(offsetof(struct session_state, echo_alive) == 96,
	       "offsetof(struct session_state, echo_alive)");
_Static_assert(offsetof(struct session_state, remote_min_echo_us) == 104,
	       "offsetof(struct session_state, remote_min_echo_us)");
_Static_assert(offsetof(struct session_state, auth_rx_seq) == 108,
	       "offsetof(struct session_state, auth_rx_seq)");
_Static_assert(offsetof(struct session_state, auth_rx_seen) == 112,
	       "offsetof(struct session_state, auth_rx_seen)");
_Static_assert(offsetof(struct session_state, auth_fail_n) == 116,
	       "offsetof(struct session_state, auth_fail_n)");
_Static_assert(offsetof(struct session_state, auth_fail_ts) == 128,
	       "offsetof(struct session_state, auth_fail_ts)");

_Static_assert(sizeof(struct bfd_event) == 56, "sizeof(struct bfd_event)");
_Static_assert(offsetof(struct bfd_event, ts_ns) == 0, "offsetof(struct bfd_event, ts_ns)");
_Static_assert(offsetof(struct bfd_event, last_seen_ns) == 8,
	       "offsetof(struct bfd_event, last_seen_ns)");
_Static_assert(offsetof(struct bfd_event, key) == 16, "offsetof(struct bfd_event, key)");
_Static_assert(offsetof(struct bfd_event, remote_disc) == 48,
	       "offsetof(struct bfd_event, remote_disc)");
_Static_assert(offsetof(struct bfd_event, event) == 52, "offsetof(struct bfd_event, event)");

_Static_assert(sizeof(struct xdp_auth_key) == 68, "sizeof(struct xdp_auth_key)");
_Static_assert(offsetof(struct xdp_auth_key, type) == 0, "offsetof(struct xdp_auth_key, type)");
_Static_assert(offsetof(struct xdp_auth_key, key_id) == 1, "offsetof(struct xdp_auth_key, key_id)");
_Static_assert(offsetof(struct xdp_auth_key, keylen) == 2, "offsetof(struct xdp_auth_key, keylen)");
_Static_assert(offsetof(struct xdp_auth_key, kpad) == 4, "offsetof(struct xdp_auth_key, kpad)");

_Static_assert(sizeof(struct tx_cfg) == 1208, "sizeof(struct tx_cfg)");
_Static_assert(offsetof(struct tx_cfg, enable) == 0, "offsetof(struct tx_cfg, enable)");
_Static_assert(offsetof(struct tx_cfg, my_disc) == 4, "offsetof(struct tx_cfg, my_disc)");
_Static_assert(offsetof(struct tx_cfg, your_disc) == 8, "offsetof(struct tx_cfg, your_disc)");
_Static_assert(offsetof(struct tx_cfg, min_tx_us) == 12, "offsetof(struct tx_cfg, min_tx_us)");
_Static_assert(offsetof(struct tx_cfg, min_rx_us) == 16, "offsetof(struct tx_cfg, min_rx_us)");
_Static_assert(offsetof(struct tx_cfg, src_port) == 20, "offsetof(struct tx_cfg, src_port)");
_Static_assert(offsetof(struct tx_cfg, state) == 22, "offsetof(struct tx_cfg, state)");
_Static_assert(offsetof(struct tx_cfg, diag) == 23, "offsetof(struct tx_cfg, diag)");
_Static_assert(offsetof(struct tx_cfg, mult) == 24, "offsetof(struct tx_cfg, mult)");
_Static_assert(offsetof(struct tx_cfg, poll) == 25, "offsetof(struct tx_cfg, poll)");
_Static_assert(offsetof(struct tx_cfg, demand) == 26, "offsetof(struct tx_cfg, demand)");
_Static_assert(offsetof(struct tx_cfg, demand_hold) == 27, "offsetof(struct tx_cfg, demand_hold)");
_Static_assert(offsetof(struct tx_cfg, mhop) == 28, "offsetof(struct tx_cfg, mhop)");
_Static_assert(offsetof(struct tx_cfg, poll_seq) == 32, "offsetof(struct tx_cfg, poll_seq)");
_Static_assert(offsetof(struct tx_cfg, echo_iv_us) == 36, "offsetof(struct tx_cfg, echo_iv_us)");
_Static_assert(offsetof(struct tx_cfg, min_echo_rx_us) == 40,
	       "offsetof(struct tx_cfg, min_echo_rx_us)");
_Static_assert(offsetof(struct tx_cfg, min_ttl) == 44, "offsetof(struct tx_cfg, min_ttl)");
_Static_assert(offsetof(struct tx_cfg, auth_type) == 48, "offsetof(struct tx_cfg, auth_type)");
_Static_assert(offsetof(struct tx_cfg, auth_keyid) == 49, "offsetof(struct tx_cfg, auth_keyid)");
_Static_assert(offsetof(struct tx_cfg, auth_keylen) == 50, "offsetof(struct tx_cfg, auth_keylen)");
_Static_assert(offsetof(struct tx_cfg, auth_present) == 51,
	       "offsetof(struct tx_cfg, auth_present)");
_Static_assert(offsetof(struct tx_cfg, auth_kpad) == 52, "offsetof(struct tx_cfg, auth_kpad)");
_Static_assert(offsetof(struct tx_cfg, auth_nkeys) == 116, "offsetof(struct tx_cfg, auth_nkeys)");
_Static_assert(offsetof(struct tx_cfg, auth_accept) == 120, "offsetof(struct tx_cfg, auth_accept)");
_Static_assert(sizeof(((struct tx_cfg *)0)->auth_kpad) == SHA1_BLOCK_LEN,
	       "the mirrored key must be exactly one HMAC block");

/* A keyed SHA1 packet is hashed whole, so it must fit one HMAC block. */
_Static_assert(BFD_AUTH_SHA1_LEN == 28, "BFD_AUTH_SHA1_LEN");
_Static_assert(BFD_MAX_LEN == 52, "BFD_MAX_LEN");
_Static_assert(BFD_MAX_LEN <= HMAC_SHA1_MAX_MSG, "a keyed-SHA1 packet must fit the shared digest");

/* Enum values are indices on both planes, so they are pinned by value. */
_Static_assert(BFD_TUNE_SWEEP_NS == 0, "BFD_TUNE_SWEEP_NS");
_Static_assert(BFD_TUNE_DEADMAN_NS == 1, "BFD_TUNE_DEADMAN_NS");
_Static_assert(BFD_TUNE_MAX == 2, "BFD_TUNE_MAX");
_Static_assert(ST_ADMINDOWN == 0, "ST_ADMINDOWN");
_Static_assert(ST_DOWN == 1, "ST_DOWN");
_Static_assert(ST_INIT == 2, "ST_INIT");
_Static_assert(ST_UP == 3, "ST_UP");

/* Stat slots, pinned by value for the same reason. */
_Static_assert(BFD_STAT_SEEN == 0, "BFD_STAT_SEEN");
_Static_assert(BFD_STAT_WELL_FORMED == 1, "BFD_STAT_WELL_FORMED");
_Static_assert(BFD_STAT_MALFORMED == 2, "BFD_STAT_MALFORMED");
_Static_assert(BFD_STAT_REJECTED == 3, "BFD_STAT_REJECTED");
_Static_assert(BFD_STAT_REFLECTED == 4, "BFD_STAT_REFLECTED");
_Static_assert(BFD_STAT_ECHO_RETURNS == 5, "BFD_STAT_ECHO_RETURNS");
_Static_assert(BFD_STAT_DECLINED == 6, "BFD_STAT_DECLINED");
_Static_assert(BFD_STAT_NOT_SELF == 7, "BFD_STAT_NOT_SELF");
_Static_assert(BFD_STAT_ECHO_TTL == 8, "BFD_STAT_ECHO_TTL");
_Static_assert(BFD_STAT_UNSUPPORTED_FLAGS == 9, "BFD_STAT_UNSUPPORTED_FLAGS");
_Static_assert(BFD_STAT_SWEEP_INIT_FAIL == 10, "BFD_STAT_SWEEP_INIT_FAIL");
_Static_assert(BFD_STAT_IP_OPTIONS == 11, "BFD_STAT_IP_OPTIONS");
_Static_assert(BFD_STAT_AUTH_MISMATCH == 12, "BFD_STAT_AUTH_MISMATCH");
_Static_assert(BFD_STAT_AUTH_BAD == 13, "BFD_STAT_AUTH_BAD");
_Static_assert(BFD_STAT_DEADMAN_HOLD == 14, "BFD_STAT_DEADMAN_HOLD");
_Static_assert(BFD_STAT_UNKNOWN_SESSION == 15, "BFD_STAT_UNKNOWN_SESSION");
_Static_assert(BFD_STAT_V6_EXTHDR == 16, "BFD_STAT_V6_EXTHDR");
_Static_assert(BFD_STAT_AUTH_RATELIMITED == 17, "BFD_STAT_AUTH_RATELIMITED");
_Static_assert(BFD_STAT_MAX == 18, "BFD_STAT_MAX");
