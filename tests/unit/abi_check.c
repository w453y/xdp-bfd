// SPDX-License-Identifier: GPL-2.0
/*
 * Layout pins for every struct shared between the XDP program and the
 * engine. bfd_shared.h warns that a field added on one side is a silent
 * map misread; these turn that into a compile error.
 *
 * Compiled twice, by the host compiler and by clang for the BPF target,
 * so a divergence between the two fails the build rather than corrupting
 * a map at runtime. There is no runtime component: if it compiles, it
 * passes.
 *
 * The numbers were generated from the compiler, not written by hand. If a
 * deliberate layout change makes one wrong, regenerate rather than edit:
 * see tests/unit/README.md.
 */
#include <bfd_shared.h>
#include <stddef.h>

_Static_assert(sizeof(struct bfd_ctrl_pkt) == 24,
	       "sizeof(struct bfd_ctrl_pkt)");
_Static_assert(sizeof(struct bfd_addr) == 16,
	       "sizeof(struct bfd_addr)");
_Static_assert(sizeof(struct session_key) == 32,
	       "sizeof(struct session_key)");
_Static_assert(sizeof(struct session_state) == 104,
	       "sizeof(struct session_state)");
_Static_assert(sizeof(struct bfd_event) == 56,
	       "sizeof(struct bfd_event)");
_Static_assert(sizeof(struct tx_cfg) == 48,
	       "sizeof(struct tx_cfg)");
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
_Static_assert(offsetof(struct session_state, final_seq) == 52,
	       "offsetof(struct session_state, final_seq)");
_Static_assert(offsetof(struct session_state, peer_mac) == 56,
	       "offsetof(struct session_state, peer_mac)");
_Static_assert(offsetof(struct session_state, mac_valid) == 62,
	       "offsetof(struct session_state, mac_valid)");
_Static_assert(offsetof(struct session_state, echo_rx_pkts) == 64,
	       "offsetof(struct session_state, echo_rx_pkts)");
_Static_assert(offsetof(struct session_state, echo_last_seen_ns) == 72,
	       "offsetof(struct session_state, echo_last_seen_ns)");
_Static_assert(offsetof(struct session_state, echo_last_nonce) == 80,
	       "offsetof(struct session_state, echo_last_nonce)");
_Static_assert(offsetof(struct session_state, echo_alive) == 88,
	       "offsetof(struct session_state, echo_alive)");
_Static_assert(offsetof(struct session_state, remote_min_echo_us) == 96,
	       "offsetof(struct session_state, remote_min_echo_us)");
_Static_assert(offsetof(struct tx_cfg, enable) == 0,
	       "offsetof(struct tx_cfg, enable)");
_Static_assert(offsetof(struct tx_cfg, my_disc) == 4,
	       "offsetof(struct tx_cfg, my_disc)");
_Static_assert(offsetof(struct tx_cfg, your_disc) == 8,
	       "offsetof(struct tx_cfg, your_disc)");
_Static_assert(offsetof(struct tx_cfg, min_tx_us) == 12,
	       "offsetof(struct tx_cfg, min_tx_us)");
_Static_assert(offsetof(struct tx_cfg, min_rx_us) == 16,
	       "offsetof(struct tx_cfg, min_rx_us)");
_Static_assert(offsetof(struct tx_cfg, src_port) == 20,
	       "offsetof(struct tx_cfg, src_port)");
_Static_assert(offsetof(struct tx_cfg, state) == 22,
	       "offsetof(struct tx_cfg, state)");
_Static_assert(offsetof(struct tx_cfg, diag) == 23,
	       "offsetof(struct tx_cfg, diag)");
_Static_assert(offsetof(struct tx_cfg, mult) == 24,
	       "offsetof(struct tx_cfg, mult)");
_Static_assert(offsetof(struct tx_cfg, poll) == 25,
	       "offsetof(struct tx_cfg, poll)");
_Static_assert(offsetof(struct tx_cfg, poll_seq) == 32,
	       "offsetof(struct tx_cfg, poll_seq)");
_Static_assert(offsetof(struct tx_cfg, echo_iv_us) == 36,
	       "offsetof(struct tx_cfg, echo_iv_us)");
_Static_assert(offsetof(struct tx_cfg, min_echo_rx_us) == 40,
	       "offsetof(struct tx_cfg, min_echo_rx_us)");
_Static_assert(offsetof(struct tx_cfg, min_ttl) == 44,
	       "offsetof(struct tx_cfg, min_ttl)");
_Static_assert(offsetof(struct bfd_event, ts_ns) == 0,
	       "offsetof(struct bfd_event, ts_ns)");
_Static_assert(offsetof(struct bfd_event, last_seen_ns) == 8,
	       "offsetof(struct bfd_event, last_seen_ns)");
_Static_assert(offsetof(struct bfd_event, remote_disc) == 48,
	       "offsetof(struct bfd_event, remote_disc)");
_Static_assert(offsetof(struct bfd_event, event) == 52,
	       "offsetof(struct bfd_event, event)");
_Static_assert(offsetof(struct session_key, peer) == 0,
	       "offsetof(struct session_key, peer)");
_Static_assert(offsetof(struct session_key, local) == 16,
	       "offsetof(struct session_key, local)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, my_disc) == 4,
	       "offsetof(struct bfd_ctrl_pkt, my_disc)");
_Static_assert(offsetof(struct bfd_ctrl_pkt, min_echo_rx) == 20,
	       "offsetof(struct bfd_ctrl_pkt, min_echo_rx)");
