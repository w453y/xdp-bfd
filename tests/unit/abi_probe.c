// SPDX-License-Identifier: GPL-2.0
/* abi_probe.c - print abi_check.c's layout pins. Not built by default: cc -Iinclude. */
#include <stdio.h>
#include <stddef.h>

#include "bfd_shared.h"

#define S(t)                                                                                      \
	printf("_Static_assert(sizeof(struct %s) == %zu, \"sizeof(struct %s)\");\n", #t,          \
	       sizeof(struct t), #t)
#define O(t, f)                                                                                   \
	printf("_Static_assert(offsetof(struct %s, %s) == %zu, \"offsetof(struct %s, %s)\");\n",  \
	       #t, #f, offsetof(struct t, f), #t, #f)

int main(void)
{
	S(bfd_ctrl_pkt);
	O(bfd_ctrl_pkt, vers_diag);
	O(bfd_ctrl_pkt, flags);
	O(bfd_ctrl_pkt, detect_mult);
	O(bfd_ctrl_pkt, len);
	O(bfd_ctrl_pkt, my_disc);
	O(bfd_ctrl_pkt, your_disc);
	O(bfd_ctrl_pkt, min_tx);
	O(bfd_ctrl_pkt, min_rx);
	O(bfd_ctrl_pkt, min_echo_rx);

	S(bfd_addr);

	S(session_key);
	O(session_key, peer);
	O(session_key, local);

	S(session_state);
	O(session_state, last_seen_ns);
	O(session_state, rx_pkts);
	O(session_state, tx_pkts);
	O(session_state, remote_disc);
	O(session_state, local_disc);
	O(session_state, min_tx_us);
	O(session_state, min_rx_us);
	O(session_state, detect_iv_us);
	O(session_state, remote_state);
	O(session_state, remote_diag);
	O(session_state, detect_mult);
	O(session_state, remote_flags);
	O(session_state, alive);
	O(session_state, final_seq);
	O(session_state, peer_mac);
	O(session_state, mac_valid);
	O(session_state, echo_rx_pkts);
	O(session_state, echo_last_seen_ns);
	O(session_state, echo_last_nonce);
	O(session_state, echo_alive);
	O(session_state, remote_min_echo_us);
	O(session_state, auth_rx_seq);
	O(session_state, auth_rx_seen);
	O(session_state, auth_fail_n);
	O(session_state, auth_fail_ts);

	S(bfd_event);
	O(bfd_event, ts_ns);
	O(bfd_event, last_seen_ns);
	O(bfd_event, key);
	O(bfd_event, remote_disc);
	O(bfd_event, event);

	S(xdp_auth_key);
	O(xdp_auth_key, type);
	O(xdp_auth_key, key_id);
	O(xdp_auth_key, keylen);
	O(xdp_auth_key, kpad);

	S(tx_cfg);
	O(tx_cfg, key);
	O(tx_cfg, enable);
	O(tx_cfg, my_disc);
	O(tx_cfg, your_disc);
	O(tx_cfg, min_tx_us);
	O(tx_cfg, min_rx_us);
	O(tx_cfg, src_port);
	O(tx_cfg, state);
	O(tx_cfg, diag);
	O(tx_cfg, mult);
	O(tx_cfg, poll);
	O(tx_cfg, demand);
	O(tx_cfg, demand_hold);
	O(tx_cfg, mhop);
	O(tx_cfg, poll_seq);
	O(tx_cfg, echo_iv_us);
	O(tx_cfg, min_echo_rx_us);
	O(tx_cfg, min_ttl);
	O(tx_cfg, auth_type);
	O(tx_cfg, auth_keyid);
	O(tx_cfg, auth_keylen);
	O(tx_cfg, auth_present);
	O(tx_cfg, auth_kpad);
	O(tx_cfg, auth_nkeys);
	O(tx_cfg, auth_accept);
	return 0;
}
