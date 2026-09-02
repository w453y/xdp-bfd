#include "bfd_shared.h"
#ifdef __bpf__
#define P(x) _Static_assert(1, "")
#else
#include <stdio.h>
#include <stddef.h>
int main(void) {
#define S(t) printf("sizeof(struct %s) == %zu\n", #t, sizeof(struct t))
#define O(t, f) printf("offsetof(struct %s, %s) == %zu\n", #t, #f, offsetof(struct t, f))
    S(bfd_ctrl_pkt); S(bfd_addr); S(session_key); S(session_state);
    S(bfd_event); S(tx_cfg);
    O(session_state, last_seen_ns); O(session_state, rx_pkts);
    O(session_state, tx_pkts); O(session_state, remote_disc);
    O(session_state, local_disc); O(session_state, min_tx_us);
    O(session_state, min_rx_us); O(session_state, detect_iv_us);
    O(session_state, remote_state); O(session_state, remote_diag);
    O(session_state, detect_mult); O(session_state, remote_flags);
    O(session_state, alive); O(session_state, final_seq);
    O(session_state, peer_mac); O(session_state, mac_valid);
    O(session_state, echo_rx_pkts); O(session_state, echo_last_seen_ns);
    O(session_state, echo_last_nonce); O(session_state, echo_alive);
    O(session_state, remote_min_echo_us);
    O(tx_cfg, enable); O(tx_cfg, my_disc); O(tx_cfg, your_disc);
    O(tx_cfg, min_tx_us); O(tx_cfg, min_rx_us); O(tx_cfg, src_port);
    O(tx_cfg, state); O(tx_cfg, diag); O(tx_cfg, mult); O(tx_cfg, poll);
    O(tx_cfg, poll_seq); O(tx_cfg, echo_iv_us); O(tx_cfg, min_echo_rx_us);
    O(tx_cfg, min_ttl);
    O(bfd_event, ts_ns); O(bfd_event, last_seen_ns);
    O(bfd_event, remote_disc); O(bfd_event, event);
    O(session_key, peer); O(session_key, local);
    O(bfd_ctrl_pkt, my_disc); O(bfd_ctrl_pkt, min_echo_rx);
    return 0;
}
#endif
