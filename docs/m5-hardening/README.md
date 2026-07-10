# m5-hardening evidence

Session: symmetric 3x300ms via FRR dplane, kernel-tx on ens19.
Window (m5-window.txt): 1783722902 - 1783723031.
Peer FRR stopped mid-window, restarted, then both sides reverted to 10ms.

Wire results (host-side tcpdump on vmbr3), DUT Down-state transitions
with gap since peer's last packet, sliced to window:

    t=1783722941 detect gap=900 ms
    t=1783722983 detect gap=151 ms

t=941: peer kill. Detect at exactly 3x300ms configured budget. Verifies
per-session min_rx in the kernel sweep and live remote-timer sync in
userspace (pre-fix behavior on identical test: 3002ms, userspace stale
at FRR's 1s slow-start interval).

t=983: false detect during the 300ms -> 10ms revert. Timer
renegotiation race: detect budget shrinks on the peer's new advertised
min_tx before the peer actually paces at the new rate (RFC 5880 s6.8.3
keeps the old rate until Poll completes). Known bug, fix pending
(poll-sequence-aware detect).

Also characterized this session: asymmetric intervals (one side 300ms
rx, other at 10ms) flap-loop under RX-clocked TX by construction; the
echo rate is slaved to the peer's TX rate and cannot satisfy a faster
peer-side detect budget. RX-clocked TX requires symmetric intervals.

Analysis commands: same tshark/awk method as docs/reproduction.md s3-4;
transition extraction filtered to ip.src of the DUT, gap measured from
the peer's last packet before each 0x01 transition.
