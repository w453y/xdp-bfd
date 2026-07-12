# m6: multi-session

Goal: lift the single-session restriction. Maps and daemon were sized
for 64 sessions since m5; only single-session operation was validated.
This milestone makes concurrent sessions correct and proves two.

## Changes

- RX demux by address pair. The userspace RX socket matched sessions
  on peer IP alone; two sessions to the same peer from different local
  addresses were indistinguishable, and the socket never recovered the
  local dst address at all. Now IP_PKTINFO + recvmsg, matched on
  {peer, local}. Only reachable for your_disc=0 bootstrap packets;
  established sessions demux by discriminator as before.

- Per-session TX source ports (RFC 5881 s4: SHOULD be unique per
  session). Source port = 49152 + session slot. Userspace TX moves to
  per-slot sockets, opened lazily and kept for process lifetime, so a
  reused slot reuses its socket and teardown needs no fd handling.
  The kernel echo path reads src_port from tx_cfg instead of the
  compile-time constant.

- Single-writer map ownership. The kernel cleared cfg->poll in place
  on the peer's Final; userspace mirror pushes write the whole tx_cfg
  struct, so a push racing the Final could resurrect a finished Poll
  sequence (lost-Final). Now tx_cfg is strictly userspace-owned: the
  kernel acks the Final by writing final_seq = cfg->poll_seq into
  session_state (kernel-owned, already polled by userspace), and the
  echo path sets P only while final_seq != poll_seq. Each map value
  has exactly one writer; the race is gone structurally, not locked
  away.

- alive transitions via CAS. RX (set) and sweep (clear) run on
  different CPUs; plain u8 writes could double-emit liveness events.
  alive is now __u32 (BPF atomics are 32/64-bit only) and both
  transition sites use __sync_val_compare_and_swap, emitting only on
  CAS win.

## Verification (all on the m1 testbed, third VM promoted to peer)

- Two sessions up concurrently: dut<->10.66.0.2 and dut<->10.66.0.3,
  slot ports 49152/49153 visible bound and on the wire.
- Poll sequences through the final_seq path: transmit-interval
  20ms and back while Up; both changes negotiated, 0 down events,
  no residual P on the wire (tcpdump Poll count 0 post-change).
- Kill isolation: frr stopped dead on bfd-chaos (no farewell).
  Sweep declared the .3 session down at 31.2ms silent - within the
  historical 30-33ms envelope, through the CAS transition - while
  the .2 session's uptime ran uninterrupted. kill-isolation.txt.
- Two-session L3 stress (the stock-bfdd 44-flap condition), 120s:
  0 flaps both sessions. Per-session TX gaps from host pcap:
  49152 p50 8.75ms p99 10.02ms max 14.7ms; 49153 p50 8.74ms
  p99 10.02ms max 12.6ms. Matches single-session m5 numbers; two
  RX-clocked streams do not degrade each other.
- Injection with both sessions up: 200 optioned packets forging
  10.66.0.2 from the third host. rejects +200 exact, both uptimes
  monotonic, down events unchanged. spoof-2sess.txt.

## Files

- bfd-m6-2sess-L3.pcap        two-session L3 stress run, host capture
- gaps-m6-49152.txt           per-session TX gaps, session to .2
- gaps-m6-49153.txt           per-session TX gaps, session to .3
- kill-isolation.txt          hard-kill isolation evidence
- spoof-2sess.txt             two-session injection evidence

## Scale follow-up

Post-merge, rerun at 16 concurrent sessions (8 per peer VM via
secondary addresses): 0 flaps under L3 stress, mass-kill of 8
detected at 30.5-32.8ms with no batch drift, surviving 8 untouched.
Evidence: bfd-m6-16sess-L3.pcap, scale-16.txt (includes FRR
peer-identity operational findings).

## Still out of scope

Validated at 16 of 64 slots. IPv6, auth, echo/demand unchanged. Slot
ports assume one bfd_tx instance owns 49152-49215 on the host.
