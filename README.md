# xdp-bfd

BFD (RFC 5880/5881) with the fast path in XDP — failure detection and
transmission that survive CPU load that kills userspace BFD daemons.

Full writeup: [docs/writeup.md](docs/writeup.md)
Reproduce it yourself: [docs/reproduction.md](docs/reproduction.md)
## Problem

BFD is the failure detector under BGP/OSPF/IS-IS: miss N packets in
interval X, declare the link dead. Its value is timing precision, and
userspace implementations lose that precision under load. Measured here
(FRR bfdd 10.5.1, 3x10ms session, Linux 7.0):

| Load on the BFD host | bfdd result |
|---|---|
| 4x CPU hogs (fair sched) | survives |
| CPU + context-switch churn | flaps, TX gaps to 750ms |
| CPU + timer/hrtimer pressure | **44 flaps in 120s**, TX gaps to 970ms |
| SCHED_FIFO hogs | flaps hard, ~40% of packets never sent |

The dangerous detail: under timer stress bfdd's p99 inter-packet gap
looked perfect (10.16ms) while the max hit 970ms — rare total
starvation events, invisible to percentile monitoring, each one fatal.
This is why hardware routers offload BFD to line cards. This project is
the equivalent for plain Linux on commodity NICs.

## Architecture

Four cooperating pieces, one interface:

1. **XDP RX + parser** (`bfd_xdp.c`) — parses/validates BFD control
   packets in the driver path, tracks per-session state in a BPF hash
   map (timestamps taken at actual packet arrival, immune to
   socket-buffer queueing illusions).
2. **Kernel-side detection sweep** — one global `bpf_timer` (5ms)
   sweeps `now - last_seen` against each session's negotiated detect
   time; transitions are pushed to userspace via ringbuf. Detection of
   a dead peer works even when userspace is fully starved.
3. **RX-clocked kernel TX** — while the session is Up, every valid
   peer packet is rewritten in place (MAC/IP swap, BFD payload rebuilt
   from a config map, Polls answered with Final) and bounced with
   `XDP_TX`. Our transmit clock is the peer's transmit clock, executed
   in softirq (~30µs turnaround). No userspace wakeup in the
   per-packet path.
4. **Userspace FSM** (`bfd_tx.c`) — session bring-up, RFC 5880 state
   machine, Down-state slow-rate TX (1s), and the single transition
   packet on entering Up. Silent in steady state.

## Results

Five TX architectures, identical conditions (SCHED_FIFO prio-50 hogs,
3x10ms session, virtio-net, kernel 7.0):

| TX backend | flaps | p50 | p99 | max gap |
|---|---|---|---|---|
| FRR bfdd | continuous | 8.8 | 287 | 960ms |
| naive userspace loop | 25 | 10.0 | 12.0 | 324ms |
| userspace + chrt -f 90 + pinned CPU | 0 | 10.0 | 13.0 | 15.0ms |
| SO_TXTIME + etf, pipelined x5 | 48 | 10.0 | 10.1 | 994ms |
| **XDP RX-clocked (this project)** | **0** | **8.75** | **11.0** | **12.5ms** |

bfdd flap counts differ across this document because the loads
differ: 44 flaps/120s is the L3 timer-storm level from the ladder
above, while "continuous" here and the 107-flap capture in
docs/benchmarks are L4 SCHED_FIFO runs of different durations.

The p50 of 8.75ms (not 10.00) is the signature: the wire distribution
is the peer's own jittered TX echoed from softirq — the transmit clock
has left userspace entirely.

**FRR integration result:** the same session, created by an unmodified
FRR bfdd and offloaded to this engine over FRR's own distributed-BFD
dataplane protocol, survived the identical SCHED_FIFO stress with 0
flaps (p50 8.99, p99 11.01, max 13.01ms) and uninterrupted uptime in
`show bfd peers`. Putting FRR in the control loop cost nothing.

Findings along the way:

- "Userspace BFD inherently fails" is false: a tight recv-loop survives
  fair-scheduler load that kills bfdd, and RT priority rescues it
  entirely — *if* you can win the priority war. Kernel-path BFD doesn't
  have to fight it.
- Software etf fixes wire jitter but cannot fix liveness: its
  tolerance equals pipeline depth, and depth is bounded by
  state-staleness, not by etf. Under the RT throttle's 950ms/s
  starvation pattern, no userspace-fed sender survives unprivileged.
- Full matrix (kernel-tx, L1-L4 + 5min soak, ~11 min hostile load):
  one flap. A single echo delayed 28ms by softirq latency under hrtimer
  storm tripped the peer's 30ms detect at the margin; autonomous
  recovery (Down→Init→Up→Poll→Final) completed in **3.8ms**. Total
  session downtime across the matrix: under 4ms.

## Hardening

Beyond the original writeup: GTSM TTL-255 enforcement, RFC 5880
s6.8.6 your_disc demux validation (spoofed traffic can no longer
refresh liveness or be echoed), session-map creation gated on
control-plane config, per-session min_rx in the kernel detect path,
kernel TX packet counting, live remote-timer sync, poll-aware detect
budgets, self-initiated Poll sequences on parameter change, and
transitional userspace TX when the peer paces slower than the
required rate. Every fix carries wire evidence (pcap + analysis) in
docs/m5-hardening, including two invalidated test runs kept for the
record.

A later review-and-hardening pass (docs/refactor-abi) closed the
remaining edges and collapsed the kernel/userspace map structs into one
shared ABI header (`include/bfd_shared.h`) so the two sides can no
longer drift silently. On the wire it added: IP-options packets to the
BFD port dropped in XDP (they previously bypassed the GTSM/demux checks
via the variable header offset), oversized echo frames trimmed to 24
BFD bytes with a recomputed IP checksum, the RFC 5880 s6.8.7 jitter cap
at 90% for detect_mult 1, and a framing-error path that drops the bfddp
connection instead of resyncing mid-stream (which composes with
`--dp-hold` to reconnect without a data-plane outage). A FRR-notify gap
on the kernel map-path Down was also fixed. Each carries an injection
harness and evidence in docs/refactor-abi.

Graceful restart: `--dp-hold <sec>` keeps wire sessions alive across
bfdd restarts (orphan on disconnect, adopt on re-ADD with
discriminator continuity, mark-and-sweep reconciliation). Default 0
preserves drop-and-recreate. Verified: two back-to-back FRR restarts
with zero peer-visible events.

## Honest limitations

- IPv4 only, single-hop only, no authentication, no echo mode.
- Multi-session (64 slots, per-slot source ports 49152-49215, one
  bfd_tx instance per host) is validated at 16 concurrent sessions:
  independent detect, 0 flaps both under L3 stress, injection
  isolation (docs/m6-multisession). Higher session counts are
  untested.
- RX-clocked TX alone requires an async-clocked peer. The userspace
  transitional TX gate now fills at the full required pace whenever
  the peer's pacing lags our advertised rate (not just a slow-rate
  heartbeat), which also covers asymmetric-interval configurations;
  see docs/m5-hardening. Two RX-clocked ends remain untested.
- Shares fate with softirq latency (see the one flap above).
- Mid-session timer renegotiation is implemented (self-initiated
  RFC 5880 s6.8.3 Poll sequences, poll-aware detect budgets,
  transitional TX), wire-verified in docs/m5-hardening.
- All numbers from VMs (Proxmox/virtio, stress applied in-guest, wire
  truth captured host-side). Relative comparisons are load-bearing;
  absolute numbers await bare-metal validation.
- etf operational hazard, documented the hard way: a software etf
  qdisc silently drops all untimestamped traffic on its band —
  including ARP. Scope its filter precisely and tear it down after.

## Running under FRR (distributed BFD)

Works with stock FRR (tested: 10.5.1), no patches. bfdd hands session
lifecycle to this engine over its bfddp dataplane socket and displays
state/counters it reads back from us (counters come from the XDP maps).

1. `/etc/frr/daemons`:
   `bfdd_options="  --daemon -A 127.0.0.1 --dplaneaddr ipv4c:127.0.0.1:50700"`
2. Start the engine first: `sudo ./bfd_tx --dplane 50700 --kernel-tx <if>`
3. `systemctl restart frr`, configure peers in vtysh as usual.

Notes:
- Use the TCP transport. FRR's `unixc:` dataplane client mode fails with
  EINVAL: `bfd_dplane_client_init()` discards the caller's `salen` and
  passes `sizeof(union)` (= 112, padded by `sockaddr_in6` alignment) to
  `connect(2)`, which exceeds `sizeof(struct sockaddr_un)` (110) and is
  rejected for AF_UNIX. strace-confirmed. Reported upstream as
  [FRRouting/frr#22608](https://github.com/FRRouting/frr/issues/22608);
  fix submitted as [FRRouting/frr#22621](https://github.com/FRRouting/frr/pull/22621).
- `show bfd peers counters`: both input and output counts come from
  the XDP session map; kernel XDP_TX replies are counted per-packet.
- Default (`--dp-hold 0`): sessions are torn down when bfdd
  disconnects and recreated on reconnect (bfdd re-adds them).
  With `--dp-hold <sec>`: sessions survive a control-plane restart
  without data-plane interruption (orphan on disconnect, adopt by
  addr pair on re-ADD with discriminator continuity, mark-and-sweep
  reconciliation). Verified: two back-to-back FRR restarts, zero
  peer-visible events. See docs/m5-hardening.

## Repo layout

- `bfd_xdp.c` — XDP program: parser, session map, sweep timer, RX-clocked TX
- `bfd_tx.c` — userspace FSM daemon (`--dplane`, `--kernel-tx <if>`, `--dp-hold` modes)
- `loader.c` — standalone observer/loader (M2 tooling)
- `include/bfd_shared.h` — shared kernel/userspace map ABI and constants
- `docs/baseline/` — FRR bfdd stress characterization (pcaps + gap data)
- `docs/m3-bakeoff/` — five-way TX architecture comparison evidence
- `docs/m4-dplane/` — FRR distributed-BFD integration L4 run (pcap + window)
- `docs/final/` — full-matrix run of the kernel-tx path
- `docs/m5-hardening/` — RFC-correctness and graceful-restart wire evidence
- `docs/benchmarks/` — head-to-head resilience/detect/pacing/fast-path numbers
- `docs/m6-multisession/` — concurrent-session validation (pcap + gaps + isolation)
- `docs/refactor-abi/` — shared-ABI refactor, hardening closures, regression evidence

Every claim above has a pcap in this repo. Methodology: host-side
tcpdump on the hypervisor bridge as ground truth, window-sliced
inter-packet gap percentiles via tshark/awk, stress via stress-ng
ladders (fair CPU → sched churn → timer storm → SCHED_FIFO hogs).

## Roadmap

- ~~FRR distributed-BFD dataplane integration~~ **done** — see
  "Running under FRR" above
- Bare-metal benchmark reproduction
- IPv6
- Scale validation beyond 2 concurrent sessions

Prior art: [open-oam/bfd_program](https://github.com/open-oam/bfd_program)
(2020, abandoned proof-of-concept — XDP receiver and session validation; no released TX path). The 2018
SRv6/eBPF fast-reroute literature validated the speed hypothesis
academically.


## License

GPL-2.0 (see LICENSE). The bfddp wire-protocol struct definitions in
bfd_tx.c are adapted from FRR's bfdd/bfddp_packet.h, MIT licensed,
Copyright (C) 2020 NetDEF, Rafael F. Zalamena.
