# xdp-bfd

BFD (RFC 5880/5881) with the fast path in XDP — failure detection and
transmission that survive CPU load that kills userspace BFD daemons.

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

Three cooperating pieces, one interface:

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

The p50 of 8.75ms (not 10.00) is the signature: the wire distribution
is the peer's own jittered TX echoed from softirq — the transmit clock
has left userspace entirely.

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

## Honest limitations

- Single session, IPv4, single-hop, no authentication, no echo mode.
- RX-clocked TX requires an async-clocked peer; two RX-clocked ends
  would deadlock. The userspace slow-rate heartbeat is the recovery
  spark.
- Shares fate with softirq latency (see the one flap above).
- Mid-session timer renegotiation (Poll sequences we initiate) is
  minimal.
- All numbers from VMs (Proxmox/virtio, stress applied in-guest, wire
  truth captured host-side). Relative comparisons are load-bearing;
  absolute numbers await bare-metal validation.
- etf operational hazard, documented the hard way: a software etf
  qdisc silently drops all untimestamped traffic on its band —
  including ARP. Scope its filter precisely and tear it down after.

## Repo layout

- `bfd_xdp.c` — XDP program: parser, session map, sweep timer, RX-clocked TX
- `bfd_tx.c` — userspace FSM daemon (`--txtime`, `--kernel-tx <ifname>` modes)
- `loader.c` — standalone observer/loader (M2 tooling)
- `docs/baseline/` — FRR bfdd stress characterization (pcaps + gap data)
- `docs/m3-bakeoff/` — five-way TX architecture comparison evidence
- `docs/final/` — full-matrix run of the kernel-tx path

Every claim above has a pcap in this repo. Methodology: host-side
tcpdump on the hypervisor bridge as ground truth, window-sliced
inter-packet gap percentiles via tshark/awk, stress via stress-ng
ladders (fair CPU → sched churn → timer storm → SCHED_FIFO hogs).

## Roadmap

- FRR distributed-BFD dataplane integration (`bfddp_packet.h` socket
  protocol — no FRR patching required)
- Multi-session, IPv6
- Bare-metal benchmark reproduction

Prior art: [open-oam/bfd_program](https://github.com/open-oam/bfd_program)
(2020, abandoned proof-of-concept — XDP receiver and session validation; no released TX path). The 2018
SRv6/eBPF fast-reroute literature validated the speed hypothesis
academically.
