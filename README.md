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
   socket-buffer queueing illusions). Dual-stack: the parse path
   branches on ethertype, v6 sessions are keyed natively and v4
   sessions v4-mapped (::ffff:a.b.c.d) in one shared map, so both
   families ride the same fast path.
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

## IPv6

The engine is dual-stack (docs/m7-ipv6, branch m7-abi-key). The
session key is two 16-byte addresses; v4 is stored v4-mapped so both
families share one hash map, one slot-socket pool, and the same XDP
fast path with no key collisions. The v6 parse path enforces GTSM as
hop_limit 255, PASSes non-UDP first headers so ICMPv6 (ND, MLD, RA)
survives, and deliberately does not walk extension headers —
extension-header-hidden UDP never reaches a session. The kernel
XDP_TX reply is family-branched: the v6 echo recomputes the full UDP
checksum over the swapped pseudo-header before `bpf_xdp_adjust_tail`,
and oversized frames are trimmed to 24 BFD bytes with `payload_len`
patched (there is no IP checksum to fix in v6).

The kernel reply is what makes v6 equal to v4. Measured on one engine
with both families live through the L3+L4 ladder at 3x300ms:
userspace-paced v6 TX flapped 19 times under SCHED_FIFO (TX max
1900ms — the RT throttle again) while v4 kernel TX ran clean; with
the v6 kernel reply enabled, v6 ran the same ladder at 0 flaps, TX
max 300.5ms, indistinguishable from v4. The v6 spoof harness
(spoof6.py) repeats the m5 validation: wrong your_disc and hop_limit
!= 255 are XDP_DROPped and counted, and the oversized-echo trim is
verified against real traffic. Each of the five landing steps carries
a v4 regression check, so the shared code never regressed the working
v4 path.

Mixed-family scale is validated: 32 v4 + 32 v6 at the 64-session cap,
3x10ms timers, through the full L3+L4 stress ladder — 0 flaps in
either family, wire transitions 0/0, per-slot max TX gaps in one
band for both families (worst 14.5ms, under half the 30ms detect
budget), beating the v4-only m6 baseline which showed correlated
stall flaps at this N. The same mesh was validated against FRR master
carrying the merged burst-truncation fix
([FRRouting/frr#22645](https://github.com/FRRouting/frr/pull/22645)):
64/64 registrations on connect and on restart, Output full events 0.
Evidence in docs/m7-ipv6/.

Graceful restart: `--dp-hold <sec>` keeps wire sessions alive across
bfdd restarts (orphan on disconnect, adopt on re-ADD with
discriminator continuity, mark-and-sweep reconciliation). Default 0
preserves drop-and-recreate. Verified: two back-to-back FRR restarts
with zero peer-visible events.

## Echo mode

BFD echo (RFC 5880 s6.4, UDP 3785) in two roles sharing one
mechanism (docs/m8-echo).

The reflector is the production capability and lives entirely in XDP:
a self-addressed echo arriving at TTL 255 from a peer with echo
enabled is MAC-swapped, TTL-decremented, checksum-recomputed and
XDP_TX'd, with no session lookup and the payload untouched. A policy
guard keyed on echo-active peers prevents it becoming an amplification
vector. The point is what the host is not doing: with ip_forward=0 the
stack discards a self-addressed echo as a martian, so none of these
frames would be returned without the reflector. Measured against a
stock FRR neighbour originating its own echoes, 433 of 433 reflected,
12us minimum and 30us average turnaround at the bridge.

The originator is a diagnostic. XDP cannot originate packets — XDP_TX
is a verdict on a frame that just arrived, which is why the control
path is RX-clocked — so echo transmission runs from userspace and is
therefore exposed to scheduling. Returns are recognised in XDP and
demuxed on the discriminator carried in the payload (the source
address is our own and cannot name a session). Round-trip time and
loss are tracked per session, and echo liveness is reported but
deliberately never merged into the session verdict: with userspace
transmission a local stall is indistinguishable from a path fault, so
treating it as one would turn a scheduling delay into a teardown.

Implementing this surfaced an upstream bug in the echo-interval
negotiation for offloaded sessions, fixed in FRRouting/frr#22805 with
the engine side reporting and advertising the values that make the
negotiation work. Cost at 64 sessions is below what the testbed can
resolve (~5ms of median transmit-gap spread); see docs/m8-echo.

## Honest limitations

- Single-hop only, no authentication.
- Multi-session (64 slots, per-slot source ports 65472-65535, one
  bfd_tx instance per host) is validated at the full 64 sessions,
  including the 32 v4 + 32 v6 mixed-family split (docs/m7-ipv6):
  independent detect at mass-kill (32 simultaneous, all 30-33ms),
  injection isolation, and one known correlated-flap mode - a single
  RX-softirq stall under timer stress flapped 19 sessions at once,
  recovered in ~50ms (docs/m6-multisession).
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
   With more than ~20 peers, keep the bfd block out of frr.conf and
   add peers via vtysh after the dplane connects: FRR 10.5.1's dplane
   client truncates the initial session burst at 8KB (~20 sessions)
   with no resend (docs/m6-multisession/scale-64.txt, bug 2;
   [FRRouting/frr#22638](https://github.com/FRRouting/frr/issues/22638)). Fixed upstream in
   [FRRouting/frr#22645](https://github.com/FRRouting/frr/pull/22645)
   (merged to master): the enqueue path flushes the output buffer
   before failing, and a session whose dataplane registration fails
   falls back to the software implementation instead of being
   silently stranded. Packaged releases up to 10.5.1 still carry the
   bug, so the vtysh workaround applies until a release ships the fix.

Notes:
- Reserve the dplane port from the ephemeral range
  (`net.ipv4.ip_local_reserved_ports = 50700`): a bfdd dplane client
  retrying against a missing listener can TCP self-connect
  127.0.0.1:50700 and permanently steal the port from the engine;
  SO_REUSEADDR does not recover it. Do not also reserve the slot
  range 65472-65535 — reserved_ports blocks explicit bind() too, and
  the engine could then not bind its own slots.
- Use the TCP transport. FRR's `unixc:` dataplane client mode fails with
  EINVAL: `bfd_dplane_client_init()` discards the caller's `salen` and
  passes `sizeof(union)` (= 112, padded by `sockaddr_in6` alignment) to
  `connect(2)`, which exceeds `sizeof(struct sockaddr_un)` (110) and is
  rejected for AF_UNIX. strace-confirmed. Reported upstream as
  [FRRouting/frr#22608](https://github.com/FRRouting/frr/issues/22608);
  fixed upstream in
  [FRRouting/frr#22621](https://github.com/FRRouting/frr/pull/22621)
  (merged to master, reviewed by the dplane author). Packaged
  releases up to 10.5.1 still carry the bug, so use TCP with them.
- Two further upstream bfdd dataplane bugs were found while validating
  at 64 sessions, both with engine-free reproducers and fixes in
  review: session DELETEs are silently lost on clean shutdown because
  the output buffer is never drained before close
  ([FRRouting/frr#22691](https://github.com/FRRouting/frr/issues/22691),
  fix [#22692](https://github.com/FRRouting/frr/pull/22692)); and
  `show bfd peers counters` tears down the dataplane connection because
  `bfd_dplane_expect()` never reclaims consumed input-buffer space and
  misreads a full buffer as the peer closing
  ([FRRouting/frr#22693](https://github.com/FRRouting/frr/issues/22693),
  fix [#22694](https://github.com/FRRouting/frr/pull/22694)). Until the
  latter is merged, avoid polling `show bfd peers counters` against a
  dataplane at scale, or run with `--dp-hold` so the resulting
  reconnects are wire-invisible. A third was found while implementing
  echo: for a session offloaded to a dataplane, bfdd never performs the
  RFC 5880 s6.8.9 echo-interval negotiation, so the dataplane transmits
  echo at the locally configured interval regardless of what the peer
  advertised it can receive
  ([FRRouting/frr#22804](https://github.com/FRRouting/frr/issues/22804),
  fix [#22805](https://github.com/FRRouting/frr/pull/22805)).
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
- `docs/m7-ipv6/` — dual-stack: unified key, v6 parse/reply, ladder + spoof evidence
- `docs/m8-echo/` — echo mode: reflector, originator/detector, upstream negotiation fix

Every claim above has a pcap in this repo. Methodology: host-side
tcpdump on the hypervisor bridge as ground truth, window-sliced
inter-packet gap percentiles via tshark/awk, stress via stress-ng
ladders (fair CPU → sched churn → timer storm → SCHED_FIFO hogs).

## Roadmap

- ~~FRR distributed-BFD dataplane integration~~ **done** — see
  "Running under FRR" above
- ~~IPv6~~ **done** — dual-stack, validated to the 64-session
  mixed-family cap through the stress ladder; see "IPv6" above
- ~~Echo mode~~ **done** — XDP reflector and
  originator/detector; see "Echo mode" above
- Bare-metal benchmark reproduction

Prior art: [open-oam/bfd_program](https://github.com/open-oam/bfd_program)
(2020, abandoned proof-of-concept — XDP receiver and session validation; no released TX path). The 2018
SRv6/eBPF fast-reroute literature validated the speed hypothesis
academically.


## License

GPL-2.0 (see LICENSE). The bfddp wire-protocol struct definitions in
bfd_tx.c are adapted from FRR's bfdd/bfddp_packet.h, MIT licensed,
Copyright (C) 2020 NetDEF, Rafael F. Zalamena.

