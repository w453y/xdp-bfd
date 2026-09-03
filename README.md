# xdp-bfd

A BFD implementation (RFC 5880, RFC 5881, RFC 5883) with the fast path in XDP. Failure detection and packet transmission run in the driver path and in softirq, so they survive CPU load that makes userspace BFD daemons flap. It runs standalone, or as a dataplane for an unmodified FRR bfdd over FRR's own distributed-BFD protocol.

This started as a measurement project asking whether the folklore was true — that software BFD cannot hold aggressive timers under load. The answer turned out to be more interesting than the folklore, and the project became an implementation. The narrative is in [docs/writeup.md](docs/writeup.md); every number is reproducible from [docs/reproduction.md](docs/reproduction.md), and every claim has a packet capture or a kernel counter behind it in `docs/`.

## Status

| Capability | State |
|---|---|
| Asynchronous mode, RFC 5880 state machine | implemented |
| Single-hop (RFC 5881), GTSM TTL 255 | implemented |
| Multihop (RFC 5883), per-session minimum TTL, UDP 4784 | implemented |
| IPv4 and IPv6, one shared key and one fast path | implemented |
| Echo reflector (RFC 5880 s6.4), entirely in XDP | implemented, both families |
| Echo originator with RTT and loss accounting | implemented, IPv4 only, diagnostic |
| Poll sequences and mid-session renegotiation (s6.8.3) | implemented |
| `your_disc` demux validation (s6.8.6) | implemented |
| FRR distributed-BFD dataplane (bfddp) | implemented, stock FRR, no patches |
| Graceful control-plane restart (`--dp-hold`) | implemented |
| Authentication (s6.7) | not implemented |
| Demand mode (s6.6) | implemented |
| Concurrent sessions | 64, architectural cap |

## Quick start

```
make                                        # bfd_xdp.o, bfd_tx, bfd_loader
sudo ./bfd_tx <local-ip> <peer-ip> --kernel-tx <if>
```

Under FRR, see [Running under FRR](#running-under-frr-distributed-bfd). Full topology and stress setup: [docs/reproduction.md](docs/reproduction.md).

## Why

BFD is the failure detector under BGP, OSPF and IS-IS: two routers exchange small UDP packets at a negotiated interval, and if one side misses enough of them it declares the link dead and the routing protocol withdraws routes. The entire value of the protocol is timing. An implementation that sends late is worse than no BFD at all, because a false timeout tears down routes for a link that is fine — the failure detector becomes the failure.

Measured against FRR bfdd 10.5.1 on a 3x10ms session (30ms detect budget), escalating stress-ng load on the BFD host, gaps taken from a host-side capture:

| Level | Load | p50 | p99 | max gap | session |
|---|---|---|---|---|---|
| L1 | 4x CPU hogs (fair sched) | 8.81 | 10.03 | ~10ms | survived |
| L2 | 8x CPU + context-switch churn | 8.73 | 10.03 | 750ms | flapped |
| L3 | CPU + timer/timerfd/hrtimer pressure | 8.82 | 10.16 | 970ms | 44 flaps in 120s |
| L4 | 4x SCHED_FIFO prio-50 hogs | 8.82 | 287 | 960ms | flapped hard, ~40% of packets never sent |

The number that should worry anyone is not the 970ms. It is the p99 sitting at 10.16ms in the same run. Starvation events that kill sessions are rare — a handful per hundred seconds — so they are invisible to percentile monitoring. A dashboard graphing p99 packet spacing on that box would have shown a perfectly healthy daemon while it flapped 44 times.

The folklore also turned out to be wrong in an instructive way. A deliberately naive 160-line userspace daemon survived the same L3 stress that flapped bfdd 44 times, because a task that wakes 500 times a second and does microseconds of work accumulates almost no vruntime, so CFS treats it as the most deserving thing on the runqueue. Userspace was never the problem as a category; the shape of the wakeup path was. What no userspace architecture survives is SCHED_FIFO: the RT throttle reserves roughly 50ms per second for normal tasks, and no amount of scheduler friendliness helps when you exist for one breath per second. That is the failure this project is built against.

## Architecture

Four cooperating pieces, one interface.

**XDP RX and parser** (`src/xdp/`) parses and validates BFD control packets in the driver path and tracks per-session state in a BPF hash map. Timestamps are taken at actual packet arrival, which matters more than it sounds: during the RT-starvation runs the naive daemon's own log showed zero detect timeouts while the peer correctly declared the session dead, because packets had queued in the socket buffer and the daemon drained the backlog into a state machine that saw a smooth stream of arrivals. The parse path branches on ethertype; v6 sessions are keyed natively and v4 sessions v4-mapped (`::ffff:a.b.c.d`) in one shared map, so the two families cannot collide on a key.

**Detection sweep** runs one global `bpf_timer` at 5ms, comparing `now - last_seen` against each session's negotiated detect time and marking sessions in the map. XDP cannot see silence any more than it can originate — a dead link delivers no packets, so the program that would notice never runs. Detection therefore has to live outside the packet path. The kernel half is not the whole story, though: the state transition and the notification to bfdd both happen in the userspace loop, so detection shares fate with that loop rather than being independent of it. `docs/starved-detection/` measures exactly that. Making the kernel an authoritative detector needs a ringbuf consumer, which is `02-architecture` item 2.2 and is not done.

**RX-clocked kernel TX** is the core idea. XDP is an ingress hook: you can act on a packet that arrived, but you cannot originate one, and `bpf_timer` callbacks have no packet context to transmit from. So the engine stops trying to originate. In steady state the peer hands you a packet every interval, and every one of those is a packet context — swap the MACs and addresses, set the source port, rebuild the 24-byte payload from a config map userspace keeps current, and return `XDP_TX`. The frame leaves roughly 30us after it arrived, entirely in softirq. If the received packet carried Poll, the reply carries Final, so Poll sequences are answered faster than any userspace implementation could manage. The property this buys is that our transmit clock becomes the peer's transmit clock: there is no timer to service, no wakeup to miss, no process to starve.

**Userspace FSM** (`src/engine/`) keeps everything that does not need to be fast: session bring-up, the RFC 5880 state machine, the 1-second slow-rate transmission the RFC requires while a session is down, and exactly one packet at the moment of transition to Up. That last one earned its place the hard way — an earlier version suppressed all userspace TX on entering Up, which ate the Final answering the peer's Poll and produced a stable 32.6ms failure loop that looked healthy in every log and obvious in the pcap.

The kernel and userspace halves share one ABI header, `include/bfd_shared.h`. Its struct layouts *are* the BPF map value formats, so a field added on one side but not the other would be a silent map misread rather than a compile error. They were three hand-synced copies until the refactor-abi pass made them one.

## Results

Five TX architectures, identical conditions: 4x SCHED_FIFO prio-50 hogs, 60s, 3x10ms session, wire-truth capture.

| TX backend | flaps | p50 | p99 | max gap |
|---|---|---|---|---|
| FRR bfdd | continuous | 8.8 | 287 | 960ms |
| naive userspace loop | 25 | 10.0 | 12.0 | 324ms |
| userspace + `chrt -f 90` + pinned core | 0 | 10.0 | 13.0 | 15.0ms |
| SO_TXTIME + etf qdisc, one in flight | 48 | 10.0 | 13.2 | 1517ms |
| SO_TXTIME + etf qdisc, pipelined 5 deep | 48 | 10.0 | 10.1 | 994ms |
| **XDP RX-clocked (this project)** | **0** | **8.75** | **11.0** | **12.5ms** |

The p50 of 8.75ms rather than 10.00 is the signature. Every userspace backend produces 10.00ms, its own timer; the XDP path produces the peer's RFC-jittered distribution, echoed. The transmit clock has left userspace entirely.

The etf rows are the most instructive failure in the project. Zero packets were dropped by the qdisc, and the pipelined variant produced the best p99 of any backend tested — and it flapped 48 times, worse than doing nothing special. A starved daemon gives the qdisc nothing. Timestamping fixes jitter; it cannot manufacture liveness. Pipelining five packets buys 50ms of starvation tolerance against the RT throttle's 950ms drought, and deepening the pipeline does not help because pre-built packets carry pre-built protocol state. etf's tolerance equals pipeline depth, and depth is bounded by state staleness, not by etf.

**Full stress matrix**, complete ladder plus a five-minute soak, ordinary process priority, stock FRR on the far end:

| Level | p50 | p99 | max | flaps |
|---|---|---|---|---|
| L1 fair CPU | 8.97 | 10.03 | 13.3 | 0 |
| L2 sched churn | 8.83 | 10.01 | 12.0 | 0 |
| L3 timer storm | 8.72 | 10.11 | 28.0 | 1 |
| L4 RT hogs | 8.72 | 10.01 | 11.5 | 0 |
| 5-min soak | 8.77 | 10.01 | 10.7 | 0 |

The one flap is worth more than the column of zeros. Under the hrtimer storm one echoed reply in roughly 66,000 was delayed 28ms by softirq latency, and the peer's 30ms detect fired at the margin, correctly. Reconstructed from the capture: the peer's Down arrived, userspace noticed via the map within 3ms, transitioned, and answered the re-establishment Poll with Final 74us after it arrived. Down, Init, Up, Poll, Final — the complete handshake in 3.8ms. Total session downtime across eleven minutes of hostile load: under 4ms. So the honest characterization is not immunity. Kernel-path TX is immune to scheduler starvation but shares fate with softirq latency.

**Under FRR.** The same session created by an unmodified bfdd and offloaded over the bfddp dataplane protocol, under identical SCHED_FIFO stress: 0 flaps, p50 8.99, p99 11.01, max 13.01ms, uptime uninterrupted in FRR's own CLI. Putting FRR in the control loop cost nothing. A head-to-head run of the same ladder gives stock bfdd 107 flaps against 0.

**Scale.** 32 v4 plus 32 v6 at the 64-session cap, 3x10ms timers, through L3 and L4: 0 flaps in either family, wire transitions 0/0 across a 197-second window carrying 2.91M packets, per-slot maximum TX gaps in one band for both families — worst 14.5ms against a 30ms budget. The v4-only m6 baseline had shown correlated stall flaps at this session count; the dual-stack engine beats its own earlier result, and v6 is statistically indistinguishable from v4.

**Detection latency**, 20 peer kills, measured from the peer's last wire packet to the DUT's Down transition:

```
xdp-bfd   n=20  min=30.2  mean=31.3  p50=31.3  p99=32.4  max=32.6 ms
bfdd      n=20  min=30.0  mean=30.05 p50=30.0  p99=30.08 max=30.09 ms
```

bfdd is tighter at idle, and that is a real tradeoff rather than a rounding artifact: its detection runs on an hrtimer at almost exactly 3x the interval, while this engine's runs in the userspace loop, bounded by the configured tick. About 1.3ms of mean overshoot at the default. Under stress the figure is 33-34ms. That 1.3ms at idle buys scheduler immunity under load, which is the whole trade.

**Steady-state pacing**, 60s idle window: p50 8.77, p99 10.01, p999 10.05, max 10.08ms across 7295 packets. bfdd at idle is a twin (p50 8.79, p99 10.01) but already shows a tail past the interval at max 11.74ms. The entire xdp-bfd tail fits inside the 10ms interval, against a 30ms budget.

**Fast-path cost.** 701 ns mean per packet from in-kernel BPF run stats — parse, GTSM, length and demux validation, session map update, and on the echo path the full L2/L3/L4 rewrite plus `XDP_TX`, averaged across echo and non-echo packets.

## Correctness and hardening

Validation runs before anything else, and rejects die in XDP rather than reaching userspace. That distinction was found the hard way: an early spoof test showed GTSM and `your_disc` rejects returning `XDP_PASS`, so rejected packets were counted and *still* handed to the userspace socket, where a forged packet carrying our own discriminator overwrote session state and flapped a live session while detection was never fooled. Both reject sites became `XDP_DROP`. The verified rerun: 600 injected packets, 600 rejects, uptime unbroken.

Implemented since: GTSM TTL-255 enforcement; RFC 5880 s6.8.6 `your_disc` demux validation; session-map creation gated on control-plane config; per-session `min_rx` in the kernel detect path; live remote-timer sync; poll-aware detect budgets; self-initiated Poll sequences on parameter change; and transitional userspace TX when the peer paces slower than our required rate.

A later review pass added: IP-options packets to the BFD port dropped in XDP, because options push the UDP header to a variable offset and such packets were skipping the GTSM and discriminator checks entirely; oversized echo frames trimmed to 24 BFD bytes with a recomputed checksum; the s6.8.7 jitter cap at 90% when `detect_mult` is 1; and a framing-error path that drops the bfddp connection rather than resyncing onto arbitrary mid-stream bytes, which composes with `--dp-hold` into a hitless reconnect.

Some of the evidence records failures rather than successes. Two invalidated m5 runs are kept in the repo with the reason each one exercised nothing, because a test that agrees with you for the wrong reason is worse than no test.

**Tests.** `tests/` holds 33 single-packet injection cases covering every accept and reject rule the fast path applies, plus a graceful-restart test and a Poll-sequence observation test. Two rules the cases follow: every `+0` assertion needs a witness that must move, and nothing may disturb a live session. The first rule exists because a case once passed for months while sending nothing at all. See [tests/README.md](tests/README.md).

## Limitations

Each with the reason, since the reason is usually more useful than the fact.

**No authentication (RFC 5880 s6.7).** Not implemented.

**Demand mode does not poll on its own (s6.6).** The mode itself is implemented — the engine sets the D bit once both ends are Up, ceases periodic transmission while the peer is demanding, and holds off both its own detection and the kernel sweep while it is the one demanding — but nothing periodically initiates the Poll Sequence that would verify an idle path. `bfd_set_polling` is reached from a parameter change and nothing else, which is exactly what stock bfdd does, and matching it is deliberate: an engine that polled on a timer would report a link fault that bfdd on the same config would not. The consequence is the one `doc/user/bfd.rst` warns about — demand at both ends without echo can leave a failure undetected — and it is a property of demand mode as FRR implements it rather than of this dataplane.

One departure from bfdd is required, not optional. bfdd evaluates the transmit hold at each timer expiry, so by the time it stops it has already sent several D-marked packets. This engine can cease within a microsecond of the flag flipping, and both conditions arrive together: `r_state` only reaches Up when the peer's first Up-state packet lands, and if that peer is also demanding then the same packet carries its D bit. Ceasing immediately would mean going quiet having never once set D, leaving the peer transmitting forever into a session that will never ask it to stop — demand configured at both ends, achieved in one direction. So the engine sends `DEMAND_ANNOUNCE_N` D-marked packets before honouring the peer's request. Three, for the same reason `fsm_announce_down` sends three.

**64 concurrent sessions.** The cap is architectural rather than arbitrary: it is tied to the per-slot source port range 65472-65535, with one `bfd_tx` instance owning that range per host.

**RX-clocked TX requires an asynchronously-clocked peer, and two of these engines must not face each other.** The predicted failure was silence — nobody sends first after a gap — and the measurement found the opposite. Two engines with `--kernel-tx` on both sides transmit 690223 packets in five seconds against a configured 10ms interval, roughly 660 times the expected rate, sustained rather than a startup burst; the control arm with kernel-TX on one side only gives 1043. The sessions stay Up; the link does not. Nothing in the loop has a clock: each bounce arrives at the far side and triggers its bounce immediately, so the rate is bounded only by how fast two XDP programs can process frames. Against bfdd this is safe, because bfdd paces from its own timer and the bounce rate is bounded by the peer's clock. `docs/symmetric-ktx/` has the measurement. This is a deployment constraint rather than a bug, and probably an unfixable one: a rate limit in the bounce path means a timer in XDP, which is exactly what the RX-clocked design removed.

**Shares fate with softirq latency.** Immune to scheduler starvation, not to softirq delay — see the single 28ms graze in the matrix above. Under extreme timer pressure it touched the detect budget once in eleven minutes and self-healed in less than one packet interval.

**One known correlated-flap mode at scale.** In the v4-only 64-session run under L3 stress, a single RX-softirq stall flapped 19 sessions at once, recovering in about 50ms. That is the design's quantified false-flap boundary at capacity.

**Detection resolution is bounded by the loop tick.** About 1.3ms of mean overshoot above the RFC floor at the default tick, and 0.09ms at 200us — `docs/tick-ladder/` walks it down. This was described as sweep quantization until `docs/sweep-ladder/` falsified that; the cost is real, the mechanism named for it was not.

**Echo origination is a diagnostic, not a production capability.** XDP cannot originate packets: `XDP_TX` is a verdict on a frame that just arrived, which is exactly why the control path is RX-clocked. There is no timer callback that can transmit and no helper that produces a second packet from one; the kernel-side escape, `bpf_clone_redirect`, exists only for TC, and moving the control bounce to TC would mean skb allocation in the hot path and a rewrite of the mechanism the project rests on. That trade was declined. Echo transmission therefore runs from userspace over a raw socket and is exposed to scheduling. The reflector, which has a packet in hand, lives entirely in XDP and is the production capability.

**Echo detection is advisory and permanently so.** With userspace transmission, a local scheduling stall is indistinguishable from a path failure — echoes stop leaving, returns stop arriving, the timestamp goes stale. Feeding that into the state machine would convert our own scheduling delay into a teardown, which is the exact failure this engine exists to avoid. Verified from both sides: disabling forwarding on the neighbour stops the returns, loss climbs one-for-one, echo liveness flips, and all 64 control sessions stay up.

**Echo origination is IPv4 only.** The reflector handles both families.

**The cost of echo at 64 sessions is bounded, not zero.** Measured as under roughly 5ms of median transmit-gap spread: the reference build's own median spans 22.3 to 27.1ms across two runs and the echo build sits at 23.2ms inside that spread. Flap count was abandoned as a metric at this scale because it varies from 0 to 20 across runs of identical code.

**Multihop at scale is unmeasured.** The 64-session ladder was not re-run with multihop sessions present, and v4 and v6 multihop were not exercised simultaneously at scale.

**All numbers are from VMs.** Proxmox with virtio-net, stress applied inside the guest, wire truth captured host-side on the hypervisor bridge. The stress hit every backend identically, so the comparisons are load-bearing; the absolute figures await bare-metal reproduction.

## Running under FRR (distributed BFD)

Works with stock FRR (tested: 10.5.1), no patches. bfdd creates and owns the sessions, assigns discriminators, and displays state and counters; the packets ride the XDP path, and `show bfd peers counters` reports counts read out of a BPF map.

1. `/etc/frr/daemons`: `bfdd_options="  --daemon -A 127.0.0.1 --dplaneaddr ipv4c:127.0.0.1:50700"`
2. Start the engine first: `sudo ./bfd_tx --dplane 50700 --kernel-tx <if>`
3. `systemctl restart frr`, then configure peers in vtysh as usual.

Notes:

- **Reserve the dplane port** from the ephemeral range (`net.ipv4.ip_local_reserved_ports = 50700`). A bfdd dplane client retrying against a missing listener can TCP self-connect to 127.0.0.1:50700 and permanently steal the port from the engine; SO_REUSEADDR does not recover it. Do *not* also reserve the slot range 65472-65535 — `reserved_ports` blocks explicit `bind()` as well as ephemeral assignment, so the engine could not bind its own slots.
- **With more than ~20 peers on a packaged release**, keep the bfd block out of `frr.conf` and add peers via vtysh after the dplane connects. FRR 10.5.1 truncates the initial registration burst at its 8KB output buffer with no retry, stranding the remainder with software BFD already disabled.
- **Use the TCP transport on packaged releases.** `unixc:` client mode fails every connect with EINVAL.
- `--dp-hold <sec>` keeps wire sessions alive across a bfdd restart: orphan on disconnect, adopt live sessions by address pair on re-ADD with discriminator continuity, sweep sessions bfdd did not re-register, hard teardown at the deadline if bfdd never returns. Default 0 preserves drop-and-recreate. Verified with two back-to-back FRR restarts and zero peer-visible events. It also makes the reconnects caused by the counters bug below wire-invisible.
- Note the asymmetry a clean shutdown creates: with master bfdd a clean restart is *not* hitless under `--dp-hold`, because delivered DELETEs are honored as teardowns. A SIGKILL, which sends nothing, is strictly more hitless than a clean stop.

## Upstream bugs found

Building and validating against stock FRR surfaced six bugs in bfdd — three fixes merged, three in review. Most were reduced to arithmetic and shipped with an engine-free reproducer: byte-counting TCP responders that need no dataplane implementation at all, so a maintainer can reproduce them without any of this code.

| Bug | Issue | Fix | Status |
|---|---|---|---|
| `unixc:` client passes `sizeof(union)` (112) as addrlen to `connect(2)`, exceeding `sizeof(sockaddr_un)` (110); unix client mode had plausibly never worked on Linux | [#22608](https://github.com/FRRouting/frr/issues/22608) | [#22621](https://github.com/FRRouting/frr/pull/22621) | merged |
| Registration burst overflows the 8KB output buffer; delivered sessions register, the rest are stranded with software BFD already disabled and no retry | [#22638](https://github.com/FRRouting/frr/issues/22638) | [#22645](https://github.com/FRRouting/frr/pull/22645) | merged |
| No RFC 5880 s6.8.9 echo-interval negotiation for offloaded sessions, so the dataplane transmits at the locally configured interval regardless of what the neighbour advertised | [#22804](https://github.com/FRRouting/frr/issues/22804) | [#22805](https://github.com/FRRouting/frr/pull/22805) | merged |
| Clean shutdown enqueues one DELETE per session and exits without draining the buffer, delivering exactly 58 of 64 | [#22691](https://github.com/FRRouting/frr/issues/22691) | [#22692](https://github.com/FRRouting/frr/pull/22692) | in review |
| `show bfd peers counters` never reclaims consumed input-buffer space; a full buffer is then misread as the peer closing, so bfdd RSTs a healthy connection at a deterministic reply ordinal | [#22693](https://github.com/FRRouting/frr/issues/22693) | [#22694](https://github.com/FRRouting/frr/pull/22694) | in review |
| IPv6 echo packets are sent on a shared per-VRF socket with no source bound, so the kernel picks an arbitrary interface address and the receiver's reflection guard — which keys on the session's address pair — drops every one | [#22875](https://github.com/FRRouting/frr/issues/22875) | [#22920](https://github.com/FRRouting/frr/pull/22920) | in review |

Two are worth a note. The echo-interval bug had two halves facing each other across the socket: the daemon never negotiated, and the engine was hardcoding the neighbour's advertised interval to zero, so the daemon-side fix would have had no input. The engine also advertised its own Required Min Echo RX as zero, which RFC 5880 s4.1 defines as "cannot receive echo packets" — meaning no conforming neighbour would ever have echoed at it, which explains why every reflector test before that had used a hand-built frame.

The IPv6 echo bug is a regression rather than a longstanding gap, introduced by a March 2026 commit that gated v6 echo reflection on known sessions. The hardening it added is correct and the fix preserves it; the problem is on the sending side, and it bites whenever the sender has more than one IPv6 address on the interface, which is the normal case on a router. It does not fail silently either — enabling v6 echo takes a working session down. It is also the one bug here reproducible with configuration alone, no dataplane involved.

Packaged releases up to 10.5.1 do not yet carry the merged fixes, so the workarounds above apply until a release ships them.

## Repo layout

- `src/xdp/` — the XDP program and its helpers: `bfd_xdp.c` (parse, dispatch, session update), `parse.h`, `validate.h`, `maps.h`, `stats.h`, `sweep.h`, `csum.h`, `echo.h`, `tx.h`, `tunables.h`
- `src/engine/` — the userspace daemon: `main.c` (argv and the RX loop), `session.c` (session table), `dplane.c` (bfddp socket), `ktx.c` (kernel-TX mirror), `fsm.c` (RFC 5880 state machine), `echo_tx.c` (echo originator), `bffdp.h` (FRR wire protocol)
- `src/loader/` — standalone observer and loader
- `include/bfd_shared.h` — the shared kernel/userspace map ABI, wire format and constants
- `tests/` — injection matrix, graceful-restart and Poll/Final scripts

## Evidence

Methodology: host-side tcpdump on the hypervisor bridge as ground truth, because the host sees actual wire times and does not care what a guest's processes believe. Window-sliced inter-packet gap percentiles via tshark and awk. Stress via stress-ng ladders — fair CPU, then sched churn, then timer storm, then SCHED_FIFO hogs. `XDP_DROP` and `XDP_TX` are both invisible to a capture taken on the DUT, so kernel counters are the only trustworthy signal for those.

| Directory | What it holds |
|---|---|
| `docs/writeup.md` | the full narrative: problem, bake-off, design, results, method |
| `docs/reproduction.md` | topology, stress ladder, run modes, and the pitfalls |
| `docs/baseline/` | FRR bfdd stress characterization, the L1-L4 ladder |
| `docs/m3-bakeoff/` | the five-way TX architecture comparison |
| `docs/m4-dplane/` | FRR distributed-BFD integration under L4 |
| `docs/final/` | the full-matrix run of the kernel-tx path |
| `docs/m5-hardening/` | RFC correctness, graceful restart, spoof injection, and two invalidated runs |
| `docs/benchmarks/` | head-to-head resilience, detect, pacing and fast-path numbers |
| `docs/m6-multisession/` | concurrent sessions, scale to 64, kill isolation |
| `docs/refactor-abi/` | the shared-ABI refactor and the review pass it came from |
| `docs/m7-ipv6/` | dual-stack: unified key, v6 parse and reply, ladder and spoof evidence |
| `docs/m8-echo/` | echo reflector, originator, and the upstream negotiation fix |
| `docs/m9-multihop/` | per-session minimum TTL, port 4784, TTL restore on reply |

## Roadmap

Bare-metal benchmark reproduction. Everything else on the original roadmap is done: FRR integration, session continuity across control-plane restarts, multi-session, IPv6, echo mode, multihop.

Prior art: [open-oam/bfd_program](https://github.com/open-oam/bfd_program) (2020, abandoned proof-of-concept — an XDP receiver and session validation, no released TX path). The 2018 SRv6/eBPF fast-reroute literature validated the speed hypothesis academically.

## Method

Every bug in this project was found by a packet capture, and not one was found by a log. The Init-loop from a stale transmit schedule after timer renegotiation; the socket buffer convincing a starved daemon that packets were arriving on time; the etf qdisc blackholing ARP; the pipeline scheduling Poll answers a second into the future; the eaten Final; the same timestamp-race bug written twice by the same author on two sides of the kernel boundary; a multihop test suite that passed while sending to the wrong port entirely. All of them produced healthy-looking logs and a wire that told a different story.

What survived is worth stating: an observer outside the system under test, distributions rather than averages, and a refusal to let any claim stand untested when a capture could settle it.

## License

GPL-2.0 (see LICENSE). The bfddp wire-protocol struct definitions in `src/engine/bffdp.h` are adapted from FRR's `bfdd/bfddp_packet.h`, MIT licensed, Copyright (C) 2020 NetDEF, Rafael F. Zalamena.

