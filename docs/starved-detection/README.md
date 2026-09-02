# Starved detection

Detection latency when the userspace loop is starved, measured on the engine and
independently on the wire.

## What this measures

`docs/sweep-ladder/` established that in engine mode detection is entirely
userspace. The only diag 1 transition is `fsm_detect` in `src/engine/fsm.c`, and
the kernel sweep's output (clear `st->alive`, emit a ringbuf event) has no
consumer in engine mode. Every number in that directory was taken at idle.

This directory measures the case the idle ladder could not reach: the peer goes
silent while the userspace loop is starved by a real-time stressor. Detection is
the half of BFD that runs in the loop being starved. Transmit is not, because
RX-clocked TX answers the peer from softirq.

## Method

`tests/starved_detection.py`, one sample at a time:

1. Start `tcpdump` on the Proxmox host on `vmbr3`, filtered to the one session
   pair. The pid is echoed and the capture is killed by pid, not by `pkill`,
   because `pkill` patterns match the ssh and sudo wrappers.
2. Blackhole the peer's egress for that pair with an iptables rule on the PEER.
   It has to be the peer: XDP runs before netfilter, so a DUT-side rule never
   sees BFD packets and the fast path would keep answering them.
3. Start the stressor on the DUT:

   ```
   sudo stress-ng --cpu 4 --sched fifo --sched-prio 50 --timeout 2s
   ```

4. Poll the SIGUSR1 stats snapshot until the session reports Down, and read
   `last_overshoot_us`.
5. Stop the capture BEFORE removing the iptables rule. Once traffic resumes the
   pcap holds a second event and "last packet from the peer" stops naming the
   right one.
6. Fetch the pcap and take the gap between the peer's last packet and the DUT's
   first `State Down`.

The two numbers come from different clocks on different machines. The engine's
is its own accounting from inside the starved process. The wire's is a capture
on the hypervisor, outside the machine under test.

## Result

n=10, 2s starvation, 5000us sweep interval.

| sample | engine (ms) | wire (ms) | diff (ms) |
|--------|-------------|-----------|-----------|
| 01 | 944.62 | 974.75 | 30.14 |
| 02 | 941.89 | 972.04 | 30.15 |
| 03 | 948.89 | 979.02 | 30.13 |
| 04 | 952.15 | 985.12 | 32.97 |
| 05 | 946.71 | 976.88 | 30.18 |
| 06 | 943.93 | 974.05 | 30.12 |
| 07 | 948.53 | 978.67 | 30.14 |
| 08 | 945.84 | 975.99 | 30.15 |
| 09 | 940.88 | 971.04 | 30.16 |
| 10 | 943.47 | 973.70 | 30.23 |
| **mean** | **945.69** | **976.13** | **30.44** |

Engine: mean 945.69ms, sd 3.46ms, range 940.88 to 952.15ms.
Wire: mean 976.13ms, sd 4.10ms, range 971.04 to 985.12ms.

The difference between the two columns is the detect budget (3 x 10ms). It lands
between 30.12 and 32.97ms on every row against a nominal 30ms, so the engine's
self-report and an external capture agree on all ten samples. Row 04 is the only
one more than a transmit interval away from the budget.

At idle, the same sweep interval gives a mean overshoot of 1.36ms
(`docs/sweep-ladder/`). Starved, detection runs about 31x the 30ms budget it
exists to enforce.

## The bound is the kernel's, not the engine's

6s of starvation gives the same result as 2s (~947ms), so the delay does not
scale with the starvation window. It is bounded at one RT period. The DUT reads
`sched_rt_runtime_us` 950000 against `sched_rt_period_us` 1000000, so SCHED_FIFO
tasks get at most 950ms of every second and the non-RT engine gets the remaining
50ms. It detects in that slice.

Two consequences. The bound comes from the scheduler rather than from anything
in the engine's design. And on a host with RT throttling disabled
(`sched_rt_runtime_us = -1`), which real-time deployments do set, a starved
engine would not detect at all. That case is not measured here.

## What this does and does not undermine

The project's headline result (0 flaps against bfdd's 107 under the same ladder)
is about TRANSMIT. XDP answers the peer from softirq, so the peer never sees the
DUT go quiet. That result stands unchanged.

It says nothing about noticing a quiet peer, and that half runs entirely in the
loop being starved. The engine is scheduler-immune in one direction only. Before
this measurement that was not stated anywhere.

## Two things this capture does not show

Neither of these can be read out of the pcaps, and both were claimed at some
point while the measurement was being taken.

The combined stream is silent for the whole window, but that is NOT evidence
that RX-clocked TX correctly stops for a dead session. The peer is blackholed,
so there is nothing to bounce, and the starved userspace cannot transmit either.
The capture cannot distinguish the two.

The harm is a delayed LOCAL notification, not a lie on the wire. The DUT goes
quiet, so the peer detects on its own 30ms budget and converges normally;
recovery is visible in the captures as the peer sending Init as soon as the
block lifts. What is late by roughly 976ms is our own control plane's knowledge,
because bfdd learns nothing until the engine's loop next runs.

An exploratory capture taken before the script shows the boundary exactly: the
peer's last packet, then two more Up packets from the DUT at its normal 10ms
rate (20ms of continued transmit, well inside the 30ms budget), then silence
until the DUT's `State Down` 976ms after the peer stopped.

## Limits

- One session pair, single-hop IPv4.
- One starvation profile. 2s and 6s were both run and agree; nothing between or
  beyond either.
- Default RT throttling only.
- Nothing here covers a session that stays up under starvation but should go
  down for a reason other than peer silence.

## Not fixed here, and why

Wiring `ktx_poll_map` to act on the kernel sweep's `alive` flag does not help:
`ktx_poll_map` runs in the loop being starved, and only userspace can notify
bfdd. Making the kernel a real detector needs a ringbuf consumer, which is
`02-architecture` item 2.2 and touches the main loop's pacing.

## Two documents corrected 2026-09-02

The root `README.md` and `docs/benchmarks/README.md` result 2 both attributed
detection overshoot to 5ms sweep quantization and described detection as
kernel-side. `docs/sweep-ladder/` falsified the first and this document the
second. Both now say the overshoot is bounded by the loop tick, and that the
transition and the notification to bfdd run in the loop being starved rather
than independently of it. `docs/baseline/` carried the same quantization claim
and was corrected with them. The measurements in all three were never in
doubt; only the mechanism named for them.

## Files

- `sample-01.pcap` through `sample-10.pcap`, one per sample, hypervisor-side on
  `vmbr3`, filtered to the session pair and cut before the block was lifted
- `samples.json`, the engine and wire series plus the run parameters
- `exploratory/starve.pcap`, the pre-script capture the boundary
  example above is taken from; it spans several events, not one sample

Regenerate with `python3 tests/starved_detection.py`.

