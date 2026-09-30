# m12: bare metal

Every number before this was taken on Proxmox VMs, and every writeup said
the absolute figures awaited a bare-metal run. This is that run, at the
session count the engine now ships for, against the stress ladder the
project started with. It found three things the VMs had not, and all three
were fixed before this was written: [#24](https://github.com/w453y/xdp-bfd/pull/24),
[#25](https://github.com/w453y/xdp-bfd/pull/25) and
[#26](https://github.com/w453y/xdp-bfd/pull/26). Earlier the same day it
found the one behind [#23](https://github.com/w453y/xdp-bfd/pull/23).

## The rig

Four machines and a switch, no hypervisor anywhere.

| | | |
|---|---|---|
| m1 | DUT: engine + FRR master bfdd over bfddp | i5-12500 (12 threads), Intel I210 (igb, native XDP) |
| m2 | peer: FRR master bfdd, every session in software | same |
| m3 | load generator, and where captures are analysed | same |
| m4 | capture only | Dell VEP1400-X, Atom C3558, Intel I350 |

Test ports on an isolated Cisco SG300-28 at 1G, management on a separate
network. The switch mirrors what m1 and m2 **send** (port RX in the
switch's terms) to m4's port, so every BFD packet between them is captured
once, with the NIC's hardware receive timestamp
(`tcpdump -j adapter_unsynced`). This replaces the hypervisor bridge as the
observer outside the system under test. A 10 s cross-check against m2's own
NIC agreed to 0.2%, the difference being start and stop skew, with nothing
dropped by either capture. DSCP CS6 goes to a strict-priority queue on the
switch.

The mesh is the VM regression mesh moved over whole: 1022 sessions and 2
phantoms, v4 and v6, echo, demand, keyed and meticulous SHA1, passive at
either end, multihop, asymmetric timers, 50 ms to 1 s. The 40 sessions of
its 100 ms class were set to 10 ms x3, so the ladder's original timers are
in it too (`v4-10` in the tables).

## The ladder

As in `reproduction.md`, scaled from 4 vCPUs to 12 threads, one capture per
run: 30 s idle, L3 (`stress-ng --cpu 12 --timer 24 --timerfd 12 --hrtimers
6`, 120 s), L4 (`--cpu 12 --sched fifo --sched-prio 50`, 60 s), 30 s idle.
`tools/run.sh`. Flaps are counted on the wire, as a sender's state leaving
Up, and cross-checked against both bfdds' down counters. Those agreed
exactly on every engine run; for A1 the peer counted 19426 against 18910
on the wire, stock bfdd's sessions flapping faster than a packet can show.

## Results

| run | DUT | flaps | sessions |
|---|---|---|---|
| A0 | stock bfdd, idle 5 min | 0 | 0 |
| B0 | engine, idle 5 min | 0 | 0 |
| A1 | stock bfdd | 18910 | 957 |
| B1 | engine as on the VMs: normal priority, dead-man 1 s | 698 | 213 |
| B2 | B1, `--deadman-us 0` | 265 | 79 |
| B3 | B1, `--deadman-us 2000000` | 261 | 84 |
| B5-B7 | B3 plus the three demand fixes, one at a time | 227, 214, 116 | |
| B4a | #24 + #25, engine `SCHED_FIFO` 10 (the unit's priority then) | 957 | 957, once each |
| B4b | #24 + #25, `SCHED_FIFO` 51 | **0** | 0 |
| B4c | #24 + #25, `SCHED_FIFO` 60 | **0** | 0 |
| B9 | main `fc32c4f` (#23-#26), `SCHED_FIFO` 60 | **0** | 0 |

L3 did nothing to either implementation on 12 threads. Everything above
happened in L4.

In B9 every class's largest gap stayed within 0.68 of the receiver's
detection time, exactly as at idle; the 10 ms sessions' largest was 20.2 ms
against 30. Stock bfdd under the same ladder stalled for up to 2.5 s, took
down sessions with a 5 s detection time, and kept flapping for 1625 more
events after the stress had stopped.

## 1. The dead-man gate tripped on a live engine

The VMs never ran the ladder with the gate; it came in with m11, after m7's
64-session runs. m11 chose its 1 s bound from the loop's gap histogram on
an idle mesh (worst 16-32 ms). `investigations/starved-detection/` had
already measured what the loop does under L4: it runs once per RT
throttling period, about 945 ms apart. The two were never put side by side.

At 1024 sessions the loop's gaps under L4 reached the 1.05-2.1 s bucket, the
gate withheld 4610 replies from an engine that was only starved, and the
peer took 213 sessions down (B1). With the gate off or at 2 s (B2, B3), no
session the fast path answers flapped at all, 10 ms x3 included, as m7 had
shown at 64. Five runs never went past the 2.1 s bucket; #25 makes the
default 3 s, three throttling periods.

## 2. A demanding session timed out its own answered Poll

With the gate out of the way, the demand class still flapped 50 to 59
times a run, every one declared by us: diag 1, after the peer had answered
each Poll it received within 0.1 ms. Three separate causes, found in that
order because fixing each moved the count only a little (B5: 35, B6: 42):

- A loop back after the Final read the ack only in `fsm_detect`'s sync,
  which ended the Poll and then measured the silence we had asked for.
- The Poll reached the program's copy of `tx_cfg` only at the end of the
  visit, after it had left, so a loop preempted in between let the Final
  arrive to a copy without the Poll and it was never acked.
- Starting a Poll restarted the detection clock, but the Poll waited for
  the next periodic slot, and a starved loop timed out a Poll it had never
  sent.

The third was found only with a debug line at the timeout: `polling=1`,
the detection clock 0.93 s old, and the kernel's last packet from the peer
1.92 s old. A Poll started, never sent. B7, all three: 0.

## 3. The unit ran the engine where real-time load starves it most

What B7 left was 116 flaps on sessions the fast path cannot clock:
asymmetric timers, where we must send faster than the peer does, and demand
at our end only, where the peer goes quiet. Their extra packets come from
the loop, and nothing in XDP can originate them. m7 had recorded the same
limit for v6 sent from userspace.

The packaged unit already ran the engine `SCHED_FIFO`, at 10. B4a is that
configuration, and it is worse than normal priority: the loop went more
than 8 s without a pass, and 957 of the 1022 sessions flapped once, 3 to
10 s into L4, as the gate let go. The 65 spared were exactly the ones in
which the peer demands, so that it was not timing us out. RT throttling hands the unthrottled part of each period to CFS tasks,
not to lower-priority RT ones, so an engine below the load gets nothing.
Threaded interrupt handlers run at 50. At 51 and at 60 (B4b, B4c), nothing
flapped. #26 moves the unit to 60.

## Also found

- **DSCP.** Packets the engine sent from userspace went out as DSCP 0, and
  the program's replies copied whatever the peer had sent. On a switch
  that queues by DSCP those are dropped first. Fixed in #23, verified from
  the mirror: 0 of 55554 control packets unmarked afterwards. FRR's own v6
  echo socket sets no traffic class either; not fixed.
- **Reply latency on the wire** is 118 us at p50 and 248 us at p99 (B0),
  against about 1.5 us in the program: the I210's adaptive interrupt
  moderation and idle C-states. Not investigated further.
- **A peer bfdd stalls on its own configuration.** With 1022 software
  sessions, a timer change on 40 of them and a `write memory` stalled m2's
  bfdd for about a second and flapped 231 sessions, 1 s x5 excepted.
  Nothing is changed on the peer during a run.
- **FRR, to reproduce upstream:** one 10 ms session on the peer kept
  transmitting at its old 100 ms after the timer change and a flap
  (`show bfd peer`: actual 100 ms against 10 ms negotiated). The engine
  held its detection at the observed rate, as s6.8.3's slow-down rule
  asks, so it did not flap. And stock bfdd started from its config opened
  no echo sockets in software mode either, the root cause of FRR#23465 in
  a mode that PR does not cover: 25 echo sessions flapped with "echo
  function failed" until echo-mode was toggled at runtime.
- For stock bfdd the DUT needs `ip_forward`, to loop the peer's echo; the
  engine does that in XDP.

## Not covered

- One RT load, prio 50 on every thread. A load above 60 starves the engine
  again; that is the priority arms race from writeup section 4, moved, not
  won.
- 1G only, one NIC model on the DUT, 1024 sessions. The floods of
  `tools/matrix/m9-flood.md` have not been rerun here.
- With `sched_rt_runtime_us = -1` a starved engine at normal priority
  would never run; not measured.

## Files

- `analysis/` - `bfdcap.py` and `flaps.py` output for every run: per class
  and side, the gap distribution against the receiver's detection time,
  the wire reply latency, and every flap with who left Up first and why.
- `captures/` - 10 s of L4 from B1, A1, B4a and B9, mirror-side, HW
  timestamps, snaplen 128. The full captures (4-6M packets each) are kept
  offline.
- `runs/` - each run's log (phase times, both ends' down counters) and
  stress-ng's own report.
- `tools/` - the harness (`run.sh`, `mode_a.sh`, `mode_b.sh`), the two
  analysers and the session-to-class map they read.
