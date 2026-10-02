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
  against about 1.5 us in the program. Not interrupt moderation or
  C-states, as first written here: the NIC's PCIe link, below.
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

## Later the same day: the package, and the floods

**The package as installed.** Everything above ran the engine by hand
under `chrt`. Installed from its `.deb` and run by its own unit (user
`xdp-bfd`, capabilities only, `SCHED_FIFO` 60), the ladder again gave 0
flaps (B10). Two things did not work as installed, though the tests said
they did, both fixed in [#27](https://github.com/w453y/xdp-bfd/pull/27):

- `systemctl reload` failed. A new engine recognised the one it takes over
  by its comm starting with `bfd_tx`; installed, it is `xdp-bfd`. The unit
  test installed the binary as `bfd_tx`.
- A package upgrade stopped the engine. `dh_installsystemd --no-start`
  makes debhelper stop the units in preinst on upgrade, before postinst can
  reload, and here it took every session down.

Fixed, an in-place `dpkg -i` over a running 1024-session engine replaced it
with no down event on the peer, and a reload handed over in 18 ms.

**Floods.** The m9 frames, re-targeted, from m3 with `trafgen` at up to
1.24M frames/s (line rate for these sizes on 1G), 10 s per arm, against
the packaged engine and the full mesh. `flood-hw.txt`.

| arm | frames/s at XDP | ns/frame | sessions that flapped |
|---|---|---|---|
| A non-BFD UDP, spread | 1.21M | 19 | 0 |
| B valid BFD, TTL 64 (GTSM) | 1.19M | 213 | 0 |
| C malformed BFD | 1.23M | 67 | 0 |
| D valid BFD, unknown pair | 1.19M | 213 | 0 |
| E real pair, wrong your_disc | 1.12M | 293 | 0 |
| F bad auth at one session | 1.03M | 301 | 37-48 (see below) |
| G echo from a known peer | 1.19M | 263 | 1, the target |
| H moved address, real discriminator | 1.18M | 274 | 1, the target |
| I real pair, churning timers | 1.20M | 304 | 1, the target |

The engine stayed at 3-5% of a core throughout, and no NIC queue dropped
anything. F was the one arm with collateral flaps, and they were not the
engine's: 125 of 135 were the peer's own echo failing on its IPv6 echo
sessions. F's frames are 94 bytes, so at 1M/s they fill the 1G port to the
DUT, and the switch drops at that port. BFD control goes through the
strict-priority queue because it is CS6, and so does bfdd's IPv4 echo, but
bfdd sends its IPv6 echo unmarked, so it shared the flood's queue: a third
of those echoes never reached the DUT (the program's own counters account
for every one that did). At 395k and 590k frames/s the same arm flapped
nothing. `F-flood.txt` has the per-second echo counts.

## Reply latency: the NIC's PCIe link

Measured on 2026-10-01 at idle, full mesh, 60 s per arm, peer packet in to
the DUT's packet out, both from the mirror (`tools/lat.sh`,
`analysis/latency.txt`). Knobs on m1 only.

| ASPM | rx-usecs | C-states | p50 | p99 | p999 | package |
|---|---|---|---|---|---|---|
| L1 (as installed) | 3 | all | 118 us | 250 us | 310 us | 8.5 W |
| L1 | 0 | all | 122 | 237 | 317 | 8.3 W |
| L1 | 3 | C1E | 114 | 299 | 356 | 33.6 W |
| L1 | 0 | C1E | 117 | 237 | 237 | 33.9 W |
| off | 3 | all | **33** | **122** | 162 | 8.9 W |
| off | 0 | all | **31** | **52** | 143 | 8.9 W |
| off | 3 | C1E | 34 | 108 | 135 | 33.9 W |
| off | 0 | C1E | 27 | 46 | 50 | 34.4 W |

At this rate igb already raises about one interrupt per packet, so
`rx-usecs` alone changes nothing, and holding the cores in C1E costs 25 W
for no gain at p50. Kernel ICMP replies showed the same spread as the
program's, from m1 and from m2 alike, so it was neither XDP nor one host.
With gi1 mirrored both ways the switch took 1.0 us flat, and the rest lay
between the frame reaching m1 and the reply leaving it; the I210's own
receive timestamp against the kernel's put it on the receive side. EEE off
moved nothing and DMA coalescing was already off. The I210's PCIe link was
in ASPM L1: clearing it on the NIC and its root port took a ping's
turnaround on m1 from 97 us to 18 us at p50. The link advertises an L1
exit under 16 us.

The firmware on these boxes enables L1 and withholds ASPM from the kernel
("FADT indicates ASPM is unsupported, using BIOS configuration"), so
`pcie_aspm.policy` is refused and `pcie_aspm=off` leaves L1 on. Only the
BIOS or `setpci` at boot turns it off.

None of this moves a detection time: 250 us is 2.5% of the shortest
interval FRR accepts. It applies to every frame the host receives, not
only BFD. With the floor lower, authenticated sessions show the digest
computed in XDP: about 7 us more at p50 than the rest.

`rx-usecs 0` was also run under floods C and I with ASPM off. Under a
flood NAPI stays in polling, so it added no interrupts, and the engine and
softirq used no more CPU. No session went down beyond I's target, the
session I forges with its real discriminators. That one went down on the
peer in all five runs at `rx-usecs 0` and in none of three at 3; it also
went down in the first flood run above, at 3 with ASPM on.

m1 was left as installed: ASPM L1, EEE on, `rx-usecs 3`, all C-states.

## The priority race, ended

\#26 put the engine above the prio-50 load, which only moves the race the
writeup's section 4 calls a standoff: a load above 60 starves it as one
above 10 did. Measured on 2026-10-01 with the hog at 99 instead (`run.sh`
with `L4PRIO=99 NOL3=1`: 30 s idle, 60 s of hog, 30 s idle), down events
from both bfdds:

| run | engine | down events |
|---|---|---|
| R1 | packaged, `SCHED_FIFO` 60 | 959 |
| R2 | `SCHED_DEADLINE`, 1 ms in 10 ms (`chrt -d`) | **0** |
| R3 | 0.2 ms in 10 ms | 0 |
| R4 | 0.05 ms in 10 ms | 411 |
| R5 | 1 ms in 10 ms, the usual ladder | 0 |
| R6 | packaged with [#28](https://github.com/w453y/xdp-bfd/pull/28) | **0** |

Deadline tasks run ahead of every `SCHED_FIFO` priority, so there is no
number left to outbid, and admission control keeps the reservations within
the CPUs. #28 (0ca5ca3) has the engine take the reservation itself and drop
`CAP_SYS_NICE`; the unit passes 1 ms in 10 ms and keeps `SCHED_FIFO` 60
for a kernel that refuses it. Installed over the running engine with
`dpkg -i`, it handed over in 10 ms with no down event on the peer.

Both at once, against main with #28: the prio-99 hog on every thread and
flood arm D at 1.16M frames/s for 50 s inside it (C1, valid BFD for an
unknown pair, which the program passes up to the engine's socket): 0 down
events, and the dead-man gate held nothing. Then an hour idle on main
5b8e73f, sampled each minute (S1, `tools/soak.sh`): 0 down events at either
end, 1022 Up throughout, the engine's RSS flat at 8 MB and its CPU 4% of a
core, the minute's stats dump included.

## Under attack: flood, CPU and memory at once

The question, from a network engineer: what does an XDP fast path with no
SmartNIC do when the host is flooded and its CPU and memory are choked at the
same time? The floods above ran 10 s each on an otherwise idle box. Here,
`tools/hsoak.sh`: an hour, m3 flooding m1's port at line rate throughout,
rotating every minute through A-E (plain UDP, wrong TTL, malformed, unknown
pair, wrong discriminator), while m1 ran a different `stress-ng` every 5
minutes: a FIFO 99 hog on every thread; CPU and timers; memory at 95% and at
110% (into swap); and mixes. Down events counted on m2, which was not under
attack, every 30 s.

| run | m1 | down events in the hour |
|---|---|---|
| H1 | (void: see below) | 108,165 |
| H2 | main | 165,028 |
| H3 | `--spread-pass` | 68,231 |
| H4 | `--spread-pass`, flow control off, UDP hashed on ports | **4,148** |

By phase:

| phase | H2 | H3 | H4 |
|---|---|---|---|
| CPU and timers | 16k | 13 | 0 |
| CPU, timers, memory 85% | 23k | 6k | 3 |
| FIFO 99 hog | 34k | 7k | 453 |
| FIFO 50, memory 90% | 23k | 5k | 542 |
| memory 95% | 36k | 28k | 1,675 |
| memory 110%, 2.2 GB of swap | 32k | 22k | 1,475 |

The engine itself never wavered: on its deadline reservation throughout, no
major fault, nothing swapped, the dead-man gate never held. What failed was
m1's receive path, in three layers, found one at a time with 60 s cases
(`tools/iso.sh`, `tools/iso2.sh`):

1. **Other traffic up the stack on the RX CPU.** Arm A, plain UDP, is passed
   to the stack. igb hashes UDP on addresses only, so it all lands on one
   queue whatever its ports, and the stack's work runs in that queue's
   softirq. Alone that core keeps up (1.21M frames/s); with `stress-ng` on the
   other threads, the sibling hyperthread and lower clocks take it over the
   edge (12,715 down events in a minute). Threaded NAPI at FIFO 50 did not
   help (11,659): it is capacity, not scheduling.
   [#30](https://github.com/w453y/xdp-bfd/pull/30) (3546741) adds
   `--spread-pass`, a cpumap redirect of that traffic by flow to every CPU;
   the RX CPU then only runs the program: 0, and 0 for a single flow too.
2. **One queue drowns the rest.** With flow control negotiated, igb leaves
   per-queue drop off, so a queue that falls behind fills the I210's shared
   RX buffer and all four drop (`rx_missed_errors`). Flow control off turns
   per-queue drop on: the flooded queue drops its own and the others are
   clean (12,715 to 2,103 before `--spread-pass`). Hashing UDP on ports
   spreads a many-flow flood over all queues (0).
3. **Memory.** With RAM thrashed, the program's own map accesses miss cache:
   a malformed frame it drops in 73 ns took 142, and a single line-rate flow
   no longer fits one core. Not the engine (0 major faults), not the
   driver's allocations (0 failures). With per-queue drop on, nothing was
   lost at the NIC and 74 down events in a minute remained, nearly all on the
   10 ms x3 class: a box's own memory bandwidth is the floor here.

H1 is void, and a trap worth knowing: the reply-latency work earlier left
m1's NIC timestamping every packet (`HWTSTAMP_FILTER_ALL`). igb then reads
each timestamp from a register, `igb_rd32` took 84% of the RX CPU, and one
queue managed 200k frames/s instead of 1.21M. Nothing logs it.

## A neighbour that holds the key

The second question from the same engineer: assume the neighbour is
compromised, keys and all; can the engine be hurt beyond that neighbour's own
session? BFD concedes the session itself to whoever holds its key. Reviewed
against the code on 2026-10-02 (wiki: Security model):

- **Memory.** Nothing a received packet does allocates. The only fast-path
  map write is the per-session state insert, reachable only for a configured
  pair; sessions come from bfdd or static config, never from a packet.
- **A crash.** A key-holder's packets run the same verified program as any
  other.
- **Other sessions: one gap, now closed.** The failure budget counts only bad
  digests and the s6.8.7 rate gate sat after the digest, so good digests from
  a key-holder each cost a full HMAC: 2632 ns of program time a frame against
  68 on the drop path (`BPF_PROG_TEST_RUN`), enough to hold one RX CPU and the
  sessions sharing its queue.
  [#32](https://github.com/w453y/xdp-bfd/pull/32) (1829351) budgets verifies
  before the digest, at twice the rate the peer may send with a burst of two,
  reading only arrival time and refunding a failed verify so a forger without
  the key cannot spend the peer's. Same flood: 267 ns a frame. On m1's real
  traffic, 2.76M authenticated packets in five minutes moved
  `verify-limited` by zero, 68 of 68 authenticated sessions Up.

## The lab, kept honest

- An unattended upgrade on m2 (openssl, 2026-10-02 06:56) restarted
  systemd-networkd, which drops addresses it did not configure: the 1022 lab
  addresses went, and the mesh sat dead until the next measurement noticed.
  The test ports now carry `critical: true` (networkd keeps static addresses
  across a restart, proven by restarting it), `bfd-lab-addrs` restarts with
  networkd, and automatic upgrades are off on all four machines; updates are
  applied by hand between runs.
- m1's port is tuned at boot as the wiki recommends for a flooded link
  (`bfd-lab-nic.service`: flow control off, UDP hashed on ports), before the
  engine and FRR, since changing flow control resets the NIC. A cold reboot
  of m1 alone came back to 1022/1024 with every setting in place.
- The reply-latency work left m1's NIC timestamping every packet, which voided
  H1 above. A probe that changes NIC state now puts it back.

## Upstream, from this milestone

Proposed on 2026-10-01 as FRR
[#23495](https://github.com/FRRouting/frr/pull/23495) and
[#23496](https://github.com/FRRouting/frr/pull/23496):

- `bfdd-echo6-tclass`: set the IPv6 echo socket's traffic class to CS6, as
  the control sockets and the IPv4 echo already are. The F arm above is
  the consequence of not doing so.
- `bfdd-echo-sockets-enable`: since the on-demand VRF sockets of
  5fa775bf1e (in 10.7.0 and 10.7.1), bfdd opens its echo sockets only if
  the first session enabled uses echo; echo set from the startup
  configuration on a session enabled later opens none, and every echo
  session then flaps. Seen on m1 in stock mode; the new topotest
  reproduces it with a link that appears after bfdd starts.

m1 and m2 then ran FRR master with all six open bfdd PRs merged (fork
branch `lab-combined`, 09b22b01c6), the engine declaring its capabilities
to #23463: the ladder gave 0 flaps (B12), and with a data plane bfdd held
no BFD socket at all.

One observation was not reproduced: after the timer change that stalled the
peer, one peer session kept transmitting at its old 100 ms against 10 ms
negotiated. Replaying the change twice on the mesh and twice between two
bfdds in a topotest left every session at 7-10 ms.

## Not covered

- One shape of RT load: every thread spinning at a single priority.
- 1G only, one NIC model on the DUT, 1024 sessions. A single injector,
  so floods reach one RX queue at a time for single-flow arms.
- With `sched_rt_runtime_us = -1` a starved engine at normal priority
  would never run, and a deadline one should be unaffected; not measured.

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
  analysers and the session-to-class map they read; for the reply latency,
  `lat.sh` (one arm), `icmplat.py`, `icmpsplit.py` and `turn.sh` (ping
  turnaround from the mirror) and `rxts.py` (NIC against kernel receive
  time).
- `runs/lat-*` - each latency arm's log, per class.
