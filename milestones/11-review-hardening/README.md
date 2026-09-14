# m11: two reviews, and what the testbed found working through them

Merged as [#10](https://github.com/w453y/xdp-bfd/pull/10) (`db432e8`), 27
commits.

Two reviews arrived against the same tree: one from a colleague reading
`main` cold, and one re-review of the earlier `review-fixes` branch that
had been sitting unread. Working through them produced three behaviour
changes, a set of ordinary fixes, and four findings that came from
neither review but from the testbed while checking them.

The most useful thing to record is not the fix list. It is that **four of
the defects here were found by a test being wrong, or by a premise being
stale**, and that the two gates added in this round were both nearly
built on measurements that no longer held.

## 1. The rule this round was run by

The earlier `review-fixes` work established that a measurement from last
month is not a premise until it is re-checked. This round applied that
literally, and it changed two outcomes.

**The pacing gate was abandoned on evidence.** It was item 3 on the
re-review's priority list, described there as one mechanism with three
payoffs. Before writing it, the storm it was meant to bound was
re-measured. It did not reproduce: 850 packets with the gate off against
the 690223 recorded in
[`symmetric-ktx`](../../investigations/symmetric-ktx/). Sessions flapped
348 to 494 times per run either way, which is pre-existing and unrelated.
The gate, built to see, fired 22 times against a conforming bfdd, which
falsifies the claim in its own design that it would be invisible to
conforming peers. The whole thing was reverted. What survives is one
comment in `fsm_tx` recording what the kernel-TX backstop actually
assumes, which is the part that turned out to matter.

**The dead-man gate was built, because its premise held.** Same
procedure, opposite result: see section 2.

## 2. XDP stops answering for an engine that has stopped making progress

Answering from softirq is what makes detection independent of the loop.
It is also what lets a wedged engine lie. The program keeps replying on
the peer's clock whether or not anything upstairs is still running, so a
control plane that is alive but making no progress presents Up sessions
to the whole network indefinitely. That is the exact lie BFD exists to
prevent, arriving by way of the optimisation.

[`investigations/wedged-ktx`](../../investigations/wedged-ktx/) measured
this in August and it still holds. With the engine held in `T` state for
fifteen seconds, 55 of 64 sessions stayed Up with the peer receiving at
full rate, 455 control packets over a 20 second window on a 50ms
interval.

The engine now stores `CLOCK_MONOTONIC` into a heartbeat cell once per
loop pass and the program declines to bounce a frame when that reading
goes stale. Declining does not take the session down: it lets the peer
reach its own conclusion on its own detection timer, which is the peer's
decision to make and needs no new protocol.

### The bound was not a judgement call

The loop already kept a log2 histogram of its own inter-pass gaps, and
over 651347 consecutive passes on the 64-session mesh it reads:

```
[    1024 ..     2048) us      630447   cum 98.596752%
[    2048 ..     4096) us        9092   cum 99.992631%
[    4096 ..     8192) us          39   cum 99.998618%
[    8192 ..    16384) us           4   cum 99.999232%
[   16384 ..    32768) us           2   cum 99.999539%
[ 8388608 .. 16777216) us           3   cum 100.000000%
```

The two worst legitimate gaps in the entire run land in 16-32ms. The only
samples past that are the three deliberate SIGSTOPs, alone in the 8 to 16
**second** bucket. Four orders of magnitude separate the worst thing the
engine does to itself from the thing being caught, so the threshold does
not need to be delicate and should not be. One second is about thirty
times the worst observed gap.

The re-review suggested 10 to 60 seconds, reasoned as "far above anything
the scheduler-immunity results defend". The histogram allows something
much tighter with evidence, so 1s it is. `--deadman-us 0` disables.

### Result

Same window, same build, the only difference the flag:

| | carried | dropped |
|---|---|---|
| `--deadman-us 0` | 55 | 4 |
| default (1s) | **0** | **59** |

"Carried" is a session the peer kept hearing from with no down event.
198016 loop passes at default with zero false trips; worst gap in that
run still 16-32ms.

### What it cost to get right

The gate breaks an inference that `fsm_tx` had been making, and
`efbcad8` had already written down that it would. The backstop read
`last_rx_us` and took "a packet arrived" to mean "the program replied",
which holds only while every accepted packet is answered. A gate that
declines to answer breaks that, and userspace then stays quiet believing
the kernel is transmitting: both ends go silent and the session times out
at a flap every 32ms, the detect budget exactly.

`session_state.tx_pkts` was already maintained on the path that
transmits, so the fact was published and only the reading of it was
missing. That went in first, as its own commit, stamped with
`last_rx_us` so it is bit-identical to the value it replaces until
something actually declines.

Two attempts to store a transmit timestamp kernel-side both failed the
same way, and the message is worth keeping:

```
combined stack size of 3 calls is 528. Too large
```

The verifier charges one 512-byte budget across the whole call chain.
Neither carrying `now` down to the store nor calling `bpf_ktime_get_ns`
again there fits. Deriving it from the counter in userspace costs no BPF
stack at all.

## 3. A demanding session verifies its own path (RFC 5880 s6.6)

While a system is demanding, `demand_detect_held` stops its detection
timer: it told the peer to go quiet, so silence is what it asked for and
cannot be read as a fault. Nothing else then ever takes the session down.

[m10 section 11](../10-auth/) recorded the consequence from the other
side: changing an authentication key on one end of the mesh took down
every authenticated session **except** the one demanding at both ends,
which stayed Up against a key it could no longer have verified.
Authentication protects the packets a session sends; it cannot protect a
session that has agreed to stop sending.

s6.6 leaves the timing to the implementation, and stock bfdd reaches
`bfd_set_polling` only from a parameter change, so in practice never
does. The engine now starts a Poll on a timer. The Poll re-arms
detection, so a Final that never comes back brings the session down on
the detect budget rather than never.

Keyed off `last_rx_us` rather than a timer of its own, because that is
already the answer to "when was this path last verified": a packet
arriving is a verification, the Final ending a poll is one, and
`fsm_start_poll` stamps it, so an unanswered poll restarts the same clock
it is then measured against. Never faster than the session's own detect
budget, since a poll costs a round trip and demand mode exists to stop
paying for those.

Measured on the mesh against stock FRR bfdd, one session demanding, the
peer then silenced:

| | polls | outcome |
|---|---|---|
| `--demand-poll-us 0` | 0 | still Up after 25s |
| default (1s) | 31 | **Down in 1.45s**, diag 1, recovered |

Every poll in the armed run completed, so bfdd answers each one with a
Final. That is the interoperation question settled.

The Poll start was factored out of `dplane.c` rather than written twice.
There are now two reasons to begin one, and the third step, resetting the
receive clock so the re-armed detection is not measured against the
silence we ourselves asked for, is exactly what a second copy would omit.
A session that lost it would come down on its first poll.

`--demand` was added for static mode. Under bfdd the flag arrives per
session on the bfddp ADD, so standalone mode could not reach demand mode
at all, which left this behaviour testable only from a full FRR testbed.

## 4. The engine refuses a kernel program built against a different ABI

`tests/unit/abi_check.c` pins every shared struct at compile time and
structurally cannot see the failure that actually happens. `bfd_tx` and
`bfd_xdp.o` are separate artifacts, built at separate times, paired at
runtime by a path: an installed copy, a stale `--bpf-obj`, a half-rebuilt
tree.

This was demonstrated rather than argued. With the check disabled and an
object whose `tx_cfg` is four bytes longer, the engine **loads it,
attaches it, and brings a session up**:

```
kernel-tx: XDP attached to lo (generic mode, link)
bfd_tx: static session lid=1652027835 10.0.0.1 -> 10.0.0.2 (kernel-tx)
```

Nothing logged, nothing refused. The verifier has no opinion, the map
accepts the key, and the two halves read the same bytes as different
structs.

The check compares the object's own BTF against the engine's `sizeof`,
plus `max_entries` on the two maps that enums size directly. A version
integer would work and would have to be remembered; a size read off both
sides cannot be forgotten to bump. The two edits earlier in this same
round are the argument: `session_state` grew by 8 bytes and
`BFD_STAT_MAX` went 14 to 15, and both would have sheared exactly this
way.

**The first version of this check refused the correct object.** BTF for a
BPF object is built from map definitions and program signatures, so a
struct named only inside a function body is pruned: `bfd_event` and
`bfd_ctrl_pkt` were absent entirely. They are now kept alive by a witness
in `maps.h`, declared by value rather than as pointers, because a pointer
can be recorded against a forward declaration and a forward declaration
has no size to compare. This was caught only because the positive case
was tested, not just the negative.

No BTF at all is not a refusal. That means built without `-g`, which the
Makefile never does but a packager might, and turning it into "will not
start" trades a silent risk for a certain outage.

## 5. Four defects found by tests being wrong

This is the section worth reading twice.

**The wedged-kernel-TX instrument reported the opposite of what it
measured.** Its verdict collapsed to "any down event at all". The mesh is
two populations: sessions the fast path carries, and sessions it does not
which transmit from the loop and are *supposed* to go down when the loop
stops. Counting the second as a refutation reads the control group as the
result. It printed "the wedged-but-alive concern is unfounded" off four
userspace-TX sessions while 55 kernel-TX ones sat there being carried. It
also ran a bare `vtysh`, which resolves to the distro binary whose
daemons are not running, so every run died before measuring anything.

**The ABI skew fixture tested the wrong failure.** It first grew
`session_state`, which pushes the packet path over the verifier's
512-byte stack budget, so the skewed object failed to load whether or not
anything checked its ABI. That test passes against an engine with no
check at all. Moved to `tx_cfg`, which is reached through a map pointer
and costs no stack, so the skewed copy loads and runs and the check is
the only thing between it and sheared fields.

**A stopped `sudo` left a corpse for the next run.** `sudo` follows
job-control convention: when the child it waits on stops, it stops
itself. Resuming only the child left `sudo` in `T` permanently, and a
stopped parent cannot reap, so the next `pkill -x bfd_tx` produced a
defunct `bfd_tx` that never went away. `pgrep` lists by pid, so the
following run picked up the corpse, SIGSTOPped it, and measured a
perfectly healthy mesh through it. It refused rather than reporting that,
but only by luck of the check ordering.

**A dead session had been dead all session.** The DUT carried the peer's
own address `fd67::10:1/64` on its `ens20` in `dadfailed tentative`
state, so packets to that peer never left the box. The peer read `Control
packet input: 0 packets` against `Control packet output: 26374` with zero
down events: that session had never once worked. Removing the address
brought the mesh to 64/64 for the first time in the round, which is what
let `wedged_ktx.py` past its own "mesh is not fully up" guard.

## 6. What CI found that no local suite can reach

The branch had accumulated 27 commits without CI ever running on it:
`ci.yml` triggers on `pull_request` and on `push: branches: [main]`, and
nothing else. Opening the pull request was the first exposure. Two real
breaks surfaced immediately, both invisible to `make check`:

**The fuzz harness stopped linking.** `eda42fd` gave `fsm_detect` a call
to `ktx_events_fd`; `dp_run.c` was given the stub and `dp_fuzz.c` was
not. `check` builds `dp_run` and not `dp_fuzz`, because the latter needs
a clang with `-fsanitize=fuzzer` a developer may not have, so only the
self-hosted job builds it. The two harnesses keep separate copies of that
stub group on purpose, since they disagree about what `ktx_attach_if`
should return, and this is the cost of that.

**scan-build read `ss.ss_family` as a garbage value in
`dp_peer_allowed`.** The `getsockname` return is checked and the function
returns on failure, so the report is the analyser not modelling
`getsockname` as an initialiser rather than a reachable bug. Zeroed
anyway: this decides whether a peer may take over the control connection,
the project already runs scan-build as a gate with no findings to excuse,
and answering a checker with a comment on that particular function is not
a trade worth making.

All nine jobs green on the re-run: `cross`, `full`, `kernel`, both
`portability` arms, and all four `toolchain` arms.

## 7. The ordinary fixes

| | |
|---|---|
| `cbd30d6` | The XDP path leaves traffic that is not BFD alone. GTSM, IP-options and fragment rules now gate on the destination port. |
| `146dd1f` | A control connection is authorized before it displaces one. |
| `5f98b0e` | The applied interval is held across a repeated ADD, instead of being slowed to a rate the peer has not accepted. |
| `576dac1` | The mirror cache is keyed, so an address move is not mistaken for a no-op. |
| `e4d8e85` | The output queue is forgotten at a connection boundary. |
| `e828c86` | The peer's detect multiplier is carried back from the map. |
| `93a8e07` | Passive gates transmission, not the state machine. |
| `bf72574` | An echo-only change from the peer is still a change. |
| `e42baf4` | A send that failed has not consumed anything. |
| `4214186` | Transmission stops when the peer advertises Min RX zero. |
| `1ff1773` | The envelope must describe the frame. |
| `a4b7cde` | The v4 single-hop socket drains like the other three, instead of one packet per pass. |
| `73971c2` | AdminDown is announced on SIGTERM instead of letting the peer time out. |
| `aa51ee1` | JSON output is escaped. |
| `eda42fd` | The sweep's detection verdict is taken rather than derived a second time. |

`eda42fd` is worth one more line. The sweep already computed a detection
verdict every interval and published it on a ring, and nothing read it:
`fsm_detect` worked the same answer out again on its own schedule. Two
derivations of one fact is also how they come to disagree, and `e828c86`
is exactly that, the peer's multiplier not being carried back making the
engine time out against a budget the sweep knew was longer. The honest
limit is that the drain still runs in the loop, so the *reaction* stays
loop-bound; what is new is that detection latency and loop lateness are
now separable, measured at 11 to 30us against a 30ms detection.

## 8. Testing

`make check`, the netns end-to-end suite at 14 passed (up from 6), the
FRR container scenarios at 9 passed, all nine CI jobs green, and the
64-session mesh at 64/64.

Every new gate carries two arm tests, because one arm proves nothing on
its own: a session going down while the engine is stopped is equally well
explained by the engine simply being stopped. Each new test was also run
against the code with its subject disabled, to confirm it fails.

New coverage: five `xdp_run` cases for the dead-man gate (fresh, stale,
just-inside-bound, disarmed, never-beaten), eight `fsm_run` cases for the
demand poll, and four e2e files (`test_abi_handshake.py`,
`test_deadman.py`, `test_demand_poll.py`, `test_shutdown.py`).

The dead-man cases assert the `deadman-hold` counter as well as the
verdict, because withholding a reply is `XDP_PASS`, which is also what an
unarmed session gets: the verdict alone would still pass if the gate were
deleted.

## 9. Not covered

The dead-man gate bounds how long the fast path will answer for a wedged
engine. It does nothing about the engine being wedged. `--dp-hold`
extends the opposite philosophy deliberately, bounded and intentional
survival, and the two have not been reconciled into one story.

The demand poll was measured on one session on the mesh and in the netns
rig. It was not exercised at the session cap, nor against a peer that
answers Poll with something other than Final.

The ABI handshake compares sizes, not layouts. Two structs of equal size
with fields reordered would pass. Field-level BTF comparison is possible
and was not done.

CI still does not run on a branch until a pull request exists, so the
next long-lived branch will accumulate the same blind spot.
