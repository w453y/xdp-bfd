# External review, 2026-08

An outside reviewer read the tree at `8b8282e` and produced four documents:
a 20-finding code review, an architecture assessment, a testing plan, and a
proposal for running the engine on both ends of a link. This branch
implements the first, plus three defects found while verifying it. The
architecture and testing documents are not started; the symmetric
deployment one is deliberately deferred (see the end).

All twenty findings checked out against the code. No false positives, no
stale line references. Three needed a different fix from the one proposed,
and those are called out below rather than quietly changed.

## What the review got right that we had not seen

**The fast path outlived the engine.** `bpf_xdp_attach` leaves the program
attached when the process dies. After a SIGKILL, XDP kept answering every
control packet from a frozen `tx_config` while nothing drove the session
and bfdd was not running — the exact failure this project exists to
prevent, produced by the tool meant to prevent it. Now attached through a
`bpf_link`, so the kernel detaches when the process dies, with no
cooperation from us.

Proven both arms: with the old build, `bpftool net show dev ens19` still
listed the program after `pkill -KILL`. With the new one the section is
empty.

**Consequence, worth knowing:** `ip link set dev <if> xdp off` no longer
removes the program. Killing the owning process is what removes it.

**The two planes had drifted on what a valid packet is.** XDP checked the
length field; userspace never looked at it, so a packet claiming 200 bytes
inside a 24-byte datagram was accepted in userspace and rejected in the
kernel. There is now one predicate in `bfd_shared.h` that both call.

**Neither plane honoured the A or M bit.** RFC 5880 s6.8.6 says both must
be discarded when authentication is not configured, which here is always.
They were recorded into `remote_flags`, reported to bfdd, and ignored.

## What the review missed

**Deferred GTSM ran after the promiscuous pass.** With any multihop session
configured, `prog_flags` bit 1 makes `parse_l3` defer the TTL verdict; a
low-TTL packet naming an unconfigured address pair then fell out of the
`cfg == NULL` pass and reached the stack, where the v4 socket had no
`IP_MINTTL`. The block's own comment claimed the opposite. Moving it above
the pass turns finding 2 from a parity gap into a closed path.

**The receive drains had no budget.** Three `MSG_DONTWAIT` loops ran until
EAGAIN, so a sustained flood of frames XDP passes to the stack kept the
loop inside a drain and starved transmit, detection, the map poll and the
dplane read. The process stays alive and scheduled throughout, so this is
the wedged-but-alive case that no process-liveness check can see. Bounding
each drain to `MAX_SESSIONS` per pass was a smaller fix than the heartbeat
the architecture document proposes, and it is the reason that heartbeat is
not here.

**`dp_send` treated EAGAIN as fatal.** `dp_conn` is non-blocking, so a full
socket buffer surfaced as `send() < 0` and the only error path closed the
connection and orphaned every session. The counters burst the review cites
therefore produced a full dplane teardown, not a short write. Messages now
go through a 64KB outbox flushed once per pass; the connection drops only
on real overflow, which is what `--dp-hold` exists to cover. Same class of
bug as FRR #22638/#22645, on the other side of the same socket.

## Where the fix differs from the proposal

**Finding 19 — sweeper arming.** The review reads as an objection to the
CAS being set before `bpf_timer_init`. That ordering is the only safe one:
initialising first would have two CPUs both calling `bpf_timer_init` and
`bpf_timer_start` on the same timer. The real problem, which the review
also names, is that the arming calls can fail, their returns were
discarded, and `inited` is already 1 — so on a kernel without timer support
the sweep silently never arms. The error is now recorded in the sweep map
and counted to stat slot 10, which must stay flat.

**Finding 3 — partial send.** Rated high; in practice the trigger is not a
short write but the EAGAIN path above. Fixed as an outbox rather than a
retry, because `dp_notify_state` runs inside the per-session tick and even
a 1ms wait per message would cost tens of milliseconds in one pass. This
loop's pacing is upstream of transmit and detect timing.

**Compile-time `_Static_assert` on the shared structs.** Not done, for the
same reason as the previous review: both planes include the same header
from the same tree in the same build, so they cannot disagree. The failure
that actually bites is a stale loaded program against rebuilt userspace,
where the kernel uses the old `value_size` — invisible to a compile-time
assert. A version field checked at attach time would catch it, and that is
the item worth doing instead.

## Evidence

Every change ran the full suite: `inject_matrix.py`, `dp_hold.py`,
`poll_final.py`, against 64 configured sessions with 62 up.

Changes with a failing before-arm on record:

| Change | Before | After |
| --- | --- | --- |
| Deferred GTSM ordering | `gtsm-unconfigured-pair` fails `rejected +0` | passes `+20` |
| Fragment drop | `frag-first` fails `rejected +0` | passes `+20` |
| A and M bit discard | `auth-bit-v4` fails `unsupported-flags +0` | all four pass `+20` |
| bpf_link attach | program survives `pkill -KILL` | `bpftool net show` empty |
| Counter fidelity | `Control packet input: 0` on an Up session | `3196 packets` |
| AdminDown on teardown | peer reports `control detection time expired` | `neighbor signaled session down` |

The matrix grew from 33 cases to 39 and the stat map from 9 slots to 11.

**Coverage gap, stated rather than papered over:** nothing in the suite
exercises the userspace socket path. `inject_matrix` asserts on BPF
counters and userspace has none, so both halves of finding 2 — the shared
predicate and the userspace GTSM — are reasoned rather than wire-proven on
that side. Closing that needs the veth rig from the testing document.

The address-move path in finding 6 also has no test: it needs bfdd to send
an ADD for an existing lid with a different address pair, which FRR may
never do. The log line `moved address pair, clearing the old` is the
observable, and it should never appear in normal operation.

## Test harness bugs found by using it

Two, both of the vacuous-pass class the harness was built to prevent:

- `--only <name>` filtered inside the case loop, so a name matching nothing
  ran zero cases and still printed `all cases passed`. Now a hard error
  listing the available cases.
- `pick()` identified a phantom session as "multihop with `enable == 0`",
  which also describes a real multihop peer that is merely not up yet.
  During bring-up the live peer to bfd-chaos was selected as the phantom
  and the case asserted against a session carrying real traffic. Phantoms
  are now pinned by address.

## Deferred

The symmetric-deployment document argues that two engines facing each other
produce a ping-pong storm at RTT period rather than the silence the README
claims, and proposes a kernel-side pacing gate. `rx_clocked_tx` does indeed
hold no pacing state of any kind, so the premise is sound as far as reading
the code goes — but two engines have never faced each other on this
testbed. That capture comes before any of it is built.
