# Two RX-clocked engines face to face saturate the link

Date: 2026-09-02
Branch: `review-fixes`
Evidence: `rates.txt`

Two xdp-bfd engines deployed against each other, both with `--kernel-tx`,
transmit at roughly 660 times the configured rate and do not stop. The
sessions stay Up throughout; the link does not.

This is 03-testing Layer 3 scenario 5, and the question
`04-symmetric-deployment.md` parked. The README carries it as a flagged
untested assumption. It is no longer untested.

---

## 1. The measurement

Two namespaces on a Linux bridge, one veth each, so the bridge is a third
vantage outside both XDP programs. Static-mode sessions, 10ms configured
interval, which is ~100 packets per second per direction and ~1000 in a
five-second capture counting both.

```
both kernel-tx                 690223 packets in 5s (configured 10ms => ~1000 expected)
one kernel-tx (control)          1043 packets in 5s (configured 10ms => ~1000 expected)
```

The control arm is what makes this a finding rather than an observation.
One kernel-TX engine against a plain userspace peer paces normally at 1043,
within noise of the expected 1000. Turning on kernel-TX on the second side
and changing nothing else gives 690223.

Sustained, not a startup burst: separate samples at t+15s and t+45s gave
227435 and 196210 packets per two seconds, so it does not decay. Each
engine logged exactly one transition, `Down -> Up`, and nothing after. It
saturates *and keeps working*, which is the milder of the two possible
severities and still a hard constraint.

## 2. Why

Inherent to the design rather than a defect in it.

XDP bounces a control packet on receipt. There is no timer between arrival
and transmission — that is the whole point, and it is what gives the engine
its headline property: TX cannot be preempted by userspace CPU starvation
because TX is not in userspace.

Against bfdd, that is safe. bfdd paces its own transmissions from a
userspace timer, so the bounce rate is bounded by the peer's clock. One
arrival, one bounce, at the peer's interval.

Against another RX-clocked engine there is no clock anywhere in the loop.
Each bounce arrives at the far side and triggers its bounce immediately,
which arrives back and triggers the next. The rate is bounded only by how
fast two XDP programs can process frames on the available hardware.

The measured 660x is a property of this testbed's speed, not a constant.
On faster hardware it would be higher.

## 3. Consequence

**Do not deploy two xdp-bfd engines against each other with `--kernel-tx`
on both sides.** One side must run in userspace mode, or both must, for the
session to be paced at all.

That constraint is currently absent from the README, which lists symmetric
deployment as untested rather than as unsupported. It should say
unsupported, with this document as the reason.

The asymmetric case — one xdp-bfd engine against stock bfdd, which is every
deployment the project has actually measured — is unaffected and is what
all the published benchmarks describe.

## 4. What was NOT measured

Gap percentiles. The capture reports a median inter-departure of 1
microsecond and negative minima, both of which are artifacts: 1us is at the
capture's resolution limit, and negative gaps mean the bridge interleaved
two interfaces' frames out of order in the pcap. The kernel also dropped
169688 of 196205 frames in one run because the capture could not keep up.

The packet *count* is the sound measurement and it is three orders of
magnitude away from expected, so nothing here rests on the percentiles.

Whether the sessions eventually fail under longer saturation, and what the
CPU cost is, are both unmeasured. Neither changes the conclusion.

## 5. Reproducing

`rates.txt` was produced by a script that builds both arms in sequence:
two namespaces joined by a bridge, engines started with and without
`--kernel-tx` on the second side, and a 5-second `tcpdump` count on the
bridge.

The bridge matters. `tcpdump` inside either namespace sees **nothing** with
kernel-TX on both sides, because every packet is an XDP bounce at one end
and consumed by XDP at the other, so no frame ever traverses the kernel
network stack. This is the same reason the lab captures on the hypervisor
bridge rather than on the DUT. A veth pair joining the namespaces directly
has no third vantage; a bridge does.

## 6. Status

Demonstrated, unfixed, and arguably unfixable without giving up the
property the engine exists for. A rate limit in the bounce path would cap
it, but a timer in XDP is exactly what the RX-clocked design removed, and
`bpf_timer` callbacks have no packet context and cannot transmit.

The honest resolution is documentation: symmetric kernel-TX deployment is
unsupported, and the README should say so.

