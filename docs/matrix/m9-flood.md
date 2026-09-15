# M9: flood cost per drop path

Injector bfd-chaos (10.66.0.3, 2 vCPU, virtio) into the 64-session mesh
DUT. Rate labels are nominal; pps is measured. The virtio TX ceiling is
~700k pps and does not rise with injector cores (661k/724k/716k at 2/4/8),
so 700k is line rate for this path.

Headline is nanoseconds per frame on the attached program
(bpftool run_time_ns/run_cnt delta, kernel.bpf_stats_enabled=1): that
number times any NIC's line rate is the cost on that NIC. Idle baseline
1439 ns/frame, dominated by the sweep walking 64 sessions, not by parsing.

Each frame's path was verified by dumping every counter for a controlled
burst before the arm was labelled, because a frame that looks like one path
can take another: a 24-byte fill payload to port 3784 is not a BFD control
packet, it is counted malformed and dropped, not passed as an unknown
session. The frames below are the ones whose counter signature matches
their intent.

## Counter signatures (verified)

| frame | counter that moves | XDP verdict |
|---|---|---|
| non-BFD UDP (arm A) | seen only | PASS, cbd30d6 leaves it |
| TTL != 255 to 3784 | would be rejected | GTSM drop, but only if well-formed first |
| bad version / short (arm C) | malformed | DROP in XDP |
| valid BFD, unknown pair, TTL255 (G3) | well-formed only | PASS to socket |

The order matters: bfd_ctrl_check tests version and length before anything
else, so a malformed frame to a BFD port is counted malformed and never
reaches the GTSM or unknown-session logic. To exercise GTSM or G3 the frame
must be a valid BFD control packet first.

## G3, before the fix (valid BFD, unknown pair, TTL 255)

| rate | meas pps | reached XDP | well-formed d | sessions | 
|---|---|---|---|---|
| 300k | 91,054 | 462,481 | +461,482 | 64/64 |
| max  | 590,000+ | 1,857,742 | +1,856,783 | 64 -> 61 |

A well-formed BFD packet for an unconfigured address pair is neither
rejected nor malformed: well-formed climbs and nothing else moves, so it is
passed to the stack, where the engine socket is the only consumer of 3784.
At the injector ceiling this evicted legitimate packets and dropped the
mesh to 61/64; it recovered within a few seconds after the flood stopped.
This is a single 5-tuple, so it lands on one RX queue and one core, and it
still hurt sessions to OTHER peers because the socket is shared: G3 is the
only path where one forger can flap sessions it is not even addressing.
After G3 (XDP_DROP plus an UNKNOWN_SESSION counter) this arm should show
well-formed flat, the new counter climbing, and the mesh untouched.

At max rate 3.8M frames were sent and 1.86M reached the program: the NIC RX
ring dropped the rest before XDP, which is the driver saturating on one
core, not a program property.

## arm C, malformed flood

A short or wrong-version frame to 3784 is counted malformed and dropped in
XDP, so it never reaches the socket. At ~590k pps the drop is cheap
per-frame but the raw volume still saturated the core and caused a handful
of flaps through CPU starvation rather than socket eviction. That
distinction is the point: malformed is already handled in the program;
what G2 adds is dropping it for a BFD port specifically, and its cost is
already paid here.

## The socket-eviction witness (added after two mislabels)

BPF counters cannot tell a flood that starves the socket from one that
only saturates the core, because a malformed frame is XDP_PASS
(validate.h:42) and reaches the socket too, where the engine rejects it
with a counter-less `continue`. The witness is UdpRcvbufErrors from
/proc/net/snmp: datagrams the kernel dropped because the socket queue was
full, which is eviction by name. Every arm records its delta.

Measured, same rate, 5s each:
  malformed to 3784 (G2):        RcvbufErrors +0
  valid BFD, unknown pair (G3):  RcvbufErrors +19168

So the two are not the same risk. A malformed frame is passed to the
socket but discarded so cheaply that the queue never backs up; a valid
frame for an unknown pair costs a full session lookup before it is
discarded, and at rate that backs the queue up and evicts real sessions'
packets. G3 is the socket-eviction path; G2's cost is CPU, not eviction.
That distinction was invisible until the witness, and it is why the first
two labellings were wrong.

After G2/G3 (XDP_DROP for both), the after-table must show RcvbufErrors
flat on arms C and D and the mesh untouched.

### CAVEAT on the G2/G3 split (unresolved)

The +19168 vs +0 contrast above is not yet safe, for two reasons found
while checking the proposed cause against the code:

1. The frame used for the G3 witness carries state Up. main.c:830 gates
   the address-pair fallback scan on BFD_STATE <= ST_DOWN, so an Up-state
   packet with your_disc 0 has sess_by_wire(0) short-circuit to NULL and
   the sess_by_addr scan is NEVER run. So the frame measured does not
   exercise the linear-scan cost that would explain the eviction. The
   attack that actually forces the scan is a DOWN-state unknown-pair
   frame; that is what arm D must send.
2. The two witness runs did not record pps. The malformed frame (30 bytes)
   and the valid frame (60 bytes) differ in size, so at the virtio
   descriptor ceiling they may have run at different pps, and an eviction
   difference could be a rate artifact rather than a per-packet cost.

So the split stands as an observation, not a mechanism, until arm D is
re-run with state Down and both arms record measured pps. The witness
instrument itself is sound; what is unproven is the attribution.

## Injector ceiling: per-guest, not per-bridge (measured)

A second injector (bfd-chaos2, 10.66.0.4, 2 vCPU, virtio on vmbr3, the
single-hop mesh bridge; NOT vmbr9, which is the pve1 matrix segment and
does not reach the DUT) was built to test whether the ~700k ceiling is a
property of one guest's virtio TX or of the bridge.

Arm A (spread source ports, drnd) reaching XDP via seen, 6s each:
  injector 1 alone   455,075 pps
  injector 2 alone   439,225 pps
  both together      961,914 pps

Both-together is the sum of the singles, so the bridge is not the limit;
the ~700k figure was one guest's virtio TX. The spread-traffic arms gain a
~960k rung with two injectors, and the ladder would scale with more. The
mesh held 64/64 with deadman-hold 0 throughout, so ~960k pps of unrelated
traffic across queues still does not disrupt the fast path.

Single-flow arms (B-G) do not benefit: one 5-tuple hashes to one RX queue
and one core regardless of how many injectors send it, so the per-frame
cost on that core is the measure there, not aggregate pps.

(The spread-arm per-injector figure here, ~450k, is below the 787k of the
earlier fixed-port arm A because drnd randomises the source port per packet
and costs trafgen more to generate; it is the two-injector scaling that is
the result, not the absolute per-injector number.)

## G2/G3 before, matched size and recorded pps (corrects the earlier split)

Arm D (valid BFD, state DOWN, your_disc 0, unconfigured pair, the frame
that reaches the address-pair scan and is indistinguishable from a peer
re-establishing) and arm C (the identical 66-byte frame, version 0 so
bfd_ctrl_check counts it malformed) at gap 0. Counter dump confirmed the
path first: D moved well-formed, C moved malformed.

| arm | pps | RcvbufErrors | peer-downs | mesh | recover |
|---|---|---|---|---|---|
| D valid unknown pair (G3) | 632,250 | +9,208 | +29 | 63/64 | 1.0s |
| C malformed, matched (G2) | 694,933 | +67,224 | +34 | 61/64 | 2.4s |

Both paths reach the socket (XDP_PASS, confirmed by the counters) and both
evict legitimate packets: RcvbufErrors climbs for both, and both flap real
sessions. This CORRECTS the earlier witness run, which showed malformed
+0 and was measured with a 30-byte malformed frame against a 60-byte valid
one at unrecorded pps; the size confound, not a real difference. At matched
size both evict, and malformed evicts more.

So G2 and G3 are the same class of risk: a frame the driver passes to a
socket only the engine reads, at a rate that overflows the queue. Both need
the XDP_DROP fix, and the after-table must show RcvbufErrors flat on both.
Why malformed evicts more than a valid unknown pair at matched size is not
established (the valid path does more userspace work per packet, which
would predict the opposite); it is left as an open question, not a
mechanism, and it is moot once both are dropped in the driver.

## Arm B (GTSM drop) is the reference: what an XDP drop looks like

Arm B, the same valid BFD frame at TTL 64, gap 0:

  rejected +365409, RcvbufErrors +0, mesh 64/64, 667102 pps

This is the control that makes C and D mean something. At the same ~660k
pps, a frame dropped in XDP (B, GTSM) leaves the socket completely alone
(RcvbufErrors +0) and does not flap a single session, while frames passed
to the socket at the same rate (C malformed +67k, D unknown-pair +9k) evict
and drop the mesh to 61-63/64. That contrast IS the G2/G3 argument: the fix
is to make C and D behave like B, dropped in the driver, and the after-table
target is RcvbufErrors +0 and mesh 64/64 for both, exactly as B reads now.

## Before-table so far (two injectors, matched frames, recorded pps)

| arm | path | XDP today | pps | RcvbufErrors | mesh | 
|---|---|---|---|---|---|
| A | non-BFD, spread | PASS (left) | 961,914 agg | n/a | 64/64 |
| B | valid, TTL64 | DROP (GTSM) | 667,102 | +0 | 64/64 |
| C | malformed | PASS | 694,933 | +67,224 | 61/64 |
| D | valid, unknown pair | PASS | 632,250 | +9,208 | 63/64 |

A and B leave the mesh intact; C and D evict. B proves an XDP drop costs the
socket nothing at this rate, which is the after-state G2/G3 must reach.
Arms E (demux fail on a real session), F (bad digest on an auth session,
the G4 arm) and G (echo) remain and need a live session's discriminators.
