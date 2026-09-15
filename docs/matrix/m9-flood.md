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
