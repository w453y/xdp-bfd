
## Injector ceiling (measured)

bfd-chaos into the mesh tops out near 700k pps and adding cores does not
help: 661k / 724k / 716k at 2 / 4 / 8 vCPUs. The bound is per-guest virtio
TX, not the generator's CPU. Do not resize the injector for rate; a second
injector VM on the test segment is the only way higher, and only the
single-flow arms would need it (a spoofed peer is one 5-tuple to one RSS
queue, so one DUT core eats it regardless of injector rate).

## Flood arms: the per-arm checklist

m9-flood.py drives the flood arms. Three arms were mislabelled in one night
because the frame did not take the path its label named, so before a number
is attached to an arm, pin every field that selects a path and record it:

- **state** — the demux fallback in main.c:830 only runs for
  BFD_STATE <= ST_DOWN. An Up-state packet with your_disc 0 is dropped
  cheaply and never reaches the address-pair scan. To exercise the unknown-session drop's real
  cost the frame must be state DOWN.
- **your_disc** — 0 selects the address-pair path; nonzero selects the
  wire-disc scan. Choose deliberately.
- **TTL / hop_limit** — 255 clears GTSM; anything else is the GTSM drop,
  but only after the frame is well-formed, because bfd_ctrl_check runs
  first. A malformed frame never reaches the GTSM check.
- **flags** — the A bit and the M bit each take their own verdict; leave
  them clear unless the arm is about them.
- **well-formedness** — vers 1, len >= 24, mult != 0, my_disc != 0, or the
  frame is counted malformed and XDP_PASS'd before any path under test.
- **size and pps** — record both. At the virtio ceiling a smaller frame
  reaches a higher pps, so two arms of different sizes are not comparable
  unless pps is measured, not assumed from the gap.

Then dump every counter for a short burst and confirm the counter that
moves is the one the arm's path predicts, BEFORE the timed run. The
counter-signature table in matrix/m9-flood.md on the docs branch is the
reference; an arm
whose dump does not match its row is mislabelled, not a finding.
