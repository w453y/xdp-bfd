# M9: flood cost per drop path

Injector bfd-chaos (10.66.0.3, 2 vCPU, virtio) into the 64-session mesh DUT.
Rate labels are nominal; the pps column is measured. The virtio TX ceiling
is ~700k pps and does not rise with injector cores (661k/724k/716k at
2/4/8), so 700k is line rate for this path, not a target missed.

Headline is nanoseconds per frame on the attached XDP program
(bpftool run_time_ns / run_cnt delta, kernel.bpf_stats_enabled=1), because
that number times any NIC's line rate is the cost on that NIC. Idle
baseline 1439 ns/frame, dominated by the sweep walking 64 sessions.

Counter note: arm A moves only `seen` by design (cbd30d6 leaves non-BFD
traffic before counting). Every BFD-port arm should move a named counter;
where it does not, that is a finding, not a quiet zero.

| arm | path | rate | meas pps | ns/frame | seen d | counter d | peer downs | mesh after | recover |
|---|---|---|---|---|---|---|---|---|---|
| B | unknown-session BFD (G3) | 100k | 46327 | 125 | 315216 | rejected +0 | 0 | 64/64 | 1s |
| B | unknown-session BFD (G3) | 300k | 90235 | 183 | 578525 | rejected +0 | 0 | 64/64 | 1s |
| B | unknown-session BFD (G3) | 700k | 590988 | 82 | 2061335 | rejected +0 | +18 | 63/64 | 2s |

## G3, before the fix

A well-formed BFD packet for an unconfigured address pair is not rejected
in XDP (rejected +0 at every rate); it is passed to the stack, where the
engine socket is the only consumer of 3784. At ~590k pps this evicted
legitimate packets from the socket queue and caused 18 real session down
events, briefly dropping the mesh to 63/64. It recovered in 2s once the
flood stopped. That is the number G3 (XDP_DROP for unknown sessions) is
measured against: after the fix this arm should show peer downs 0 and the
count moving to a new UNKNOWN_SESSION counter rather than reaching the
socket at all.

At 700k, 3.66M frames were sent and 2.06M reached XDP: ~1.6M were dropped
at the NIC RX ring before the program saw them, which is the driver's own
backpressure and not a program property.
