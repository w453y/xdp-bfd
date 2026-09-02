# Multiple interfaces

What happened to a session on an interface the fast path was not attached to,
and what happens now.

## The setup

`--kernel-tx <if>` attached XDP to exactly one interface. bfdd places sessions
where routing puts them, not where that flag pointed. Until this work the
testbed had one BFD link, so the two always agreed and nothing exercised the
disagreement.

A second link was added for this: `ens20` on a separate bridge, 10.67.0.0/24,
one session at 10ms/10ms against the same peer. The 62-session mesh on `ens19`
is untouched throughout and serves as the control.

## What was wrong: two defects, not one

**The gate was per process, not per session.** `fsm_tx` suppressed
userspace transmit in Up state whenever `use_ktx` was set, on the assumption
that XDP would bounce the peer's packets. `use_ktx` only means the engine was
started with `--kernel-tx`. For a session on an unattached interface nothing
bounced, and nothing transmitted either. The session sent its `just_up` packet,
answered the peer's Poll with a Final, and then went silent.

That is not degraded timing. It is a session that cannot stay Up. Measured on
the wire before any fix, at 10ms/10ms with a 30ms budget:

- peer's last packet, then no transmission from us for three of its intervals
- peer declares Down at its detect budget
- bring-up succeeds (the slow path below Up does transmit), reaches Up
- silence again

Cycle length in the capture is 32.5ms and 35.8ms, so roughly 30 flaps per
second, sustained. Raising the session to 300ms/300ms did not help: still about
one flap per second, because the suppression does not depend on the interval.

**And the fast path did not follow the sessions.** Even with transmit
fixed, the session ran entirely in userspace: no RX-clocked bounce, no kernel
sweep, none of the scheduler immunity the project exists to provide.

## The fixes

`ktx_uncovered`, per session, set at ADD time. `fsm_tx` consults it instead of
the global flag, so an uncovered session keeps transmitting from userspace.

`ktx_load()` split from `ktx_attach_if()`. The object loads once and every
interface attaches the same program, so the maps stay shared. `dp_handle_add`
attaches on demand when a session arrives on an uncovered interface.
`ktx_uncovered` is then set from whether that attach succeeded, so it has
become the fallback rather than the normal path.

## Result

| | reply latency | userspace tx | flaps |
|---|---|---|---|
| before both fixes | no reply in Up | 0 in Up | ~30/s |
| coverage fix only | 3.1 to 9.0 ms | ~100/s | 0 over 3 min |
| plus attach table | 35 to 52 us | ~5/s | 0 |

Reply latency is the gap between the peer's packet and ours, from a hypervisor
capture. The last row is XDP answering in softirq: two orders of magnitude
faster than the userspace loop, and consistent with the ~30us bounce measured
on `ens19`.

Userspace tx near zero in the last row is the other half of the same fact: XDP
consumes the arrivals before the socket sees them, so the session's userspace
`rx_pkts` sat at 1 across 30 seconds while the wire carried ~100 packets per
second each way.

Attach state after the change:

```
xdp:
ens19(3) driver id 5086
ens20(7) driver id 5086
```

One program, two interfaces, both native mode through a bpf_link. `ens19` from
`--kernel-tx`, `ens20` on demand from the session's ADD.

## Limits

- One session on the second link. Enough to prove attach-on-demand and the
  bounce; nothing here exercises many sessions across many interfaces.
- No detach. Interfaces are attached on demand and released only when the
  process exits. bfdd deletes and re-adds sessions during reconfiguration, and
  a link that flaps with that churn would be worse than the cliff being fixed.
  Refcounting is therefore absent rather than deferred-but-designed.
- Cap of 8 interfaces, fixed array, linear scan. Consistent with the session
  table's own arrays at this scale.
- Multihop sessions are excluded from attach-on-demand. A routed session can
  ingress on any interface, so the ifindex in its ADD does not name the one
  that would need covering. They keep the previous behaviour.
- Both interfaces here took native mode, so the per-interface generic fallback
  in `ktx_attach_if` compiled but never ran.
- The before capture was taken on the DUT rather than the hypervisor. That is
  sound only because no XDP was attached to `ens20` at the time, so both
  instruments would have seen the same frames. The two after captures are
  hypervisor-side, which is the only place XDP_TX is visible.

## Files

- `before-attach-ens20.pcap`, DUT-side, the flapping session
- `after-fix-ens20.pcap`, hypervisor, stable on the userspace path
- `after-attach-ens20.pcap`, hypervisor, kernel-paced

Reproduce by configuring a session on an interface other than the one named by
`--kernel-tx` and reading `loop_rx_wakeups` and the session's `tx_pkts` in the
SIGUSR1 snapshot.
	
	
