# The main loop

What the userspace loop does per pass, what changed in 2026-08, and why the
ringbuf still has no consumer.

## What it was

One `recvmsg` on the v4 control socket, blocking on `SO_RCVTIMEO`, was the
clock. Everything else ran after it returned: three more RX drains with
`MSG_DONTWAIT`, then a per-session walk calling `ktx_poll_map`, `fsm_detect`,
`fsm_tx` and `echo_tx_maybe`. `dp_accept` and `dp_read` ran at the top of the
pass, before any of it.

Three costs followed from that shape.

`SO_RCVTIMEO` sleeps on the jiffy timer wheel, so a tick under one jiffy was
rounded up and the loop ran no faster. `investigations/tick-ladder/` measures it: at
`--tick-us 200` the loop period sat at 1024-2047us, the same as at 1000us.

The blocking wait was on the v4 socket alone, so a v6 packet arriving just
after the loop settled waited out the v4 timeout before anything looked at it.
29 of this testbed's 62 sessions are v6.

And every pass made a syscall per session for the map poll, plus four blind
socket drains and two blind dplane calls, whether or not any of them had
anything to do.

## What changed

Four commits, each measured before the next was written.

**A timerfd clock and a poll over every fd.** The wait became `poll` on a
timerfd armed at `--tick-us` plus all four RX sockets. Hrtimer-backed, so the
tick is honoured: at 200us the modal loop period moved from 1024-2047us to
128-255us, 99.7% of passes. At the 2000us default the loop went from about 400
passes per second to 513 against a nominal 500, because the old timeout
restarted its countdown after the work rather than on a fixed period.

**Drains gated on readiness.** Each RX socket is touched only when poll
reported it readable. The four blind `MSG_DONTWAIT` calls per pass are gone.

**One batch map fetch per pass.** `ktx_poll_all()` does a single
`BPF_MAP_LOOKUP_BATCH` before the session walk; `ktx_poll_map` reads its
session's entry out of that array instead of making its own syscall. The rest
of `ktx_poll_map` is untouched, so echo RTT accounting, Poll termination, MAC
learning and the parameter renegotiation all behave exactly as before. Data
freshness is unchanged: the batch is taken in the same pass that reads it.

There is a fallback. If the batch syscall returns EINVAL or EOPNOTSUPP the
engine says so once and reverts to per-session lookups. Without that an old
kernel would have stopped syncing from the map silently while looking healthy,
which is the failure mode the per-session kernel-TX gate already taught this
project to distrust.

**dplane fds in the poll set.** `dp_accept` and `dp_read` moved below the poll
and run only when their fd is readable. `dp_fds()` hands the loop the current
pair each pass rather than caching, because `dp_conn` is replaced on reconnect
and closed on drop.

## Measured

Syscalls per pass, from `strace -c` on the running engine:

| | before | after |
|---|---|---|
| map lookups | 59 (one per session) | 1 |
| RX drains | 4, all EAGAIN at idle | 0 at idle |
| dplane | 2, both failing | 0 at idle |
| total | about 66 | about 3.3 |

CPU, one core, 62 sessions at idle:

| tick | before | after |
|--------|--------|--------|
| 2000us | 3.0 to 3.5% | 2.0 to 2.5% |
| 200us  | 20 to 23.5% | 10 to 11% |

The batch fetch is what moved CPU. The two gating commits removed about 10k
failing syscalls per second between them and did not change CPU measurably,
which is worth stating rather than implying otherwise: cheap failing syscalls
are cheap.

A caveat on the syscall figures. Under `strace` the process becomes
syscall-bound, so the pass rate during a trace is not the engine's real pass
rate and absolute call counts from different traces are not comparable. The
per-pass ratios above are, and the CPU figures were taken without `strace`
attached.

Detection overshoot is unaffected by all four commits: the 200us arm of
`investigations/tick-ladder/` was rerun afterwards and gave the same 0.09ms mean and
0.06ms sd from a different set of samples.

## The ringbuf still has no consumer

The kernel sweep pushes DETECT-DOWN and ALIVE events into `bfd_events`. In
engine mode nothing reads them; only the standalone loader does.
`02-architecture` item 2.2 proposed consuming them, for two stated reasons.
Both are now falsified:

- *Cost.* The review counted about 32k map-lookup syscalls per second at idle.
  That is now one syscall per pass, independent of session count.
- *Quantization.* Detection notice was said to be quantized by the poll tick on
  top of the sweep. `investigations/sweep-ladder/` showed the sweep contributes nothing in
  engine mode, and overshoot at a 200us tick is 0.09ms, 0.3% of a 30ms budget.

So it is not done, deliberately. Two conditions would change that, and neither
holds today.

**If the session cap lifts.** The batch fetch is O(sessions) per pass: it
copies every entry and `poll_find` scans the returned keys per session. At 62
that is free. At 500 it is 250k key comparisons per pass, plus 50KB copied,
every tick. A ringbuf is O(changes) instead. That inversion is a better
argument for consuming it than anything in the review, but it is downstream of
lifting the 64-session cap, which is a port-range limit needing its own work
(multiple port blocks or a shared source port, plus hash demux maps).

**If the reader moves off the main loop.** Under RT starvation detection takes
about 950ms because `fsm_detect` cannot run (`investigations/starved-detection/`). The
kernel's verdict is already correct and already in the ring during that window.
Consuming it from the same starved loop changes nothing, since the reader is
starved too. Consuming it from a separate schedulable entity would let the
notification reach bfdd during starvation, which is a real improvement and a
much larger change than "add a consumer".

Until one of those is true, the honest options are to consume the ring for no
measured benefit or to stop allocating it in engine mode. Neither has been
done; the ring is left in place because the standalone loader uses it and
removing it would fork the map set between the two consumers.

## Limits

- One host, `CONFIG_HZ=1000`, 62 sessions, idle.
- The v4 single-hop path still handles exactly one packet per pass inline,
  while the other three drain up to `MAX_SESSIONS`. That asymmetry predates
  this work and is not addressed by it.
- `poll_find` is a linear scan. Fine at 64, not at 500. See above.
- CPU figures are `top` samples over a few seconds, not a profile.

