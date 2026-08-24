# Tick ladder

What the main loop's tick does to detection latency, and where it stops
mattering.

## What this measures

`docs/sweep-ladder/` falsified the README's claim that detection overshoot
comes from the 5ms kernel sweep: a 100ms sweep gave the same 1-2ms overshoot,
and the code confirmed the sweep's output has no consumer in engine mode.
Detection is `fsm_detect`, called once per pass of the userspace main loop.

That left the loop's own tick as the remaining candidate, named by elimination
and never varied. `--tick-us` varies it. The tick is the `SO_RCVTIMEO` on the
control socket: the `recvmsg` blocks on it, and each return runs the
per-session pass.

## Result 1: the tick quantizes detection, over one octave

Detection overshoot, 15 samples per arm, one session silenced at a time
(`tests/sweep_ladder.py --knob tick`):

| tick | mean | sd | min | max |
|--------|--------|--------|--------|--------|
| 2000us | 2.07ms | 0.77ms | 0.93ms | 3.25ms |
| 1000us | 0.83ms | 0.64ms | 0.03ms | 1.98ms |
| 500us  | 1.16ms | 0.54ms | 0.41ms | 1.96ms |
| 500us (rerun) | 0.82ms | 0.58ms | 0.11ms | 2.00ms |
| 200us  | 0.94ms | 0.57ms | 0.02ms | 1.93ms |

2000 to 1000 is the only real difference: 1.24ms against a pooled standard
error near 0.26ms. Everything at or below 1000us is one population. The two
500us arms differ from each other by more than 500us differs from 200us, which
is the spread the ladder's own closing note warns about.

So the tick does quantize detection, and the sweep ladder's inference was
right. But only from 2000us to 1000us.

## Result 2: below one jiffy the flag does nothing

Inter-pass gap histograms, log2 buckets, 30s per arm, from the engine's own
counters (`loop-gaps.json`):

| tick | modal bucket | share | passes |
|--------|-----------------|-------|--------|
| 2000us | 2048-4095us | 98.9% | 10067 |
| 1000us | 1024-2047us | 97.8% | 15041 |
| 200us  | 1024-2047us | 98.3% | 15069 |

The 200us arm runs the same loop as the 1000us arm. A tenth of the requested
period produced no change in the measured one.

`SO_RCVTIMEO` sleeps on the jiffy timer wheel rather than an hrtimer, so a
request under one jiffy is rounded up. This host is `CONFIG_HZ=1000`, a 1ms
jiffy, which matches both modes: 2000us is two jiffies plus wakeup overhead,
and both 1000us and 200us are one.

`--tick-us` therefore has exactly two useful settings on this platform. The
range is still 200-100000 and the engine warns rather than refusing below
1000us, because the arm is worth being able to reproduce.

## What this means for making detection faster

Detection resolution in engine mode is bounded at one jiffy, and no tuning
crosses that. Going finer needs the loop to stop being `SO_RCVTIMEO`-clocked:
`ppoll` or `epoll_wait` with an hrtimer-backed timeout. That is
`02-architecture` item 2.2, which was previously argued on structure alone and
now has a measurement behind it.

This also reverses the review's ordering. Item 2.4's second half, per-session
or adaptive detection timers, cannot deliver sub-jiffy deadlines on the
current loop no matter how the timers are computed, so 2.4 is downstream of
2.2 rather than independent of it.

## Incidental: userspace almost never sees a control packet

The same counters show `loop_rx_wakeups` at roughly 4 per second across every
arm, under 1% of passes, against a mesh of 62 sessions at 10ms. With
`--kernel-tx` active, XDP consumes essentially all BFD traffic before the
socket sees it. Consistent with the design, never measured before.

It also rules out an explanation worth recording as dead: arriving traffic is
not what wakes the loop, so it is not what puts the floor under detection.

## Method notes

- Detection arms use the existing ladder: one session silenced at a time by an
  egress drop rule on the peer, because XDP runs before netfilter and a
  DUT-side rule would never see the traffic. Silencing all 62 at once gives 60
  numbers and roughly one independent sample.
- Histogram arms are cumulative from engine start, so each covers that arm's
  whole 30s life rather than a sampled window.
- The engine is not CPU-bound in any arm: `top` shows about 2% of one core at
  the default tick, state S.

## Limits

- One host, one kernel, `CONFIG_HZ=1000`. On a 250Hz kernel the jiffy is 4ms
  and the useful range of the flag would be different.
- 62 sessions, single-hop v4, one interface.
- 15 samples per detection arm. Enough to separate 2000 from 1000, not enough
  to separate anything below that, which is the point.
- The histogram is log2, so it locates a mode to within a factor of two and
  nothing finer.

## Files

- `detection-2000-1000-500.txt`, the first ladder run
- `detection-500-200.txt`, the floor check
- `loop-gaps.json`, the three inter-pass gap histograms with pass and wakeup
  counts

Reproduce with `python3 tests/sweep_ladder.py --knob tick --runs 15`.

