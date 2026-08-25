# Tick ladder

What the main loop's tick does to detection latency, measured twice: once
against the `SO_RCVTIMEO` clock the engine used to have, and once against the
timerfd that replaced it.

## What this measures

`docs/sweep-ladder/` falsified the README's claim that detection overshoot comes
from the 5ms kernel sweep: a 100ms sweep gave the same 1-2ms overshoot, and the
code confirmed the sweep's output has no consumer in engine mode. Detection is
`fsm_detect`, called once per pass of the userspace main loop.

That left the loop's tick as the remaining candidate, named by elimination and
never varied. `--tick-us` varies it.

## Ladder 1: the SO_RCVTIMEO clock

The loop's wait was a socket timeout. Detection overshoot, 15 samples per arm,
one session silenced at a time:

| tick | mean | sd |
|--------|--------|--------|
| 2000us | 2.07ms | 0.77ms |
| 1000us | 0.83ms | 0.64ms |
| 500us  | 1.16ms | 0.54ms |
| 500us (rerun) | 0.82ms | 0.58ms |
| 200us  | 0.94ms | 0.57ms |

Only 2000 to 1000 was a real difference. Everything at or below 1000us was one
population, and the two 500us arms differed from each other by more than 500
differed from 200.

The engine's own inter-pass gap histogram said why:

| tick | modal bucket | share |
|--------|-----------------|-------|
| 2000us | 2048-4095us | 98.9% |
| 1000us | 1024-2047us | 97.8% |
| 200us  | 1024-2047us | 98.3% |

A 200us request produced the same loop as a 1000us one. `SO_RCVTIMEO` sleeps on
the jiffy timer wheel rather than an hrtimer, so anything under one jiffy is
rounded up. This host is `CONFIG_HZ=1000`.

The conclusion at the time was that `--tick-us` had exactly two useful settings.
That conclusion is now wrong, which is the point of the second ladder.

## Ladder 2: the timerfd clock

The wait became a `poll` over a timerfd armed at `--tick-us` plus all four RX
sockets. Same test, same 15 samples per arm:

| tick | mean | tick/2 | sd | min | max |
|--------|--------|--------|--------|--------|--------|
| 2000us | 1.20ms | 1.00ms | 0.56ms | 0.10ms | 1.99ms |
| 1000us | 0.40ms | 0.50ms | 0.27ms | 0.03ms | 0.99ms |
| 500us  | 0.22ms | 0.25ms | 0.10ms | 0.00ms | 0.36ms |
| 200us  | 0.09ms | 0.10ms | 0.06ms | 0.01ms | 0.19ms |

Every arm lands within a factor of 1.2 of tick/2, and the spread halves with
each halving of the tick, which is what a uniform distribution over [0, tick)
does. No floor appears down to 200us.

The gap histogram agrees: at 200us the modal bucket is 128-255us at 99.7%,
against 1024-2047us for the same setting under the old clock.

The 2000us arm improved too, from 2.07ms to 1.20ms, because the old timeout
restarted its countdown after each pass finished, making the real period the
timeout plus the work. The timerfd is periodic, so the loop now runs at 513
passes per second against a nominal 500 rather than the previous 400.

Detection overshoot at 200us is 0.09ms. Under the old clock the same setting
gave 0.94ms. Against the 5ms-sweep era's ~1.3ms it is about fifteen times
better.

## What it costs

Every pass walks all configured sessions, so CPU scales with the tick:

| tick | overshoot | CPU (one core) |
|--------|-----------|----------------|
| 2000us | 1.20ms | 2.0 to 2.5% |
| 200us  | 0.09ms | 10 to 11% |

At 62 sessions, 1.1ms of detection accuracy costs about 8% of a core. Against a
30ms budget that is still a poor trade, so the default stays at 2000us. Against
a 3ms budget it may not be, which is what the flag is for.

Those figures are after the batch fetch below. Before it they were 3.0 to 3.5%
and 20 to 23.5%, so the same accuracy now costs about half what it did.

Where the CPU went: each pass called `ktx_poll_map` per session, one map lookup
syscall each. At 2000us that was about 31k syscalls per second; at 200us about
310k, and 67% of the engine's syscall time. `02-architecture` item 2.2 flagged
the first figure. One `BPF_MAP_LOOKUP_BATCH` per pass replaced all of them:
`bpf` calls fell from 76953 to 2523 over the same window, and CPU at 200us
halved.

Two smaller reductions landed alongside it and are worth separating from that
result, because neither moved CPU measurably: the four RX drains now run only
when poll reports the socket readable (about 5150 failing syscalls removed per
1300 passes), and the dplane listen and connection fds are polled rather than
called blind (another 5000). Both remove real waste; neither was where the time
was going.

## What this settles

Detection resolution in engine mode is now bounded by the configured tick and
nothing else, down to at least 200us.

It also settles `02-architecture` item 2.4's second half. Adaptive or
per-session detection timers were proposed to reduce this quantization; a fixed
200us tick already puts overshoot at 0.3% of a 30ms budget, so the added
complexity has nothing left to buy. The review listed 2.4 after 2.2; the
measurement says 2.2 removes the need for 2.4 rather than preceding it.

## Limits

- One host, `CONFIG_HZ=1000`. Ladder 1's floor would sit elsewhere on a 250Hz
  kernel; ladder 2 should not care, but that is untested.
- 62 sessions, single-hop v4 arms, one interface for the silenced session.
- 15 samples per arm. Enough to separate adjacent arms in ladder 2, where the
  spread is small; ladder 1's lower arms were never separable.
- Nothing below 200us was measured. The flag's floor is 200us by argument, not
  by evidence.
- CPU figures are `top` samples over a few seconds at idle, not a profile.
- Ladder 2 was measured before the batch fetch and the two poll-gating
  commits. The 200us arm was rerun afterwards and gave the same 0.09ms
  mean and 0.06ms sd from a different set of samples, so the arms carry
  over; the other three were not rerun.

## Files

- `detection-2000-1000-500.txt`, ladder 1 first run
- `detection-500-200.txt`, ladder 1 floor check
- `loop-gaps.json`, ladder 1 gap histograms
- `detection-timerfd.txt`, ladder 2
- `loop-gaps-timerfd.json`, ladder 2 gap histograms

Reproduce with `python3 tests/sweep_ladder.py --knob tick --runs 15 --arms
2000,1000,500,200`.

