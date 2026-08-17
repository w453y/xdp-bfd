# The sweep interval does not set detection latency

The root README describes a mean detection overshoot of roughly 1.3ms and
attributes it to the kernel sweep running every 5ms, presenting the
quantization as a deliberate trade. This measures that claim. It does not
survive.

## What was measured

`--sweep-us` (commit "make the kernel sweep interval a load-time tunable")
makes the sweep interval settable between load and attach.
`last_overshoot_us` (commit "fsm: record what each detection cost") records,
at each detect-timeout transition, how long past the negotiated budget the
session was silent before the engine declared it Down. Overshoot is the
quantity the README's figure describes.

## Method, and why not the obvious one

The obvious method - stop frr on the peer, read every session's overshoot -
produces about sixty numbers and roughly one independent sample. All the
sessions fall silent at the same instant, so their deadlines land within a
few milliseconds of each other and most are caught by the same sweep tick.
The tell is the maximum: it sits near the peer's transmit jitter rather than
near the sweep interval.

`tests/sweep_ladder.py` silences one session at a time with an egress drop
rule on the peer, waits for the engine to declare it Down, and reads the
recorded overshoot back out of the SIGUSR1 stats snapshot. Each iteration is
an independent draw.

The rule goes on the peer, not the DUT. XDP runs ahead of netfilter, so a
local rule would never see a BFD packet - the fast path would answer every
one of them.

## Results

Fifteen samples per arm, idle, 64 sessions configured and 62 up, 10ms
intervals.

| sweep | n | mean | sd | min | max |
| --- | --- | --- | --- | --- | --- |
| 5000us | 15 | 1.36ms | 0.84ms | 0.07ms | 2.92ms |
| 2000us | 15 | 1.59ms | 1.12ms | 0.03ms | 3.80ms |
| 1000us | 15 | 2.06ms | 0.65ms | 1.06ms | 2.98ms |
| 100000us | 8 | 1.63ms | 0.94ms | 0.25ms | 2.58ms |

Two things are wrong with this if the sweep were the quantizer. The trend is
inverted - a shorter sweep gives a larger mean. And the 5000us arm never
exceeds 2.92ms, where sweep phase alone would spread it over [0, 5ms).

The 100000us arm is the falsification. A 100ms quantizer cannot produce a
2.58ms maximum. Its distribution is indistinguishable from every other arm.

The 5000-vs-1000 difference is marginally significant on its own terms
(0.70ms against a pooled standard error near 0.27ms), but the arms ran in
fixed order against the same fifteen sessions, so a time-ordered confound is
not excluded. Given the 100ms arm, it is not worth chasing.

## What the measurement found

Reading the code afterwards confirms it exactly. The only transition to Down
with diagnostic 1 - control detection time expired - is in `fsm_detect`, in
userspace. `ktx.c`'s only Down path carries diagnostic 3, peer signalled.

The kernel sweep, on finding a session silent, does two things: it clears
`st->alive` and emits a ringbuf event. The engine never reads `st->alive`;
it reads only `st->echo_alive`. The ringbuf has no consumer in engine mode -
only `bfd_loader` reads it, and the loader cannot run while the engine holds
the interface.

So in engine mode the kernel detector's output goes nowhere. Detection is
entirely the userspace main loop, whose 2ms receive timeout is what the
measured 1-2ms means and 0.6-1.1ms standard deviations actually reflect.

## What this does not undermine

The project's central result is RX-clocked transmit in the kernel: control
packets are answered from XDP, which is why the fast path survives CPU
starvation that costs bfdd 44 flaps. That is transmit, and it is unaffected.

What is wrong is narrower and should be stated plainly: detection is not
kernel-side in engine mode, and the sweep interval is not what sets
detection latency.

## Why this is not being "fixed"

The apparent fix - have `ktx_poll_map` act on `alive == 0` - does not buy
what it looks like it buys. `ktx_poll_map` runs in the userspace loop, and
only userspace can notify bfdd of a state change, so a stalled engine cannot
complete a detection however the flag is wired. At idle the gain is a
fraction of a millisecond against a 30ms budget.

The sweep is not useless: it maintains `echo_alive`, and it is the only
thing that would let a future consumer see silence without polling every
session. But it is not a detector today, and wiring it up would be a change
made to match a document rather than to fix a problem.

The documentation is what needs correcting.

## Reproducing

    python3 tests/sweep_ladder.py --runs 15 --json | tee /tmp/ladder.txt
    python3 tests/sweep_ladder.py --arms 100000 --runs 8 --json

Needs passwordless sudo and key-based ssh to the peer, and iptables there.
The script restarts the engine per arm with the same flags mode_b_opt.sh
uses plus --sweep-us; arms are not comparable to other results on this
testbed if that drifts.

Afterwards, confirm no drop rule was left behind:

    ssh <peer> 'sudo iptables -L OUTPUT -n --line-numbers'

Raw samples for each run are in this directory.
