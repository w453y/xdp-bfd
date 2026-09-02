# Benchmarks

All fresh, both columns measured this session on the m5-hardening
binary (all poll/transitional-TX/persistence/hardening code live).
Wire numbers from host-side tcpdump on the hypervisor bridge; fast-path
cost from in-kernel BPF run stats. VM measurement (see
reproduction.md): relative comparisons are sound, absolutes provisional
until bare metal. Rig: 3 VMs, isolated bridge, DUT 4 vCPU pinned,
native XDP (not generic), 3x10ms timers (30ms detect budget).

## 1. Resilience (the headline)

Identical stress ladder against stock bfdd (mode A) then xdp-bfd
(mode B): L3 timer pressure (stress-ng --cpu 4 --timer 8 --timerfd 4
--hrtimers 2, 120s) then L4 RT starvation (--cpu 4 --sched fifo
--sched-prio 50, 60s). Flaps counted from the peer's transmitted state
transitions on the wire.

    stock bfdd:  107 flaps (214 transitions / 2)
    xdp-bfd:     0 flaps, peer uptime spanned the full ~3 min untouched

bfdd's TX rides the userspace scheduler; RT starvation blocks it for
up to ~900ms (original writeup), tripping the peer's 30ms budget
repeatedly. xdp-bfd's TX is RX-clocked in softirq and cannot be
preempted by userspace CPU starvation. At idle the two are
equivalent (results 2-3); the difference is entirely under load.
pcaps: bench1-bfdd-107flaps.pcap, bench1-xdpbfd-0flaps.pcap

## 2. Detection latency (xdp-bfd)

20 peer kills, detect measured from the peer's last wire packet to the
DUT's Down transition.

    xdp-bfd:  n=20  min=30.2  mean=31.3  p50=31.3  p99=32.4  max=32.6 ms
    bfdd:     n=20  min=30.0  mean=30.05 p50=30.0  p99=30.08 max=30.09 ms

Floor is 3x10ms = 30ms. bfdd is marginally tighter at idle: its
detection runs on a hrtimer at almost exactly 3x interval, while
xdp-bfd's runs in the userspace loop, bounded by one jiffy.
This is the tradeoff: ~1.3ms of idle detection granularity for
scheduler immunity (see result 1). Mean 1.3ms over floor, max spread 2.4ms.

CORRECTED 2026-09-02: this passage previously attributed the ~1.3ms to
quantization by the 5ms bpf_timer sweep. `docs/sweep-ladder/` falsified
that. The trend is inverted - a shorter sweep gives a LARGER mean - the
5000us arm never exceeds 2.92ms where sweep phase alone would spread it
over [0, 5ms), and the 100000us falsification arm produced a 2.58ms
maximum, which a 100ms quantizer cannot do. The sweep contributes nothing
in engine mode. The numbers above are unchanged and were never in doubt;
only the mechanism was wrong.
Engine DETECT TIMEOUT logs corroborate (30.0-32.5ms). The m5 detect
changes (poll-aware budget, live remote-timer sync) did not smear it.
pcap: bench2-detect-dist.pcap

## 3. TX pacing (xdp-bfd, steady state)

Inter-departure of the DUT's control packets, 60s idle window.

    xdp-bfd:  n=7295  p50=8.77  p99=10.01  p999=10.05  max=10.08  mean=8.77 ms
    bfdd:     n=7304  p50=8.79  p99=10.01  p999=10.08  max=11.74  mean=8.76 ms

At idle the two are twins (mean 8.77 vs 8.76, p99 both 10.01);
bfdd already shows a small tail past the interval (max 11.74 vs
10.08), both well inside the 30ms budget. The entire xdp-bfd tail fits inside the 10ms interval; max 10.08ms vs a 30ms
budget (3x margin). Contrast the baseline finding where bfdd p99 looked
healthy at 10.2ms while max exceeded 900ms under stress. The
transitional-TX gate added in m5 introduced no outliers. (The ~0ms
minima are a handful of poll/final or transition back-to-backs.)
pcap: bench3-pacing.pcap

## 4. Fast-path cost (xdp-bfd)

In-kernel BPF run stats (kernel.bpf_stats_enabled), ~20s at 10ms.

    run_time_ns 1599075 / run_cnt 2281 = 701 ns mean per packet

Full per-packet cost: parse, GTSM, length/demux validation, session
map update, and on the echo path the L2/L3/L4 rewrite plus XDP_TX,
averaged across echo and non-echo packets. ~701ns in softirq is the
mechanistic reason for result 1: the TX turnaround no userspace
scheduler can block.

## Reconciliation with the original writeup

These fresh numbers are consistent with docs/writeup.md; the apparent
differences are method, not drift:

- bfdd flaps: writeup reports 44 in 120s at L3 alone; bench 1 reports
  107 across L3+L4 combined in one window. L4 (RT starvation) flaps
  bfdd continuously (writeup s4), so the combined count is expectedly
  higher. Different windows, both correct.
- xdp-bfd flaps: writeup s6 shows 0 at L1/L2/L4 and 1 at L3 (a single
  ~28ms softirq-latency graze, one packet in ~66000, self-healed in
  3.8ms). bench 1 saw 0 across L3+L4 this run; the L3 graze is rare and
  non-deterministic, not a regression.
- detect latency: writeup cites 33-34ms under full stress; bench 2
  measures 31.3ms mean at idle. Idle is slightly faster (no softirq
  queuing); both sit in the 30-34ms band above the 30ms floor, set by
  the userspace loop's one-jiffy bound, not by the sweep - see the
  correction under result 2.
- pacing: writeup p50 8.75 / max ~10-13ms; bench 3 p50 8.77 / max
  10.08ms. Same distribution.

New this session and not in the writeup: the head-to-head idle detect
comparison (bfdd 30.05ms vs xdp-bfd 31.3ms). bfdd's hrtimer detection
is marginally tighter at idle; xdp-bfd trades that for scheduler
immunity under load. The writeup never measured this directly.

Mode A/B setup scripts: mode_a.sh, mode_b.sh in this directory.
