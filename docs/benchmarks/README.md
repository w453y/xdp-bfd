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
preempted by userspace CPU starvation.
pcaps: bench1-bfdd-107flaps.pcap, bench1-xdpbfd-0flaps.pcap

## 2. Detection latency (xdp-bfd)

20 peer kills, detect measured from the peer's last wire packet to the
DUT's Down transition.

    n=20  min=30.2  mean=31.3  p50=31.3  p99=32.4  max=32.6 ms

Floor is 3x10ms = 30ms. Mean 1.3ms over floor, max spread 2.4ms.
Engine DETECT TIMEOUT logs corroborate (30.0-32.5ms). The m5 detect
changes (poll-aware budget, live remote-timer sync) did not smear it.
pcap: bench2-detect-dist.pcap

## 3. TX pacing (xdp-bfd, steady state)

Inter-departure of the DUT's control packets, 60s idle window.

    n=7295  min~0  p50=8.77  p99=10.01  p999=10.05  max=10.08  mean=8.77 ms

The entire tail fits inside the 10ms interval; max 10.08ms vs a 30ms
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
