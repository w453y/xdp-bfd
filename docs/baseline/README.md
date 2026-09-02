# Milestone 1: userspace BFD (FRR bfdd) stress baseline

Baseline characterization of userspace BFD (FRR bfdd) vs the XDP
observer/detector, captured 2026-07-06/07.

## Testbed

- Proxmox VE host `pve2`, isolated internal bridge `vmbr3` (no uplink),
  ground-truth capture point via host-side tcpdump.
- 3x Ubuntu 26.04 VMs, kernel 7.0.0-27-generic, virtio-net, queues=4,
  Proxmox firewall disabled on test NICs:
  - `bfd-dut`   10.66.0.1 (4 vCPU pinned, XDP native mode on ens19)
  - `bfd-peer`  10.66.0.2 (2 vCPU, unpinned, FRR 10.5.1 bfdd)
  - `bfd-chaos` 10.66.0.3 (traffic/impairment, unused in this milestone)
- BFD session: single-hop RFC 5881, 10.66.0.1 <-> 10.66.0.2,
  rx/tx interval 10ms, detect multiplier 3 (detect time 30ms).

## Stress levels (run on bfd-dut)

- L1: stress-ng --cpu 4
- L2: stress-ng --cpu 8 --switch 4 --yield 4
- L3: stress-ng --cpu 4 --timer 8 --timerfd 4 --hrtimers 2
- L4: stress-ng --cpu 4 --sched fifo --sched-prio 50 (sudo)

## Results: FRR bfdd (userspace)

DUT->peer inter-packet gaps from host pcap (10ms nominal):

| Level | p50 | p99 | max | session |
|-------|------|------|--------|---------------------|
| L1 | 8.81 | 10.03 | ~10ms | survived |
| L2 | 8.73 | 10.03 | 750ms | flapped |
| L3 | 8.82 | 10.16 | 970ms | flapped (~44 down/up in 120s) |
| L4 | 8.82 | 287 | 960ms | flapped hard (~40% TX missing) |

Key point: L2/L3 p99 looks perfect while max exceeds the 30ms detect
budget by 25-32x — rare massive starvation events invisible to
percentile monitoring, each one fatal to the session.

## Results: XDP observer + kernel detection sweep

Under L3 stress (the 44-flap condition for bfdd), with FRR stopped and
started on the peer to create true failures:

- False positives: 0
- True-death detection latency: 33-34ms (30ms RFC budget plus the
  userspace loop's one-jiffy bound), stable under stress. CORRECTED
  2026-09-02: this read "<=5ms sweep quantization" until
  `docs/sweep-ladder/` falsified that attribution - its 100ms
  falsification arm produced a 2.58ms maximum, which a 100ms quantizer
  cannot do. The latency is unchanged; the mechanism named for it was
  wrong.
- One sweep-vs-RX race found and fixed (unsigned time delta wrap ->
  signed delta guard); visible in events.csv as the 18446744073709.6ms
  entry before the fix
- The 3004ms DOWN entry is correct RFC behavior: FRR's AdminDown
  farewell packet advertises 1s TX, renegotiating detect time to 3s

## Files

- bfd-10ms-stress.pcap        L1 run + earlier 300ms-era tail
- bfd-levels234.pcap          L2/L3/L4 runs (timestamps in git history)
- bfd-m2-observer-test.pcap   L3 rerun with XDP observer attached
- gaps-dut.txt, gaps-234.txt, tgaps-234.txt  extracted inter-packet gaps
- observer.csv                per-second XDP RX view (epoch, rx_pkts, age_ms, state[, alive])
- events.csv                  kernel detection events (DOWN/ALIVE, silent_ms)

Gap extraction: tshark frame.time_epoch filtered by ip.src + udp.dstport
3784, successive-difference in awk; percentiles via sort -n.
