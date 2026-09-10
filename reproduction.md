# Reproduction guide

Everything needed to reproduce the results in [writeup.md](writeup.md): topology, setup, stress procedures, capture, and analysis. Commands are generalized; substitute your own interface names, bridge names, and addresses. The specific values used in this project are noted where they matter.

The core methodology, if you take nothing else: capture on the hypervisor, not in the guest. The host sees actual wire times and is immune to guest-side scheduling, socket buffering, and log buffering. Every number in the writeup comes from host-side tcpdump.

## 1. Topology

Three VMs on one hypervisor, two networks:

```
                    hypervisor (Proxmox in this project)
                    tcpdump here = ground truth
                             |
        +--------------------+--------------------+
        |          isolated test bridge           |
        |       (no physical uplink, no DHCP)     |
        +----+-----------------+-------------+----+
             |                 |             |
         [ DUT ]           [ peer ]      [ chaos ]
        10.66.0.1         10.66.0.2     10.66.0.3
      runs xdp-bfd       runs stock    traffic gen
      and/or bfdd        FRR bfdd      (optional)
```

Plus a separate management bridge on each VM for SSH, so nothing pollutes the test segment.

VM specs used here (adjust to taste, but note the constraints):

- All: Ubuntu 26.04 (kernel 7.0), virtio-net on the test NIC with multiqueue enabled (queues=4 on the DUT), hypervisor firewall disabled on the test NICs (intermediate firewall bridges add hops and confuse captures).
- DUT: 4 vCPU (pinned to dedicated host cores), 8 GB. CPU type host, not emulated: the BPF JIT wants real CPU features.
- Peer and chaos: 2 vCPU, 4 GB, deliberately unpinned.
- Test subnet: any private /24, static addresses, no gateway, no DHCP. Single-hop BFD (RFC 5881) requires the peers on the same subnet.

Kernel requirements on the DUT: >= 6.12 or so for comfortable BPF development (this project used 7.0), CONFIG_DEBUG_INFO_BTF=y (check: /sys/kernel/btf/vmlinux exists), JIT enabled (sysctl net.core.bpf_jit_enable = 1).

Sanity checks before anything else:

```
# on DUT: driver, multiqueue, BTF
ethtool -i <test-if> | head -2        # expect virtio_net (or your NIC)
ethtool -l <test-if>                  # combined queues >= vCPU count
ls /sys/kernel/btf/vmlinux

# path is clean L2 (TTL untouched)
ping -c2 -t 255 <peer-ip>

# host-side observer works (on the hypervisor, while pinging)
tcpdump -i <test-bridge> -c 5 icmp
```

## 2. FRR baseline session

Install FRR on DUT and peer, enable bfdd:

```
sudo apt install -y frr frr-pythontools
sudo sed -i 's/bfdd=no/bfdd=yes/' /etc/frr/daemons
sudo systemctl restart frr
```

Configure the session on both sides (mirror the peer address), in vtysh:

```
configure
bfd
 peer <other-side-ip> interface <test-if>
  receive-interval 300
  transmit-interval 300
  detect-multiplier 3
  no shutdown
end
write memory
```

Bring it up at 300ms first, confirm `show bfd peers` reports Status: up on both sides, then tighten both sides to receive-interval 10 / transmit-interval 10. Detect time is now 3 x 10ms = 30ms. Do not `systemctl restart frr` after vtysh changes; changes apply live, and a restart without `write memory` loses them.

Capture the session from the hypervisor for the whole test:

```
tcpdump -i <test-bridge> -w baseline.pcap udp port 3784
```

Reading the Down -> Init -> Up handshake and the timer negotiation in that pcap (Wireshark, filter `bfd`) is worth twenty minutes before going further.

## 3. The stress ladder

All stress runs on the DUT. Bracket every run with epoch timestamps so pcaps can be sliced per level afterwards:

```
date +%s > window.txt
<stress command>
date +%s >> window.txt
```

The ladder, in escalating order:

```
# L1: fair-scheduler CPU saturation
stress-ng --cpu 4 --timeout 120s

# L2: oversubscription + context-switch churn
stress-ng --cpu 8 --switch 4 --yield 4 --timeout 120s

# L3: timer subsystem pressure (this one killed bfdd: 44 flaps/120s)
stress-ng --cpu 4 --timer 8 --timerfd 4 --hrtimers 2 --timeout 120s

# L4: real-time priority starvation (this kills every unprivileged userspace sender)
sudo stress-ng --cpu 4 --sched fifo --sched-prio 50 --timeout 60s
```

Scale the counts to your vCPU count (these assume 4). L4 makes the VM console sluggish for its duration; that is the point.

Observing flaps: watch the peer, not the DUT (the DUT's own view is unreliable under load; see writeup section 3):

```
# on the peer, during the run
watch -n1 'sudo vtysh -c "show bfd peers" | grep -E "Status|Uptime|Diagnostics"'
```

Better: count flaps from the wire afterwards. Every state transition the peer transmitted is in the pcap:

```
tshark -r <file>.pcap -Y "ip.src==<peer-ip>" -T fields -e frame.time_epoch -e bfd.sta \
  | awk '{if(p!="" && $2!=p) printf "t=%.0f state %s -> %s\n",$1,p,$2; p=$2}'
```

`0x03 -> 0x01` transitions are Up -> Down flaps. Enable `debug bfd peer` in vtysh on both sides if you also want FRR's own transition log in /var/log/frr/frr.log.

## 4. Gap analysis

The primary metric: inter-packet gaps in one direction, from the host capture, sliced to the stress window. With a 10ms transmit interval and RFC jitter, healthy spacing is 7.5-10ms; the detect budget is 30ms.

```
S=<window start epoch>; E=<window end epoch>
tshark -r <file>.pcap -Y "ip.src==<dut-ip> && udp.dstport==3784" \
  -T fields -e frame.time_epoch \
  | awk -v s=$S -v e=$E 'NR>1 && $1>=s && $1<=e {printf "%.3f\n",($1-p)*1000} {p=$1}' \
  | sort -n \
  | awk '{a[NR]=$1} END{printf "n=%d p50=%.2f p99=%.2f p999=%.2f max=%.2f ms\n", \
      NR,a[int(NR*.5)],a[int(NR*.99)],a[int(NR*.999)],a[NR]}'
```

Report the full tail (p99, p999, max), not just p99. The central finding of the baseline is that p99 stays healthy while max exceeds the detect budget by 25-30x; averages and mid percentiles hide exactly the events that kill sessions. benchmarks/charts/make_chart.py builds the survival-function plot from files of these gaps.

## 5. Building and running xdp-bfd

```
sudo apt install -y clang llvm libbpf-dev bpftool make gcc
make            # builds bfd_xdp.o and the loader
make bfd_tx     # builds the daemon
```

If clang fails on asm/types.h, the Makefile's `-I/usr/include/x86_64-linux-gnu` handles it; adjust for other architectures.

Standalone mode (no FRR on the DUT; stop it first, port 3784 must be free):

```
sudo systemctl stop frr
sudo ./bfd_tx <local-ip> <peer-ip>                       # pure userspace TX
sudo ./bfd_tx <local-ip> <peer-ip> --kernel-tx <test-if> # XDP RX-clocked TX
```

The far end runs stock FRR bfdd as configured in section 2. Expect the handshake transitions in the log, then in kernel-tx mode near-silence: XDP consumes and answers the peer's packets, so userspace has nothing to say while the session is Up. The session's health is visible on the peer and on the wire, not in the daemon's stdout.

Verify native XDP attach: `ip link show <test-if>` must say `xdp`, not `xdpgeneric`. Generic mode means the driver refused (check multiqueue) and the numbers will not represent the driver fast path.

Rerun the ladder from section 3 against each mode. For the L4 comparison in the writeup, the interesting variants are: plain, plain under `chrt -f 90 taskset -c <core>`, and --kernel-tx with no privileges at all.

Two failure detections to exercise deliberately:

```
# true peer death: on the peer
sudo systemctl stop frr    # expect DETECT TIMEOUT ~30-35ms in the DUT log
sleep 10 && sudo systemctl start frr   # expect autonomous re-establishment
```

Watch systemd's start rate limit if cycling fast (`systemctl reset-failed frr` clears it).

## 6. FRR integration (distributed BFD)

bfdd hands session lifecycle to the engine over its bfddp socket. No FRR patches.

On the DUT, /etc/frr/daemons:

```
bfdd_options="  --daemon -A 127.0.0.1 --dplaneaddr ipv4c:127.0.0.1:50700"
```

Transport note: use TCP (`ipv4c:`). The unix transport (`unixc:`) fails with EINVAL on FRR <= 10.5.x due to an oversized connect address length; reported as FRRouting/frr#22608 and fixed in #22621, so builds from master after that merge can use `unixc:` as well.

Start order matters: engine first (it listens), then FRR (bfdd connects out):

```
sudo ./bfd_tx --dplane 50700 --kernel-tx <test-if>
# other terminal:
sudo systemctl restart frr
```

Expected in the engine log: bfdd connected, ADD session with the timers from frr.conf (possibly via an ADD at defaults followed by UPDATEs as config applies), then the handshake and Up. Verify from FRR itself:

```
sudo vtysh -c "show bfd peers"           # Status: up, discriminators sane
sudo vtysh -c "show bfd peers counters"  # input climbing ~100/s at 10ms timers
```

Both counters are read from the XDP session map; kernel-path XDP_TX replies are counted per-packet (added in m5-hardening), so the output count tracks the echoed replies, not just userspace-sent handshake and slow-rate packets.

Lifecycle checks worth running: restart FRR twice in a row (sessions must tear down on disconnect and re-establish with fresh discriminators on reconnect), then rerun L4 and confirm `show bfd peers` uptime spans the stress window untouched.

Graceful restart (`--dp-hold`): start the engine with `--dp-hold 30` and
restart FRR twice. Instead of teardown, the engine holds each session
live and re-adopts it on reconnect (log: `holding N session(s)` then
`adopts live session`). The wire proves it: slice the peer's transmitted
state to the restart window and expect zero transitions. Default
(`--dp-hold 0`) keeps the drop-and-recreate behavior above. Watch the
systemd start-rate limit when cycling fast: `systemctl reset-failed frr`
between restarts, or the second start is refused and the session
genuinely drops.

Hardening harnesses (milestones/05-abi-refactor): three standalone injection
scripts reproduce the review-pass verifications against a live session.
`spoof_options.py` (run on the peer or chaos host) injects 200 optioned
packets with valid discriminators; expect the loader's `rej` counter
(stats idx 3) to climb by exactly 200 with no uptime reset.
`spoof_long.py` injects one 76-byte control packet; expect the echo back
on the wire at 66 bytes with a valid checksum. `bad_frame.py` connects
to the dplane listener as a fake bfdd and sends an invalid-length
header; expect "bad frame length ... dropping connection" in the engine
log and an orderly close on the harness socket.

## 7. Authentication (RFC 5880 s6.7)

Two things have to be true before any of this works, and neither is
obvious from a failing session.

**bfdd needs the key extension.** Stock `bfddp_session_msg` has no field
for a key — upstream it is a `/* TODO: missing authentication. */` — and
no guard either, so stock bfdd offloads an authenticated session and then
transmits it in the clear while `show bfd peer` reports authentication
enabled. The engine fails closed against that and the session simply
never comes up. Build bfdd from `bfddp-auth-lifetimes` on the fork, which
adds a `DP_SESSION_AUTH` message carrying every key in the chain with its
send and accept periods.

**The peer needs three merged-or-pending bfdd fixes** for the restart
cases to behave: FRRouting/frr#23281 (sequence window), #23282 (a
keychain with no usable key), #23284 (`your_disc == 0` tested against the
packet's State field). Everything in milestones/10-auth was measured
against a peer carrying all three.

Configure the key chain on both ends. The algorithm is the trap:

```
key chain bfdkeys
 key 1
  key-string sixteenbytekey01
  cryptographic-algorithm hmac-sha-1
 !
!
bfd
 peer 10.66.0.24
  key-chain bfdkeys
 !
!
```

`cryptographic-algorithm` is not optional in practice. A key defaults to
no algorithm and bfdd only selects one that is `cleartext` or
`hmac-sha-1`, so `key-string` alone leaves the session unauthenticated
while `show bfd peer` still reports authentication configured. That is a
quiet way to believe a link is protected, and it cost more time here than
anything else in the milestone.

Verify from the wire rather than from either daemon. Simple password is
auth type 1 and 35-byte packets; keyed SHA1 is type 4 and 52 bytes;
meticulous keyed SHA1 is type 5:

```
tshark -r cap.pcap -T fields -e ip.src -e bfd.auth.type -e bfd.auth.key \
                   -e bfd.auth.seq_num -e frame.len
```

Expect the sequence numbers to increase by exactly one per packet from
whatever seed userspace handed over, and the source port to be a per-slot
port (65472-65535), which is how you tell the fast path is signing rather
than userspace. On IPv6 also check `udp sum ok`: the payload is part of
the mandatory checksum, and getting the fold wrong there presents as a
flapping session with both authentication counters flat.

Engine counters, via `kill -USR1`:

- `auth-bad` — a digest, key id or sequence number that did not verify.
  Should be 0 in steady state; a non-zero value climbing against a flat
  `rx_pkts` on the same session is the signature of a stale receive
  window.
- `auth-mismatch` — the A bit and the session disagree. A small number at
  bring-up is the window between a session being added over bfddp and its
  keys arriving in the following message; it should stop climbing.

For a rollover, give the chain two keys with adjacent lifetimes and let
the clock run. The `accept` period of the outgoing key must outlast the
`send` period, or packets already in flight are refused at the handover:

```
 key 2
  key-string sixteenbytekey02
  cryptographic-algorithm hmac-sha-1
  send-lifetime 10:00:00 Jan 1 2026 11:00:00 Jan 1 2026
  accept-lifetime 10:00:00 Jan 1 2026 11:05:00 Jan 1 2026
```

Expect the key id on the wire to change with no state change and no gap
larger than the session interval. `milestones/10-auth/keyroll.pcap.gz` is
one such handover across 329 seconds.

Do not expect a demanding session to notice a key change at all. Neither
side transmits, so neither receives anything to reject, and detection is
held on both. Pair demand with echo if the session needs to notice
anything.

The flap matrix is driven by `milestones/10-auth/eventA.sh` and
`eventB.sh`, which capture on the hypervisor bridge and snapshot both
ends either side of the restart. `timeline.sh` turns either capture into
a per-session state timeline.

## 8. Pitfalls encountered, so you skip them

- Heredocs with tab-indented content get mangled by interactive bash (tab completion fires mid-paste). Use `sh`, or files, for multi-line pastes.
- vtysh changes are live but volatile: `write memory` before any restart.
- If you experiment with SO_TXTIME/etf: the etf qdisc drops every untimestamped packet on its band, including ARP. Never install it as the root qdisc on all queues; steer only the timestamped flow into it with a tc filter, and delete the qdisc when done. Also delete it before running any non-txtime sender on that port, or your handshake packets silently vanish.
- Daemon stdout through a pipe is block-buffered and dies unflushed on Ctrl-C; bfd_tx line-buffers for this reason. If you add logging, do the same, and trust the pcap over the log regardless.
- Under RT starvation, a userspace daemon's RX view lies: queued socket-buffer packets drain in a burst and look like on-time arrivals. Only the peer and the wire know the truth.
- One XDP program per interface: stop the standalone loader before running bfd_tx --kernel-tx.
- On Ubuntu 26.04, the packaged tshark ships an AppArmor profile that
  denies reads under /home (dmesg shows `apparmor="DENIED" ...
  profile="tshark"`), so `tshark -r ~/some.pcap` fails even as root with
  a misleading "permission denied". Analyze from /tmp, or put the
  profile in complain mode: `sudo aa-complain /etc/apparmor.d/*tshark*`
  (needs the apparmor-utils package).
- VM caveat: relative comparisons between backends are valid (in-guest stress hits all of them identically, and the host capture is jitter-free), but treat absolute numbers as provisional until reproduced on bare metal.
