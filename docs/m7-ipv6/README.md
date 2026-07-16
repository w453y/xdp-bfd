# m7: IPv6 support

## Step 1: ABI key widening (this commit)

session_key widened from 2x __be32 to 2x 16-byte bfd_addr; v4 encoded
v4-mapped (::ffff:a.b.c.d) so v4/v6 keys cannot collide. Both hash maps
(bfd_sessions, tx_config) move to the 32-byte key; XDP RX and the
userspace shim share the key_set_v4() encoder in bfd_shared.h. No v6
code yet: this commit is the v4 regression proof for the layout change.

## Evidence: abi-regress-v4.pcap

Single 300ms session, DUT (10.66.0.1) <-> stock FRR bfdd 10.5.1 peer
(10.66.0.2), created via bfddp dplane. Long Down span at capture start
is environmental (peer had no matching session configured while the
port issue below was debugged); Init arrives 14:34:43, Up follows.
Verified during the run:

- bpftool map dump: keys carry ff:ff at bytes 10-11, v4 at 12-15,
  identical layout from both writers (XDP RX path and userspace shim)
- rx_pkts/tx_pkts climb in lockstep (RX-clocked ktx intact)
- FRR counters match map counters (input == rx_pkts; output ==
  userspace slow-rate backlog + ktx)
- Up-phase DUT-side inter-packet gaps: n=10348 p50=264ms p99=300ms
  max=300.6ms; DUT TX count tracks peer TX one-for-one (10348 vs
  10349), the RX-clocked signature through the new key

## Environmental findings (not code bugs, recorded for reuse)

- TCP self-connect: bfdd's dplane client retrying against a missing
  listener can self-connect 127.0.0.1:50700 (port is in the ephemeral
  range), permanently stealing the port from the engine; SO_REUSEADDR
  does not recover it. Fixed with net.ipv4.ip_local_reserved_ports =
  50700 (sysctl.d/90-bfd-dplane.conf).
- Orphaned daemons from a /opt/frr-master build were holding the
  dplane socket alongside the packaged FRR; both sets must be swept
  before mode_b.sh.

## Step 2: XDP v6 parse (this commit)

bfd_xdp.c parse path branches on ethertype. v6: fixed 40-byte ipv6hdr,
non-UDP first header PASSes to the stack (ICMPv6 ND/MLD/RA must survive;
mirrors the v4 non-UDP PASS, and extension-header-hidden UDP is not
walked), hop_limit != 255 dropped (GTSM), key filled native via
key_set_v6(). Shared UDP/BFD validation and the tx_config gate follow
unchanged. Kernel XDP_TX reply stays v4-only (gated on iph != NULL): the
v6 reply needs a mandatory UDP checksum recompute, deferred to a later
step; v6 sessions get RX tracking and kernel detect, TX from userspace.

Verified standalone (XDP attached, no engine): spoofed v6 frames from
bfd-chaos, hop_limit 255 parsed and PASSed at the config gate, hop_limit
64 dropped in GTSM (stats[3] +5 per 5-packet burst), hop-by-hop frames
PASSed (ND preserved). v4 regression: session Up under FRR dplane, rx/tx
lockstep intact through the reordered parse.

## Step 3: userspace v6 path (this commit)

bfd_tx.c: session struct carries 16-byte addrs (v4 stored v4-mapped) +
family; shim accepts SESSION_IPV6 (sm_addrs() decodes both layouts);
slot sockets family-typed (AF_INET6 binds local+65472+slot,
IPV6_UNICAST_HOPS 255); v6 RX socket on [::]:3784 with IPV6_V6ONLY,
IPV6_RECVPKTINFO, IPV6_MINHOPCOUNT 255, drained nonblocking in the main
loop; demux compares full 16-byte pairs.

Interim TX architecture: v4 = full RX-clocked kernel TX; v6 = kernel RX
tracking + kernel detect, TX from userspace at normal RFC 5880 pacing
(tx_cfg.enable never set for v6, and the ktx silence gate exempts v6).
First cut of this gating flapped at exactly the 3x300ms detect budget:
userspace went silent in Up while the kernel reply was disabled, wire
showed peer-only traffic. The fix is this commit's explicit v6
exemption in both gates.

## Evidence: v6-userspace-tx.pcap

v4 + v6 sessions concurrent, both Up, 90s window, four flows balanced
(335-340 pkts each). v6 map entry keyed native (fd66::), rx_pkts
climbing with tx_pkts pinned at 0 (kernel reply off); v4 entry
v4-mapped with rx/tx lockstep. v6 userspace TX gaps: n=334 p50=267ms
p99=300.4ms max=302ms. Our TX from slot port 65473, accepted by stock
bfdd GTSM (hop limit 255).

Note: "bad udp cksum" on locally-originated packets in host captures is
virtio checksum offload (filled after the tap), not corruption.

## Baseline: v6 userspace TX vs v4 kernel TX under the stress ladder

Captured BEFORE the v6 kernel reply exists, deliberately: this is the
number step 4 has to beat, measured with both sessions live on the same
engine during one run of the bench-1 ladder (L3 timer storm 120s, L4
SCHED_FIFO prio-50 60s; 300ms timers, 900ms budget).

    L3: 0 flaps, both families.
    L4: v4 (kernel RX-clocked TX)  0 flaps, TX p50=261ms max=300.7ms
        v6 (userspace-paced TX)   19 flaps, TX p50=262ms p99=1199ms
                                  max=1900ms

The v6 p50 stays healthy between starvation events; the tail is the RT
throttle's ~950ms/s starvation pattern exceeding the 900ms budget, one
flap per ~3s cycle, each recovering autonomously in ~3ms. Same
conclusion as the m3 bake-off, now measured in-band against the kernel
path on the same box at the same instant. pcap:
v6-L34-baseline.pcap (peer wire transitions: 39 non-Up frames from
fd66::2, 0 from 10.66.0.2).

## Step 4: v6 kernel XDP_TX reply (this commit)

The reply path is family-branched: L2 swap shared; L3 swap per family
(checksum-neutral both); v4 keeps udp->check = 0 and the IP-checksum
trim recompute; v6 gets a full UDP checksum recompute - pseudo-header
(swapped addrs, length, nexthdr) + UDP header + the fixed 24-byte
payload, a 34-word fold, with the RFC 768 0 -> 0xffff rule. The fold
runs before bpf_xdp_adjust_tail (which invalidates packet pointers);
it never reads past payload byte 24, all of which survives the trim.
v6 trim patches ipv6hdr.payload_len (no IP checksum exists).

Validated in two stages. 4a, both TX paths live concurrently: host
tcpdump showed alternating frames - kernel echoes [udp sum ok]
(peer's flowlabel preserved, frame rewritten in place) interleaved
with userspace slot-socket frames (virtio offload artifact). Every
kernel-echoed frame validates. 4b, userspace pacing exemption removed:
all steady-state v6 TX is kernel echo, all checksums valid.

## Ladder rerun vs baseline (v6-L34-ktx.pcap)

Same L3+L4 ladder, 300ms timers, both sessions live:

                        v6 flaps   v6 TX p99   v6 TX max   v4 flaps
    userspace TX          19        1199ms      1900ms        0
    kernel reply (now)     0         300ms       300.5ms      0

Engine silent through both stages; wire transitions 0/0; v6 is now
indistinguishable from v4 under RT starvation. The 19-flaps-per-minute
cost of userspace TX at 300ms timers is exactly what the kernel reply
eliminates.
