# m7: IPv6 support

Extends the engine from IPv4-only to dual-stack. v4 and v6 sessions
share one hash map, one slot-socket pool, and the same XDP fast path;
v6 is encoded natively and v4 is stored v4-mapped (::ffff:a.b.c.d) so
the two families cannot collide on a key. The work landed in five
steps, each with a v4 regression check so the shared code never
regressed the working v4 path.


## 1. ABI: unified session key

session_key widened from two __be32 fields to two 16-byte bfd_addr
fields. v4 addresses are stored v4-mapped, so v4 and v6 keys are
unambiguous in one map. Both hash maps (bfd_sessions, tx_config) move
to the 32-byte key, and the XDP RX path and the userspace shim share a
single key_set_v4() encoder in bfd_shared.h. No v6 code in this step —
it is purely the layout change, proven not to disturb v4.

Evidence: abi-regress-v4.pcap. A single 300ms session, DUT
(10.66.0.1) against a stock FRR bfdd 10.5.1 peer (10.66.0.2), created
over the bfddp dplane. The long Down span at the start of the capture
is environmental (the peer had no matching session while the port
issue below was being debugged); Init arrives at 14:34:43 and Up
follows. Verified during the run:

- bpftool map dump shows keys carrying ff:ff at bytes 10-11 and the v4
  address at 12-15, identical from both writers (XDP RX and the shim).
- rx_pkts and tx_pkts climb in lockstep (RX-clocked kernel TX intact).
- FRR counters match the map counters (input == rx_pkts; output ==
  userspace slow-rate backlog + kernel TX).
- Up-phase DUT-side inter-packet gaps: n=10348, p50=264ms, p99=300ms,
  max=300.6ms; DUT TX tracks peer TX one-for-one (10348 vs 10349),
  the RX-clocked signature preserved through the new key.


## 2. XDP v6 parse

The parse path in bfd_xdp.c branches on ethertype. The v6 branch
reads a fixed 40-byte ipv6hdr, drops hop_limit != 255 (GTSM), and
fills the key natively via key_set_v6(). A non-UDP first header is
PASSed to the stack rather than dropped: ICMPv6 (ND, MLD, RA) must
survive, and this mirrors the v4 non-UDP PASS. Extension-header-hidden
UDP is deliberately not walked. Shared UDP/BFD validation and the
tx_config gate follow unchanged. The kernel XDP_TX reply stays v4-only
at this stage (gated on iph != NULL); v6 sessions get RX tracking and
kernel detect, with TX from userspace, until step 4 adds the v6 reply.

Verified standalone with the XDP program attached and no engine
running: spoofed v6 frames from a third host, hop_limit 255 parsed and
PASSed at the config gate, hop_limit 64 dropped in GTSM (stats[3] +5
per 5-packet burst), hop-by-hop extension frames PASSed so ND is
preserved. v4 regression: session Up under the FRR dplane, rx/tx
lockstep intact through the reordered parse.


## 3. Userspace v6 path

bfd_tx.c gains dual-stack plumbing. The session struct carries 16-byte
addresses (v4 stored v4-mapped) plus a family field; the shim accepts
SESSION_IPV6 and sm_addrs() decodes both wire layouts; slot sockets
are family-typed (AF_INET6 binds local:65472+slot with
IPV6_UNICAST_HOPS 255); a v6 RX socket on [::]:3784 sets IPV6_V6ONLY,
IPV6_RECVPKTINFO and IPV6_MINHOPCOUNT 255 and is drained nonblocking
in the main loop; demux compares full 16-byte address pairs.

Interim TX split at this stage: v4 uses full RX-clocked kernel TX; v6
uses kernel RX tracking and kernel detect but transmits from userspace
at normal RFC 5880 pacing (tx_cfg.enable is never set for v6, and the
kernel-TX silence gate exempts v6). The first cut of this gating
flapped at exactly the 3x300ms detect budget: userspace went silent in
Up while the kernel reply was disabled, and the wire showed peer-only
traffic. Fixed with an explicit v6 exemption in both gates.

Evidence: v6-userspace-tx.pcap. v4 and v6 sessions concurrent, both
Up, 90s window, four flows balanced (335-340 packets each). The v6 map
entry is keyed natively (fd66::) with rx_pkts climbing and tx_pkts
pinned at 0 (kernel reply off); the v4 entry is v4-mapped with rx/tx
lockstep. v6 userspace TX gaps: n=334, p50=267ms, p99=300.4ms,
max=302ms. TX leaves from slot port 65473 and is accepted by the stock
bfdd GTSM (hop limit 255).

Note: a "bad udp cksum" on locally-originated packets in host captures
is virtio checksum offload (filled in after the capture tap), not
corruption.


## 4. v6 kernel XDP_TX reply

The reply path becomes family-branched. The L2 swap is shared; the L3
swap is per-family (checksum-neutral either way). v4 keeps udp->check
= 0 and the IP-checksum trim recompute. v6 gets a full UDP checksum
recompute — pseudo-header (swapped addresses, length, nexthdr) plus
UDP header plus the fixed 24-byte payload — as a 34-word fold, with the
RFC 768 zero-to-0xffff rule. The fold runs before bpf_xdp_adjust_tail
(which invalidates packet pointers) and never reads past payload byte
24, all of which survives the trim; the v6 trim patches
ipv6hdr.payload_len, since there is no IP checksum.

Validated in two stages. In 4a both TX paths ran concurrently: host
tcpdump showed alternating frames — kernel echoes ([udp sum ok], the
peer's flowlabel preserved because the frame is rewritten in place)
interleaved with userspace slot-socket frames (the virtio offload
artifact). Every kernel-echoed frame validated. In 4b the userspace
pacing exemption was removed, so all steady-state v6 TX is kernel echo,
and all checksums validate.

### Baseline: v6 userspace TX vs v4 kernel TX under the ladder

Captured deliberately before the v6 kernel reply existed — the number
step 4 had to beat, measured with both sessions live on one engine
during a single run of the bench-1 ladder (L3 timer storm 120s, L4
SCHED_FIFO prio-50 60s; 300ms timers, 900ms budget). pcap:
v6-L34-baseline.pcap.

    L3: 0 flaps, both families.
    L4: v4 (kernel RX-clocked TX)  0 flaps, p50=261ms  max=300.7ms
        v6 (userspace-paced TX)   19 flaps, p50=262ms  p99=1199ms
                                            max=1900ms

The v6 p50 stays healthy between starvation events; the tail is the RT
throttle's ~950ms/s starvation exceeding the 900ms budget, one flap per
~3s cycle, each recovering autonomously in ~3ms. Same conclusion as the
m3 bake-off, now measured in-band against the kernel path on the same
box at the same instant (peer wire transitions: 39 non-Up frames from
fd66::2, 0 from 10.66.0.2).

### Ladder rerun with the kernel reply

Same ladder, 300ms timers, both sessions live. pcap: v6-L34-ktx.pcap.

                        v6 flaps   v6 TX p99   v6 TX max   v4 flaps
    userspace TX          19        1199ms      1900ms        0
    kernel reply           0         300ms       300.5ms       0

The engine log is silent through both stages and wire transitions are
0/0. v6 is now indistinguishable from v4 under RT starvation — the
19-flaps-per-minute cost of userspace TX at 300ms timers is exactly
what the kernel reply eliminates.


## 5. v6 security / validation regression

v6 variants of the m5 spoof harness (spoof6.py), injected from a third
host forging source fd66::2. Counts are stats[3] deltas: XDP_DROP is
invisible to tcpdump (XDP consumes the frame before the tc/AF_PACKET
hook), so bpftool stats are the only trustworthy signal.

    wrong your_disc, hlim 255   -> +100  demux reject (RFC 5880 6.8.6)
    correct your_disc, hlim 64  -> +100  GTSM reject (hop_limit != 255)
    correct your_disc, hlim 255 -> +0    passes, reaches session
    oversized (40-byte payload) -> echo trimmed to 24, udp sum ok,
                                    payload_len patched, adjust_tail ok

The oversized case is the only previously-untested v6 path: a valid
frame with 16 trailing bytes is echoed back at exactly 24 BFD bytes
with a recomputed valid checksum (payload length 32 on the wire),
confirming the fold-before-adjust_tail ordering against real traffic.

Testbed notes:

- The target your_disc must be read from a BFD capture (the peer's
  Your Discriminator, or the DUT's own My Discriminator in a DUT-TX
  capture) and copied exactly. A single mistyped hex digit fails demux
  and is indistinguishable from a correct rejection — verify against
  the wire, do not hand-transcribe from log output.
- vmbr3 forwards forged-source unicast v6 tap-to-tap, but the bridge
  master does not see it (learned unicast is not flooded up to the
  master), so confirm injection via DUT-side stats, not a vmbr3
  capture. Delivery itself works (the hlim-64 case counts exactly).


## Environmental findings (not code bugs, recorded for reuse)

- Scale-mesh provisioning: persist the peer mesh with `write memory`
  immediately after building it — unpersisted vtysh config evaporates
  on any frr/bfdd restart. Provision v6 addresses with `printf %x`,
  not decimal, or the local addresses the engine binds will not exist
  on the interface (EADDRNOTAVAIL on slot bind). tcpdump v6 prefix
  match needs `ip6 and src net fd66::/16`.

- TCP self-connect: the bfdd dplane client retrying against a missing
  listener can self-connect 127.0.0.1:50700 (the port is in the
  ephemeral range), permanently stealing the port from the engine;
  SO_REUSEADDR does not recover it. Fixed by reserving the port:
  net.ipv4.ip_local_reserved_ports = 50700 (sysctl.d/90-bfd-dplane.conf).
  Do NOT also reserve the slot range 65472-65535 — reserved_ports
  blocks explicit bind() as well as ephemeral assignment, so the engine
  could not bind its own slots.
- Orphaned daemons from a /opt/frr-master build can hold the dplane
  socket alongside the packaged FRR; sweep both sets before mode_b.sh.


## Patched bfdd (master + #22645) against the mixed-family mesh

The 32 v4 + 32 v6 mesh re-run against FRR master carrying the merged
burst-truncation fix
([FRRouting/frr#22645](https://github.com/FRRouting/frr/pull/22645)),
run as the whole /opt/frr-master stack against its own libfrr
(daemons file created in /opt/frr-master/etc/frr with the dplane
args; packaged frr stopped and disabled first).

Registration: fixed. Both the initial connect and a bfdd restart
delivered all 64 registrations (32 native-v6 + 32 v4 keys). bfdd
counters after the cycle: Output full events 0, Output bytes peak
8120 — the buffer filled to the old failure line and was flushed
through. Under packaged 10.5.1 the same mesh delivered ~40 and tore
down 6 on re-add; that behavior is gone.

New upstream finding from the same runs: shutdown DELETEs truncate
at the output buffer. Master bfdd (unlike 10.5.1 in practice) tears
down its dataplane sessions on clean shutdown, one DP_DELETE_SESSION
per session. Exactly floor(8192/140) = 58 of 64 were delivered, the
6 remaining lost when bfd_dplane_ctx_free() frees the outbuf without
a final drain (the #22645 flush only fires on enqueue; nothing
enqueues after the burst and the event loop never runs again). Wire
cost of a clean restart: 58 non-Up transitions (28 v4 + 30 v6); the
6 sessions whose DELETEs were lost rode --dp-hold and were adopted.
A SIGKILL of bfdd sends nothing and is fully hitless: 0 DELETEs, 64
held, 64 adopted, 0 wire transitions. Root cause confirmed three
ways: engine log (58 DELETE + holding 6), byte-counting sink
(patched: ADD=64 DELETE=58; packaged 10.5.1: ADD=58 DELETE=0 —
reconfirming #22638 and showing 10.5.1 loses the entire shutdown
burst, which is why earlier restarts under it were hitless), and
host tcpdump. Reported upstream as
[FRRouting/frr#22691](https://github.com/FRRouting/frr/issues/22691);
fix submitted as
[FRRouting/frr#22692](https://github.com/FRRouting/frr/pull/22692)
(synchronous drain in bfd_dplane_ctx_free before socket_close on the
shutdown path), validated here: sink 64/64 and 128/128 DELETEs on
clean stop, end-to-end restart delivering all 64 with zero orphans.

Operational note: with master bfdd a clean FRR restart is no longer
hitless under --dp-hold, because delivered DELETEs are honored as
teardowns. Sessions torn down and re-established across the cycle
tracked the delivered-DELETE set exactly.

## Mixed-family scale: 32 v4 + 32 v6 through the ladder

The full L3+L4 ladder at the 64-session cap, 3x10ms timers, both
families interleaved across the slot pool, control plane FRR master
carrying #22645. Steady-state capture started before the ladder; no
bfdd cycle mid-run. pcap: m7-scale-mixed-window.pcap.gz.

    L3 (timer storm, 120s):        0 flaps, both families
    L4 (SCHED_FIFO prio-50, 60s):  0 flaps, both families

All 64 sessions up with down-events 0 after each level; wire
transitions 0/0 per family across the 197s window (2.91M packets).
Per-slot max TX gaps sit in one band for both families — worst
overall 14.5ms (a v6 slot), worst v4 13.96ms, everything under half
the 30ms detect budget. The m6 v4-only baseline showed correlated
stall flaps at this N; the mixed-family run beats it, and v6 is
statistically indistinguishable from v4 under both stress levels.

During the ladder the dplane control channel dropped and reconnected
twice with zero wire impact (--dp-hold carried all 64 both times).
Root cause is a second new upstream bfdd bug, not the engine: `show
bfd peers counters` leaks input-buffer space in bfd_dplane_expect()
(the pulldown is gated on 3+ messages per call, but the synchronous
path consumes exactly one) and a full buffer is then misread as the
peer closing, so bfdd RSTs a healthy connection at a deterministic
reply ordinal — 64 + 39 = 103 replies per connection, in strict
alternation. Reported as
[FRRouting/frr#22693](https://github.com/FRRouting/frr/issues/22693);
fix submitted as
[FRRouting/frr#22694](https://github.com/FRRouting/frr/pull/22694),
validated here: 384/384 replies over six consecutive sweeps, zero
resets, coexisting with the #22692 drain on one build. The
engine-free reproducer (a TCP counters responder needing no dataplane
implementation) is dplane_counters_sink.py in this directory.

## Status

Done and committed (branch m7-abi-key): steps 1-5, each with v4
regression and wire evidence; patched-bfdd registration confirmation;
mixed-family scale ladder. Four upstream FRR bugs came out of this
milestone's validation: #22638 (fixed by #22645, merged), #22608
(fixed by #22621, merged), #22691 (fix #22692 in review), #22693
(fix #22694 in review). Nothing remains before merge to main.

