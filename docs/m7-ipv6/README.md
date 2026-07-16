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
