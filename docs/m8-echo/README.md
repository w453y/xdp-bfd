# m8: echo mode

Adds the BFD echo function (RFC 5880 s6.4, UDP port 3785) to the
engine in two roles: a reflector that returns a neighbor's echoes from
XDP, and an originator/detector that sources its own echoes and clocks
liveness off the return. Both roles are pure engine work; neither
requires FRR changes to ship. A separate, optional protocol track
(section 6) proposes carrying echo over the bffdp dplane protocol so
any dataplane, not just this engine, can be delegated echo by bfdd.

The milestone opens from wire evidence, not the RFC text: a known-good
packaged-FRR echo loop was captured and dissected first, and every
spec below is pinned to observed bytes. Reference captures:
echo-loop-reference.pcap (idle loop) and echo-stress.pcap (loop under
the L4 ladder).


## 1. What echo is, and why it is not already in the dplane

In echo mode a system emits a UDP/3785 packet addressed to itself and
handed at L2 to the neighbor; the neighbor's forwarding plane returns
it, and the originator measures the round trip. The neighbor's BFD
control plane never sees the packet. This tests the forwarding path to
the neighbor and back without involving the neighbor's software, which
is the entire point of echo and the reason it belongs in a dataplane
rather than a daemon.

BFD echo is not part of the bffdp dplane protocol. There is no echo
message type in bfdd/bffdp_packet.h, and bfdd/dplane.c has no echo
handling. bfdd sends and receives echo from its own sockets
(bfd_packet.c), with no dependence on whether the session is
distributed. So in distributed mode echo is orphaned: the control
plane is offloaded to the dataplane while echo stays in the daemon,
transmitting from a socket that has nothing to do with the offload
engine. (Note: the bffdp ECHO_REQUEST/ECHO_REPLY message types are the
dplane control-channel keepalive between bfdd and the dataplane, an
unrelated use of the word "echo".)

The engine already carries the echo fields through its ABI
(SESSION_ECHO, min_echo_rx, required_echo_rx, echo counters) but
currently rejects SESSION_ECHO at the shim and zeroes min_echo_rx in
the XDP TX path, i.e. it advertises "I cannot receive echoes" and
declines to participate. The scaffolding exists and is wired shut.


## 2. Wire evidence: the known-good loop

Two packaged FRR 10.5.1 nodes (10.66.0.2, 10.66.0.3) on the flat L2
segment, plain BFD session Up, echo-mode enabled both ends. With the
reflecting node's net.ipv4.ip_forward = 0 the loop never completes
(each side emits its own echoes, neither returns the other's; peer RTT
stays 0). With ip_forward = 1 on the reflector the loop closes and RTT
populates. That single fact defines the milestone: echo requires the
neighbor to forward a self-addressed transit packet back to its
origin, which a non-router host will not do.

One echo, decoded from echo-loop-reference.pcap:

- Outbound (originator .2 -> neighbor .3, Ethernet .2 -> .3):
  IP src = dst = 10.66.0.2 (self-addressed), tos 0xc0, ttl 255,
  UDP src = dst = 3785, valid UDP checksum, 24-byte BFD echo payload.
  My Discriminator set, Your Discriminator 0, trailing nonce.
- Return (neighbor .3 -> originator .2, Ethernet .3 -> .2):
  IP src = dst = 10.66.0.2 still, ttl 254, IP id unchanged from the
  outbound packet, BFD payload byte-identical. Only the Ethernet
  header and the TTL changed.

The unchanged IP id across the pair proves it is the same packet
forwarded, not a regenerated one. The neighbor's forwarding plane did
exactly three things: rewrote the Ethernet header to send it back,
decremented TTL 255 -> 254, and fixed the IP checksum. It did not
touch the BFD payload, so Your Discriminator is never looped in
classic echo and RTT matching is done on the nonce, not the
discriminator.


## 3. Reflector spec (m8a)

On XDP RX of a UDP/3785 packet whose destination IP is not a local
session address (it is the originator's own address, i.e. transit to
be reflected):

1. Validate minimally: it is echo-shaped and TTL is 255. A TTL other
   than 255 inbound is dropped (GTSM), matching the originator's
   expectation that the neighbor is one hop away.
2. Decrement IP TTL 255 -> 254 and apply the incremental IP header
   checksum fixup. This is required: the originator validates the
   return at 254 (see the draft in section 5), and a reflection left
   at 255 is dropped by a conformant originator.
3. Swap Ethernet source/destination so the frame returns to the
   originating MAC.
4. XDP_TX.

IP addresses are untouched (already self-addressed to the originator),
UDP is untouched, the BFD payload is untouched, and there is no UDP
checksum recompute because nothing in L4 changed. The only checksum
work is the one-word incremental IP fixup for the TTL decrement. This
is a smaller operation than the control-packet reply path, which does
address swaps and a UDP recompute; the reflector is the simplest TX
path in the engine.

The reflector runs with ip_forward = 0. The engine returns the echo
without the box being a router and without traversing the kernel
forwarding path.


## 4. Kernel-reflection baseline (the honest comparison basis)

Measured with the reflecting node (chaos) using kernel forwarding
(ip_forward = 1), from the wire on the originator, during the standard
L4 ladder (stress-ng --cpu 4 --sched fifo --sched-prio 50, 60s):

- Loss: 979 echoes out, 979 returned. Zero loss under stress.
- RTT (return_time - send_time, matched by IP id): n=979,
  min 31 us, median 43 us, max 102 us.

Kernel reflection is lossless and sub-150us even under RT starvation.
So m8a's argument is not performance and must not be written as such.
The argument is capability and isolation:

- A non-router host cannot reflect at all (ip_forward = 0 -> the
  self-addressed echo is a martian and is dropped; confirmed, RTT
  0/0/0 until forwarding is enabled). The XDP reflector returns echoes
  without enabling forwarding.
- Kernel reflection turns the box into an IP forwarder for all
  traffic, not just echo. The XDP reflector returns only echoes and
  exposes no forwarding.
- This is the mechanism a hardware BFD offload uses: reflect in the
  dataplane, never involve the host stack.

The m8a result is therefore RTT/loss parity with kernel forwarding
(the engine must not be worse), demonstrated with forwarding disabled.
Not a stress-resilience win over the kernel, which the data does not
support.

Measurement note: the vtysh "RTT min/avg/max" field is unreliable for
this: it holds the last echo's RTT and reads 0/0/0 when a 1 Hz poll
lands between updates, which looks like 50% loss but is not (the wire
shows zero loss). All echo loss and RTT numbers must come from the
wire, not from status output.


## 5. Originator / detector spec (m8b)

The engine sources its own echoes and detects liveness on the return,
making it a full echo participant rather than only a reflector.

- TX: emit a self-addressed UDP/3785 packet (IP src = dst = the
  session's local address, Ethernet dst = the neighbor's MAC, TTL 255,
  valid UDP checksum, My Discriminator set, Your Discriminator 0, a
  monotonic nonce for RTT matching) at the echo TX interval.
- RX / detect: on the returned echo, validate TTL 254 (per the
  unaffiliated-echo draft: 255 out, 254 in, else drop), match the
  nonce to compute RTT, and feed the arrival into the RX-clocked
  detection logic the engine already uses for control packets. Echo
  detection failure is a detect-multiplier x echo-interval timeout,
  handled by the same sweep.

Demux for the return follows RFC 5880 s6.3 as adapted by the draft:
until the neighbor loops the discriminator (which classic forwarding
never does), demux is by source IP / UDP source port; the nonce
disambiguates outstanding echoes for RTT.


## 6. Path 1 vs Path 2: one mechanism, two policy sources

The reflector and originator are the echo *mechanism*. What triggers
them for a given session is *policy*, and there are two sources. The
design keeps the mechanism single and lets either source drive it,
behind one internal trigger in the BPF session map:

    struct echo_cfg { __u8 enabled; __u32 tx_interval_us;
                      __u32 rx_interval_us; /* ... */ };

- Path 1 (engine-local, ships without upstream): the engine reads
  SESSION_ECHO and the echo intervals from the ADD it already
  receives, and populates echo_cfg itself. No FRR change. This is the
  m8 default.

- Path 2 (vendor-neutral protocol extension): a new bffdp message,
  e.g. DP_ECHO_SESSION carrying { lid, echo_enabled, echo_tx_interval,
  echo_rx_interval }, plus a bfdd patch to send it (and delegate echo)
  when the session is offloaded (bs->bdc set) instead of using bfdd's
  local echo socket. The engine's Path 2 handler parses that message
  and populates the same echo_cfg.

Path 2 is defined entirely at the protocol layer (bffdp_packet.h). The
engine's echo_cfg is a private implementation detail no other
dataplane ever sees. The correctness test for Path 2's independence:
could a different vendor implement their echo dataplane from
bffdp_packet.h and a short spec alone, without ever reading this
repo? If yes, it is properly vendor-neutral. The design rule that
enforces this: the DP_ECHO_SESSION message must carry everything a
dataplane with an empty session table needs to act, and must assume
nothing the engine happens to already track from the ADD.

Selection is a flag: --echo-mode auto uses Path 1 (engine decides from
session flags); --echo-mode dplane acts only on explicit delegation
(Path 2); auto is the fallback when talking to a bfdd without the
extension. Because both writers target echo_cfg, adding Path 2 later
touches only a new message handler, not the reflector, originator,
detection, or counters.


## 7. Upstream track (parallel, not a blocker)

Path 2 is a design question for the bffdp author before it is code:
distributed-BFD echo currently bypasses the dplane entirely, which
defeats the offload for echo-enabled sessions. The proposal to raise
on the mailing list is (a) a protocol extension (the DP_ECHO_SESSION
message, specified with no reference to this engine) and (b) a bfdd
patch to delegate echo to the dataplane when offloaded, with this
engine as the reference implementation demonstrating it end to end.
This runs in parallel with shipping Path 1 and does not gate it.

Not in scope for m8: SBFD echo (seamless BFD, simpler state machine,
same packet format) is a possible later extension.


## 8. Test plan

Topology: originator = packaged FRR on bfd-peer (real echo source,
measures RTT and drives its own echo detection); reflector = the DUT
engine. The known-good baseline is bfd-peer <-> bfd-chaos with chaos
forwarding in the kernel (section 4).

m8a (reflector):
- DUT reflects bfd-peer's echoes in XDP with ip_forward = 0.
- Pass: bfd-peer's echo loop completes (wire shows 1:1 out/return from
  the DUT), RTT parity with the kernel baseline (31/43/102us band),
  zero loss, and the return packets carry TTL 254 (the decrement
  applied). Confirm with ip_forward = 0 on the DUT throughout, i.e.
  the engine, not the kernel, is doing the reflection (bpftool TX
  counter climbs; kernel forwarding stat does not).
- Under the L3+L4 ladder on the DUT: reflection stays lossless and RTT
  stays bounded where kernel forwarding, being softirq-scheduled, is
  the thing the engine is meant to sidestep. Report parity or better;
  do not claim better than the section 4 numbers unless the wire shows
  it.

m8b (originator/detector):
- DUT originates echoes to a reflecting neighbor and detects on the
  return; a peer flap or path break trips echo detection at
  detect-mult x echo-interval.
- Pass: RTT populates from the nonce, detection fires on induced loss,
  and echo detection is independent of the control-packet path.

All loss and RTT numbers are taken from host-side captures on vmbr3,
never from vtysh status.

