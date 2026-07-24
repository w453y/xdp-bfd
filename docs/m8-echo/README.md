# m8: echo mode

Adds the BFD echo function (RFC 5880 s6.4, UDP port 3785) to the
engine in two roles: a reflector that returns a neighbor's echoes from
XDP, and an originator/detector that sources its own echoes and clocks
liveness off the return. Both roles are pure engine work; neither requires FRR changes to ship.
The reflector (section 3) and the originator/detector (section 5) are
both implemented and validated; section 5 records what the
implementation changed relative to the spec, and what is still open. A separate, optional protocol track
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
2. Decrement IP TTL 255 -> 254 and recompute the IP header checksum.
   This is required: the originator validates the return at 254 (see
   the draft in section 5), and a reflection left at 255 is dropped by
   a conformant originator. The full 10-word recompute is used
   verbatim from the control-packet reply path (a proven-correct
   idiom) rather than an incremental fixup, deliberately avoiding a
   subtle miscompile hit elsewhere in the TX path.
3. Swap Ethernet source/destination so the frame returns to the
   originating MAC.
4. XDP_TX.

IP addresses are untouched (already self-addressed to the originator),
UDP is untouched, and the BFD payload is untouched (no UDP checksum
recompute, since nothing in L4 changed).

The reflector runs with ip_forward = 0: the engine returns the echo
without the box being a router and without traversing the kernel
forwarding path.

### Policy guard

Reflecting every UDP/3785 packet with TTL 255 would be a reflection
amplification vector and would answer echoes for sessions that never
enabled echo. The reflector therefore reflects only a *legitimate*
echo: one that is self-addressed (IP source == destination) and whose
source address is a peer of an echo-active session on this box.

Because a self-addressed echo carries {peer, peer} addresses, it
cannot be matched against the normal {local, peer} session key. A
dedicated map, echo_peers (peer address -> 1), holds the peers of
echo-active sessions; the userspace shim inserts a peer when it
accepts a SESSION_ECHO session and removes it on delete or echo-off.
The reflector does one lookup on the packet's source address before
reflecting; a miss is passed, not bounced. This is the only point
where the reflector touches session state.

### Status: implemented and validated (commit bb32980)

Built as a branch in the XDP RX parser ahead of the control-port
check, plus the echo_peers map and a dedicated reflected-echo counter
(bfd_stats slot 4). Validated on the wire in both directions with an
engine-free injector (docs/m8-echo/echo_inject.py, self-addressed
UDP/3785 to the DUT's MAC, nonce in the trailing payload word), DUT
ip_forward = 0 throughout:

- Allow (source in echo_peers): 5 injected, 5 reflected, every
  reflection TTL 254 with source MAC = DUT and the trailing nonce
  byte-identical; slot-4 counter +5.
- Block (source absent): 5 injected, 0 reflected; slot-4 counter flat.

Since ip_forward = 0, the kernel would drop each self-addressed echo
as a martian; that the frames return proves the XDP program, not the
stack, reflected them. Confirmed from two independent vantages: the
injecting host (bfd-chaos) receiving the reflections, and the Proxmox
bridge (vmbr3) seeing the DUT's MAC source the TTL-254 frames
(docs/m8-echo/echo-reflect-host.pcap).

Observability note: a reflection is an XDP_TX, which bounces below the
AF_PACKET hook, so tcpdump on the DUT itself sees neither the inbound
echo nor the reflection. The slot-4 counter (bpftool map dump name
bfd_stats) is the on-box signal; a far-end or bridge capture is the
off-box one. tcpdump on the reflecting host is not a valid check.


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


### Status: implemented (commits cfb1400, d0958d9)

Built in four stages, each validated on the wire before the next.

Peer MAC learning. Echo TX needs an L2 destination and must not depend
on the neighbour table, so the XDP RX path records the source MAC into
the session map on every control packet and userspace reads it there.

TX. A normal UDP socket cannot send a self-addressed packet: the
destination is our own address, so the kernel routes it to loopback and
it never reaches the wire. Echo TX therefore uses AF_PACKET SOCK_RAW
with a hand-built Ethernet header. Frames carry tos 0xc0, ttl 255, UDP
3785/3785, and a 24-byte payload whose trailing word is a monotonic
nonce. The UDP checksum tracks the nonce, which confirms it is computed
over the payload rather than left stale.

Demux on return. The spec above proposed demuxing by source IP and UDP
source port. That does not work: the returning echo is still
self-addressed to our own local address, which cannot name a session,
and several sessions may share one local address. The implementation
demuxes on the discriminator written into the payload, through a
my_disc to session-key map populated at first transmit.

GTSM interaction. The v4 parser drops anything that is not ttl 255
before the echo branch is reached, so returns at ttl 254 were being
discarded at the parser. The check is now widened narrowly, admitting
only dest 3785 with ttl 254 and source equal to destination, so it
cannot become a general TTL bypass. Returns are consumed with XDP_DROP:
they are ours, and the stack has no use for a martian.

Measured against a kernel-forwarding neighbour, with the DUT at
ip_forward = 0 throughout:

- The loop closes 1:1. Every echo returns with ttl 254, MACs swapped,
  payload byte-identical, nonce matching per pair.
- 300 sent, 299 returned, 0 lost. The one-packet gap is the echo still
  outstanding.
- RTT last/min/avg/max 72/54/71/133 us.

RTT vantage, and this matters for reading the number. It is measured
from the sendto call to the XDP arrival timestamp, so it includes our
own syscall and driver transmit path. The same echoes measured
wire-to-wire on the bridge were 23 to 34 us. The roughly 30 us
difference is our transmit stack, not path latency. These figures must
not be compared against the section 4 kernel baseline of 31/43/102 us,
which is a different vantage; doing so reads as a regression that does
not exist. The engine-relative number is the correct one for detection,
because it is what the engine actually experiences.

### Detection is advisory, and why

The sweep marks each echo-active session alive or not from the time
since the last return against detect-multiplier times the echo
interval, and reports it. It does not feed the session state machine.

The reason is the transmit path. With echo sent from userspace, a local
scheduling stall produces the same signature as a path failure: echoes
stop leaving, returns stop arriving, the last-seen timestamp goes
stale. A kernel timeout cannot separate those, so wiring it into the
state machine would turn our own scheduling delay into a session
teardown, which is exactly what this engine exists to avoid.

Counting misses per outstanding echo rather than per elapsed time would
fix that, but the send timestamp has nowhere clean to live: the session
map is kernel-owned and a userspace read-modify-write would race the RX
updates arriving at roughly 100/sec, and a per-send stamp in the TX
config map would defeat its dirty-check. Detection therefore stays
advisory until transmit moves into the kernel.

Verified both ways. With the neighbour forwarding, echo-alive reads 1
and loss stays 0. With forwarding disabled on the neighbour, returns
stop, loss climbs 1:1 with transmits, echo-alive flips to 0, and all 64
control sessions stay up. Echo coverage is lost, the session is not.

### Echo TX stays in userspace: decision and rationale

XDP cannot originate packets. XDP_TX is a verdict on a frame that just
arrived, which is why the control path is RX-clocked, and an echo has
no inbound packet to clock off. XDP's redirect helpers forward the same
packet rather than produce a copy, and while XDP has timers, a timer
callback has no packet context and cannot transmit.

The kernel-side alternative is bpf_clone_redirect, which exists only
for sched_cls, sched_act and lwt_xmit. But TC has nothing to clone at
the echo cadence: control packets are XDP_TX'd, which bypasses TC in
both directions, and returning echoes are consumed with XDP_DROP. A TC
echo hook would therefore require moving the control bounce itself out
of XDP and into TC, putting skb allocation into the hot path and
rewriting the RX-clocked mechanism that is this engine's central
result.

That trade is not worth making. It spends the engine's main advantage
on a secondary feature whose detection is advisory in any case, and
control-plane liveness is already detected in the kernel and already
survives userspace stalls.

The division of labour is therefore deliberate. The reflector is the
production capability: kernel-side, stall-immune, and able to return a
neighbour's echoes with ip_forward = 0, which the host stack cannot do
at all. The originator is a diagnostic, measuring round-trip time and
verifying the forwarding path, and it is best-effort by construction.
Advisory detection is permanent by design, not a placeholder.

The measured transmit gap is the honest limit of the userspace path and
is recorded here rather than hidden: idle inter-send gap is 13 ms
against a 10 ms interval, already 30 per cent over budget with no load,
and under the CPU ladder it reaches 2.6 seconds. Anyone reading echo
RTT or echo liveness should treat both as best-effort under load.

Two counters missed those stalls entirely, which is worth recording.
The loss counter only increments when a previous echo is still
outstanding as the next falls due, and during a total stall nothing
ever falls due. The echo-alive figure is printed on transmit, and
transmit is what stops. Instrumentation driven by the thing being
measured cannot observe that thing failing; the windowed gap counter
exists for exactly this reason.

If authoritative echo detection is ever required, the path is AF_XDP
with a dedicated thread, or hardware offload. It is not TC.

### Not yet quantified

The cost of these changes at 64 sessions is not established. The
testbed's run-to-run flap count at that scale varies by more than the
effect being measured: the m7 reference build itself ranged from 0 to
20 flaps across runs of identical code under the same ladder. No
comparison drawn from that metric is meaningful. Reopening this needs
either several runs per arm or a continuous metric such as the
per-session maximum transmit gap distribution.


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

m8b (originator/detector), as run:
- Enable echo on one session against a kernel-forwarding neighbour.
  Confirm on a host capture that outbound frames are self-addressed
  with ttl 255 and a per-frame nonce, and that returns arrive at ttl
  254 with the payload unchanged.
- Confirm the engine accounts for them: returns counted, nonce matched,
  RTT and loss reported per session.
- Break the loop by disabling forwarding on the neighbour. Returns must
  stop, loss must climb 1:1 with transmits, echo-alive must flip to 0,
  and every control session must stay up.
- Report echo RTT with its vantage stated. It is sendto to XDP arrival,
  not wire-to-wire, and is not comparable to the section 4 baseline.
- Not covered: the cost of the m8b changes at the 64-session cap. See
  the note at the end of section 5.

All loss and RTT numbers are taken from host-side captures on vmbr3,
never from vtysh status.

