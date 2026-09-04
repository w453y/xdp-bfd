# m5-hardening evidence

Session: symmetric 3x300ms via FRR dplane, kernel-tx on ens19.
Window (m5-window.txt): 1783722902 - 1783723031.
Peer FRR stopped mid-window, restarted, then both sides reverted to 10ms.

Wire results (host-side tcpdump on vmbr3), DUT Down-state transitions
with gap since peer's last packet, sliced to window:

    t=1783722941 detect gap=900 ms
    t=1783722983 detect gap=151 ms

t=941: peer kill. Detect at exactly 3x300ms configured budget. Verifies
per-session min_rx in the kernel sweep and live remote-timer sync in
userspace (pre-fix behavior on identical test: 3002ms, userspace stale
at FRR's 1s slow-start interval).

t=983: false detect during the 300ms -> 10ms revert. Timer
renegotiation race: detect budget shrinks on the peer's new advertised
min_tx before the peer actually paces at the new rate (RFC 5880 s6.8.3
keeps the old rate until Poll completes). Known bug, fix pending
(poll-sequence-aware detect).

Also characterized this session: asymmetric intervals (one side 300ms
rx, other at 10ms) flap-loop under RX-clocked TX by construction; the
echo rate is slaved to the peer's TX rate and cannot satisfy a faster
peer-side detect budget. RX-clocked TX requires symmetric intervals.

Analysis commands: same tshark/awk method as reproduction.md s3-4;
transition extraction filtered to ip.src of the DUT, gap measured from
the peer's last packet before each 0x01 transition.

## Correction to the m5 analysis above

Deeper pacing analysis (inter-arrival regime detection on bfd-m5-minrx
.pcap) shows the peer honored our advertised min_rx=300000 only at
session establishment, never mid-session: our engine changes advertised
timer fields silently, without an RFC 5880 s6.8.3 Poll sequence, so the
peer never re-evaluates. The t=983 false detect was our detect budget
collapsing against a peer that was slow-pacing due to establishment-
time clamping (post-restart), not poll semantics as stated above.

## m5b: invalid run (bfd-m5b-poll.pcap, m5b-window.txt)

Kept for the record. Advertisements changed on schedule but the peer
paced at 10ms throughout (session established at 10ms; mid-session
min_rx change ignored per the correction above). The slow regime never
existed on the wire, so this run exercises nothing. Lesson folded into
method: gate every timer test on wire-verified pacing, not config.

## m5c: valid verification (bfd-m5c-race.pcap, m5c-window.txt)

Window 1783747506 - 1783748015. Precondition wire-gated: 38 pkts/6s
confirmed both sides pacing 300ms before the revert. Peer slow regime
t=521.6 to t=905 (~225ms gaps).

DUT Down-transitions in window, gap since peer's last packet:

    t=1783747521 detect gap=903 ms   (setup: peer restart, pre-soak)
    t=1783747905 detect gap=0 ms     (revert: peer-initiated Down)
    t=1783747978 detect gap=31 ms    (kill: correct 3x10ms detect)

Result: the DUT no longer false-detects at the revert (m5's 151ms
class, fixed by the poll-aware effective interval; budget held at
900ms while the peer paced slow). Detect fires correctly in both
regimes (903ms slow, 31ms after convergence to 10ms).

Remaining flap at t=905 is the mirror bug, peer-side: we advertise
min_tx=10000 instantly (no Poll sequence), the peer's detect budget
for us collapses to 30ms, but RX-clocked TX cannot accelerate ahead
of the peer (echo rate is slaved to peer pacing), so the peer times
us out. Engine log confirms "Up -> Down (peer sent Down)". Fix scoped:
Poll sequence initiation on parameter change + transitional userspace
TX at the new rate until observed peer pacing converges.

## m5d: transitional TX verified, poll blocked by ordering race
(bfd-m5d-poll-tx.pcap, m5d-window.txt, window 1783751882 - 1783752094)

Revert survived (uptime 1:54; DUT pacing flips to 10.8ms at t=998.9
while peer still slow: transitional userspace TX on the wire). No P
packets from the DUT: the poll-termination check in ktx_poll_map read
the map before the mirror pushed poll=1 and cleared the poll at birth.
Consequence: peer never applied the reverted timers, paced 300ms until
the kill, detect correctly fired at 901ms for that regime.

## m5e: full pass (bfd-m5e-poll-tx.pcap, m5e-window.txt)

Window 1783752595 - 1783752934, precondition wire-gated (38 pkts/6s,
fresh capture after catching a stale gate file in the first attempt).
Fix: poll termination only honored when the pushed config carried
poll=1.

    t=1783752622 detect gap=902 ms   (setup: peer restart, slow regime)
    t=1783752897 detect gap=33 ms    (kill: 3x10ms, post-convergence)

Zero transitions at the revert (uptime 4:04 spans it). Poll on the
wire: t=848.066 DUT P, peer F +50us, peer pacing fast at t=848.076.
Advertised timer changes now propagate mid-session; detect budget and
peer pacing converge together. Fixes the m5c t=905 peer-initiated flap
and retires the asymmetric-interval flap loop (transitional TX holds
the peer's budget whenever it paces slower than our required rate).

Peer-side FRR quirk recorded: our P advertising a min_rx increase
(t=607) was F-acked but not applied (peer kept 10ms pacing ~14s until
restart); a min_rx decrease (t=848) was applied instantly. Explains
why m5/m5b mid-session increases never slowed the peer.

## m5f: graceful restart, first attempt - discriminator bug
(bfd-m5f-persist.pcap, m5f-window.txt, window 1783756239 - 1783756563)

--dp-hold 60: orphan/adopt/reconcile machinery all functioned, but
both bfdd restarts still flapped. Wire root cause: DUT my_disc changed
at each adoption (0xebab8c67 -> 0x2c889e3c -> 0xb4e8fa8d). The
wire_disc preservation guard was on the adoption flag, but FRR replays
config as UPDATEs immediately after the ADD, and UPDATEs re-entered
the same path and stamped wire_disc with the new lid. The RFC 5880
your_disc validation (our own m5 hardening) then correctly rejected
the peer's packets still addressed to the old disc: kernel echo
stopped, 30.2ms TX gap, peer detect tripped. Fix: guard on session
freshness, not adoption.

## m5g: graceful restart verified
(bfd-m5g-persist.pcap, m5g-window.txt, window 1783757359 - 1783757486)

Two back-to-back FRR restarts on the DUT with --dp-hold 60, both sides
at 3x10ms, then a peer kill as detect-liveness control.

    single my_disc for the entire capture: 0x0e1f486f
    t=1783757461 detect gap=32 ms   (the kill; only Down event)

No DUT TX gap above 25ms except the kill aftermath (1s slow-rate
heartbeat while the peer rebooted). Peer uptime 1:36 spanning both
restarts: the control plane restarted twice with zero wire
interruption and no peer-visible event. Engine log: hold -> reconcile
armed -> adopt (old lid preserved as wire_disc, new lid for bfdd) ->
UPDATE replay -> silence, twice. Detect fired correctly at 3x10ms
while operating under the third lid, proving the held/adopted session
remains a real session, not a zombie.

Mechanism per Rafael Zalamena's guidance on the FRR dev list:
drop-and-recreate remains the default (--dp-hold 0); graceful restart
is opt-in mark-and-sweep - orphan on disconnect, adopt live sessions
by addr pair on re-ADD, sweep sessions bfdd did not re-register 10s
after reconnect, hard teardown at the hold deadline if bfdd never
returns.
## m5h: spoof/injection test (counter-based, no pcap window)

Injector on a third host (bfd-chaos, 10.66.0.3) forging source
10.66.0.2, broadcast-dst so the bridge floods to the DUT NIC. Delivery
confirmed on the DUT NIC before trusting any counter (earlier attempts
were invalid: the vmbr3 host capture does not mirror unicast-to-DUT,
and a malformed tcpdump filter hid the injected frames). Three cases,
200 packets each: wrong your_disc (0x11111111, ttl 255), low ttl
(ttl 64, correct your_disc), and correct your_disc from the forged
host (ttl 255, my_disc 0xdeadbeef).

First run exposed a real bug: the GTSM and your_disc reject paths
returned XDP_PASS, so rejected packets were counted but still handed
up the stack to the userspace UDP socket, where fsm_rx processed them
with no TTL or your_disc check. The correct-disc case (your_disc =
our wire_disc) matched the live session and overwrote rdisc, churning
the FSM against the real peer. Session flapped (uptime reset) despite
detection never being fooled. Fix: XDP_DROP on both reject sites.

Verified run: baseline uptime 1:56, rejects 0. After injecting all
600 packets: uptime 3:00 (no reset, session held), rejects 600 (all
dropped in XDP, one count each), malformed 0, detection counters
climbing only with real peer traffic. Spoofed liveness refresh,
spoofed echo, and spoofed FSM disruption are all closed; forged
packets die in XDP before reaching userspace.
