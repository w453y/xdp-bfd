# m10: authentication (RFC 5880 s6.7)

Authentication was the last section of RFC 5880 this engine did not
implement, and the only one that could not be done the way the others
were. Every earlier milestone moved work into the driver because the
work was cheap: compare a TTL, compare a discriminator, rewrite a
header. Authentication asks for a keyed digest over the whole packet,
and the kernel offers the XDP program nothing to compute one with —
`bpf_crypto_*` is skcipher only, encrypt and decrypt, with no hashing
and no HMAC anywhere in the BTF.

The alternative was to keep authenticated sessions in userspace. That
withdraws the engine's entire property from exactly the sessions an
operator has asked to protect, which is the wrong way round. So the
digest is carried in the tree, in one header both planes include, and
all three authentication types bfdd can produce run in the program.

Three things about this milestone are worth setting out before the
detail, because they shape everything below.

**The digest follows bfdd, not the RFC.** RFC 5880 s6.7.4 computes a
plain SHA1 over the packet with the shared key placed in the Auth
Key/Hash field. bfdd zeroes that field and computes an HMAC instead. The
two do not interoperate, and bfdd is the control plane on one side of
every session here, so following the RFC would mean failing against
every packet the daemon on the other end sends. This is filed upstream
as [FRR issue 23274](https://github.com/FRRouting/frr/issues/23274) with
no patch attached, deliberately: changing it would break interoperation
with every deployed FRR.

**Stock bfdd cannot send a key to a data plane.** `bfddp_session_msg`
has no field for one — upstream it is a `/* TODO: missing
authentication. */` — and there is no guard either, so stock bfdd will
offload an authenticated session and then transmit it in the clear while
`show bfd peer` reports authentication enabled. Everything measured here
runs against a bfdd carrying a protocol extension written for this
work, described in section 9.

**Two planes must agree byte for byte.** Two implementations of one
digest would disagree silently: every packet would simply fail to
authenticate, on both sides, with nothing in either log to say which end
was wrong. One header, included by both.

## 1. A digest both planes can compile

`include/hmac_sha1.h` is HMAC-SHA1 written to survive the BPF target.
Nothing in it loops over packet data. A BFD control packet with a
keyed-SHA1 auth section is 52 bytes, so the whole HMAC is four fixed
block compressions and every bound is a compile-time constant.

Four things the target forced, none of them visible in the C:

- The block compression and the padding step are calls, not inlined.
  Forced inline they expand six times between them, each expansion
  keeping its own message schedule, which overruns the 512-byte stack.
- The byte loops are *not* unrolled. Unrolled, sixty-four selects over a
  key pointer spill hard enough to need 800 bytes of frame.
- The API takes pre-padded 64-byte blocks rather than a pointer and a
  length. A copy loop bounded by a runtime length makes the verifier
  fork its state on every iteration. Nothing is lost: a caller on the
  fast path assembles the block anyway, because the digest field has to
  be zeroed before hashing.
- Both callees return a value laundered through an empty `asm`. A
  bpf-to-bpf callee must leave a scalar in R0 or the verifier rejects
  whatever the frame held there, and LLVM sees every caller of a static
  function and propagates a constant return without ever emitting it.

Checked against ten vectors, four of them RFC 2202's own, so this is
pinned to the standard rather than to whichever library produced the
rest. Run twice against the same table: on the host, and through the
kernel by an entry point in the test object, because the BPF build is a
different compilation answering to the verifier and agreeing with the
host is not something to assume. The verifier accepts it at 6235
instructions and 64 states.

## 2. Acceptance is two-sided

RFC 5880 s6.8.6 discards an authenticated packet on a session with no
key. It equally discards a bare packet on a session that has one, and
that second half is the one that matters: without it a peer strips
authentication simply by not offering it, and the session stays up
looking perfectly healthy.

Both planes enforce both directions, and both count the disagreement
separately from an unsupported flag, because "the A bit and the session
disagree" is a different fact for an operator than "we cannot honour
this flag".

This changed the shape of the fast path. Acceptance stopped being a
property of the packet alone, so the program now looks the session up
*before* it validates the header. The lookup keys on addresses the
parser has already read, so nothing in the BFD header is trusted to
perform it.

## 3. Keyed SHA1 in the program

Keyed SHA1 went first, which is the opposite of what it looks like from
outside. A keyed-SHA1 packet is always 52 bytes, so every copy in the
program has a constant bound. A simple-password packet is 24 + 3 +
however long the key is.

Verification runs after the demux and before anything about the packet
is believed. An unverified packet does not refresh liveness, does not
update the peer's parameters and is not answered, so a forged one leaves
no trace of having arrived.

The sequence numbers moved into the session map, because whoever emits
the packet has to own them. Userspace hands its own over before the
program is told to answer and never after, and takes back what the
program reached when the session leaves the fast path. Ordering is what
makes that safe rather than a lock: `enable` is still 0 in the map while
the value is written, so nothing is transmitting from the fast path.

Most of the work was the verifier's 512-byte stack budget, which is
charged against a whole call chain rather than a frame. Getting under it
took four changes: the digest's scratch moved to a per-CPU map, the
HMAC's two block buffers became one, its inner digest moved into the
caller's output buffer, and `sha1_finish` went back to being inlined
once it no longer owned a buffer. 656 bytes down to under 512, at 262915
instructions and 3153 states.

Verified against stock FRR on the peer, one session of the 64-session
mesh: 52-byte packets and auth type 4 in both directions, 431 of them,
sequence numbers strictly increasing by one from the seed userspace
handed over, and userspace transmitting 4 packets in twenty seconds
rather than four hundred. `auth-bad` stayed at zero, so every digest the
kernel computed was accepted by bfdd's OpenSSL and every digest bfdd
produced was accepted by the kernel.

## 4. Simple password, and what it actually cost

Leaving simple password in userspace would have meant the weakest type
was the one that lost the fast path. The obstacle was never the compare,
which is sixteen bytes. It was that the packet is 28 to 43 bytes, so the
length is a runtime value and every packet access has to be proven
against it. Three attempts, and what each taught:

A guarded loop over packet bytes does not survive the optimiser. The
compiler unrolls it, folds the per-iteration bound check away with the
index, and the verifier is left looking at a constant offset past the
range it has proven: `invalid access to packet, off=75, r=66`.

Computing the payload offset by subtracting packet pointers is refused
outright: `pointer arithmetic on pkt_end prohibited`. The offset is a
constant per family anyway, since the parser rejects IPv4 options, so
the header is always twenty bytes.

And a bound of "not zero" is not a bound. The verifier still believed
the length could be zero at the helper call and refused a zero-sized
read. It wants a real lower limit.

What works is `bpf_xdp_load_bytes` and `bpf_xdp_store_bytes`, which take
the length as an argument and do the bounds check in the kernel. The
section is read into scratch, assembled there, and written back in one
store. One helper call carries the whole variable-length problem and
everything else works on a fixed-size block.

Verified against stock FRR, same session as the keyed-SHA1 run: 35-byte
packets and auth type 1 in both directions, the password on the wire as
the RFC intends for a type that offers no secrecy, no flap, and
userspace transmitting four packets in twenty seconds rather than four
hundred.

## 5. The IPv6 checksum, which was not an authentication bug

Worth recording because of how it presented. On IPv6 the session came
up in userspace, handed over to the fast path, went silent, timed out,
and repeated: 58 flaps in 30 seconds with both authentication counters
flat. Nothing was wrong with the authentication. The v4 session beside
it, same key and same code path bar the checksum, never missed a packet.

The payload contribution to the IPv6 UDP checksum was being assembled
byte by byte into big-endian words, while every other term in the fold —
addresses, pseudo-header, UDP header — is read straight out of memory. A
ones-complement sum is only byte-order agnostic when every term is
accumulated the same way, so mixing conventions byte-swapped this one.
Invisible on IPv4, which sends no UDP checksum at all; fatal on IPv6,
which must.

The fixed-size scratch block from section 4 is what made the fix clean:
the block is zeroed past the section, so a constant sweep covers exactly
the payload and the trailing zeroes contribute nothing, which also
handles the odd-length payload simple password produces.

Verified on the wire: 393 consecutive engine-sent packets, 35 bytes
each, every one with a UDP checksum tshark validates.

## 6. The replay window

Three receive rules were missing, and together they were a session that
never came back.

**No upper edge.** RFC 5880 s6.7.4 accepts a sequence in `RcvAuthSeq` to
`RcvAuthSeq + (3 * Detect Mult)`. Only the lower bound was checked,
which admits most of the number space.

**A linear comparison, not a circular one.** The RFC says the range is
read "when treated as an unsigned 32-bit circular number space".
Unsigned subtraction gives that for free and a wrap stops being fatal.

**The window was never forgotten.** The RFC clears `bfd.AuthSeqKnown`
after twice the detection time without a packet, for a reason it states
outright: so the sequence can resynchronise if the remote system
restarts.

Without that last rule a peer restart was a coin toss. bfdd seeds its
transmit sequence randomly, and if the new seed landed below the
watermark the session rejected every packet it would ever send. Measured
before the fix: restarting the peer left two of eight authenticated
sessions down for good while all fifty-six unauthenticated ones came
back. Adding the upper bound alone made it *worse* — seven of eight,
every time — because then no restart could land inside the window at all.

The resync belongs in the sweep, which took two wrong attempts to see.
The program validates authentication whether or not it is answering for
the session, so a rejected packet is dropped in the driver and userspace
never sees it: a resync living in the engine cannot fire, and pulling
the kernel's stale window back on every poll undid it even when it did.
The sweep already measures the silence, so that is where the rule goes.

The watermark advances on every accepted packet rather than every fifth.
The RFC only states the update for the first packet, which cannot be the
whole rule — a watermark that never moves puts everything past
`3 * Detect Mult` outside its own window — and a lagging one makes the
window looser than the spec intends.

One further correction: the window is sized from the Detect Mult carried
by the packet being checked, not from a local value. RFC 5880 names the
state variable `bfd.DetectMult` and the header field Detect Mult, and
s6.7.4 asks for the latter. Both planes were using a local one, so the
window was mis-sized whenever the two ends did not use the same
multiplier.

Verified: three consecutive peer restarts, no authenticated session
stuck, mesh at 64 up each time.

## 7. Key chains, not keys

The control plane naming the key of the moment cannot survive a
rollover. A key chain hands over on a clock: the outgoing key stops
being used to sign before it stops being believed, so a packet already
in flight still verifies. A receiver holding only the key it transmits
under refuses exactly the packets that overlap exists to keep.

Nothing was going to arrive to prompt a change, either. bfdd re-reads
the lifetimes on every packet it sends or receives, so its own path
rolls over without being told — but an offloaded session is not on that
path, and there is no expiry hook in the key chain to fire instead.

So the data plane takes the whole chain, with the period in which each
key may be sent and the period in which each may still be accepted, and
decides for itself. A pass a second is enough: the periods are in whole
seconds and the sessions are few. The receive side looks a packet's Auth
Key ID up across everything still acceptable, rather than comparing it
against the key being transmitted with.

One verifier note. The key the program is going to use is copied into
scratch before it is hashed. Read straight out of the map array the
pointer carries a variable offset, and the verifier then walks the whole
SHA1 compression again for every state it could be in — a million
instructions rather than a few thousand.

Measured on the mesh: `keyroll.pcap.gz` is a meticulous keyed-SHA1
session at 50 ms across 329 seconds, 14977 frames. Both ends move from
key id 2 to key id 3 within the same frame pair at t=199.025 s. Every
frame in the capture is state Up, and the largest gap between any two
frames is 51.1 ms. The handover is invisible to the session.

## 8. Demand mode, and the window that never aged

The sweep returned early for a session under demand hold, before it
reached the point where the receive sequence window is aged out. The
hold is there for `alive`: the peer was asked to stop transmitting, so
the silence the sweep measures is silence we requested, and calling the
session dead over it would be wrong. It says nothing about the sequence
window.

Demand mode is where that window most needs to age. The peer can restart
inside a silence no detection timer will ever end, and it comes back
with a fresh random sequence. With the window still holding the sequence
from before the restart, every packet the peer sends lands outside it
and is dropped in the driver — so userspace never sees the peer at all,
and the session reports Up against something that is gone. Nothing
recovers from that on its own.

`demand-deadlock.pcap` is the failure: 115 Down packets from the peer
across 100 seconds, all keyed SHA1, none of them answered. The engine
was reporting Up with the pre-restart discriminator, and `auth-bad` on
that session had climbed to 3074 against 2 received packets.

Ageing the window costs replay protection for one packet after twice the
detection time, which is the trade s6.7 already makes; the digest is
still checked against the key, so a forged packet is still refused.

This is the same defect class as
[FRR 23281](https://github.com/FRRouting/frr/pull/23281), on the other
side of the wire, and it needs fixing in both places: the program
validates authentication whether or not it is answering for the session,
so a resync that lives only in userspace can never fire.

## 9. What this needed from FRR

Four things went upstream, three as patches and one as a report.

| | |
|---|---|
| [PR 23281](https://github.com/FRRouting/frr/pull/23281) | Keyed SHA1 sequence number validation. The same window defect as section 6, in bfdd. |
| [PR 23282](https://github.com/FRRouting/frr/pull/23282) | A keychain with no usable key ran the session unauthenticated rather than refusing it. |
| [PR 23284](https://github.com/FRRouting/frr/pull/23284) | `your_disc == 0` was tested against session state instead of the packet's State field, so a peer that lost its state could not be readmitted. |
| [Issue 23274](https://github.com/FRRouting/frr/issues/23274) | The keyed-SHA1 digest is an HMAC where s6.7.4 specifies a plain SHA1 with the key embedded. Reported without a patch. |

PR 23284 was cross-validated here in a way it could not be inside FRR's
own test suite: the engine emits `Down` with `your_disc = 0` when it
loses a peer, and the fixed bfdd accepts it. Both flap timelines in
section 10 show that exchange against a non-FRR implementation.

Separately, `bfddp-auth-lifetimes` on the fork carries the protocol
extension itself: a `DP_SESSION_AUTH` message carrying every key in the
chain with its send and accept periods, listener support, and a
topotest. The design point is that the data plane decides which key
applies to a packet, because it is the only side holding the packet. It
is not proposed upstream yet.

There is no capability negotiation in this protocol, so bfdd cannot tell
whether a data plane honours `SESSION_AUTH` at all. Nothing can be
enforced from the daemon's end. That is worth raising with the FRR
community independently of this work.

## 10. What was measured: six configurations, two restarts

The point of this matrix is that authentication must not change how a
session recovers. Six sessions of the live 64-session mesh were watched
across two events, with the capture taken on the hypervisor bridge so
neither end is also the observer. The peer runs a bfdd built from master
with all three fixes above applied, so it is a fixed-FRR reference
rather than a packaged one.

Event A restarts the peer's bfdd, leaving the engine as the surviving
end. Event B restarts the engine, leaving the peer as the surviving end.
Outage is measured from the first packet the restarted side sends to the
engine reaching Up.

| session | A (peer restarts) | B (engine restarts) |
|---|---|---|
| symmetric demand + keyed SHA1 | 951 ms | 0.7 ms |
| engine demands, no auth | 2.0 ms | 566 ms |
| peer demands + keyed SHA1, multihop | 0.6 ms | 0.6 ms |
| async + meticulous keyed SHA1 | 0.6 ms | 417 ms |
| async + keyed SHA1 + echo | 0.6 ms | 125 ms |
| async, no auth | 0.4 ms | 434 ms |

Both events: 64 of 64 up at both ends before and after, exactly one down
event per watched session in event A, `auth-bad` 0, `rejected` 0, and
the peer's `RX fail packet` 0 throughout. Authentication does not appear
in the recovery times at all — the two fastest and the two slowest cells
in each column are split across authenticated and unauthenticated
sessions.

What does appear is demand mode, in both directions.

In event A the async sessions look instant because they are not: the
engine's own detect timeout had already fired at 5.7 to 6.1 seconds, so
it was sitting there transmitting `Down` with `your_disc = 0` when the
peer came back, and the peer went straight to Init. The symmetric-demand
session at 951 ms is the honest one. Nothing detected anything, so the
engine was still reporting Up and transmitting nothing, and recovery was
paced by the restarted peer's one-second slow timer rather than by any
detection at all.

In event B the two demand cases finish in under a millisecond for the
mirror-image reason. The peer's detection was held, so it never went
Down; the moment the returning engine says `Down`, the peer answers. The
async cases take 125 to 566 ms because they wait on the peer's slow-timer
grid. The engine-demands session is slowest at 566 ms because the peer
had stopped transmitting but its detection was *not* held — it detected
the engine's death at 4.5 seconds and then had to be found again.

The `auth-mismatch` counter reads 279 before event A and 279 after,
frozen across the whole event. On the freshly restarted engine in event
B it reads 30 and stops. It counts the window between a session being
added over bfddp and its keys arriving in the following message, which
self-heals on retry. It is a bring-up race, not a steady-state fault.

Evidence: `flap-eventA.pcap.gz`, `flap-eventB.pcap.gz`,
`timeline-eventA.txt`, `timeline-eventB.txt`, the four `eventA-*`
snapshots and `eventB-engine-t1.json`. `eventA.sh` and `eventB.sh` drive
the whole thing; `timeline.sh` regenerates the timelines from either
capture.

## 11. Traps worth recording

**A keychain key defaults to no algorithm.** bfdd only selects a key
whose algorithm is `cleartext` or `hmac-sha-1`. Configuring `key-string`
alone leaves the session unauthenticated while `show bfd peer` still
reports authentication configured. This cost more time than anything
else here, and it is a quiet way to believe a link is protected.

**Two predicates disagreed about who answers.** Authenticated sessions
were held in userspace until the program could build a section, which
meant `tx_config` said do not answer while `fsm_tx` still believed a
bounce was coming and stayed quiet waiting for it. The session flapped
at the peer's detection time with nothing in the log: 339 transitions in
a couple of minutes, every packet authenticating correctly. One
predicate now decides.

**The session message grew and the parser required the whole struct.**
An ADD from a control plane predating the extension was being dropped in
silence — no session, no error, nothing on the wire. The header carries
the length and that is the contract: everything past
`BFDDP_SESSION_MSG_MIN` is optional and absent-means-unset. Tested at
exactly the pre-extension length, so it fails again the moment anything
new is treated as mandatory.

**The build rules named `include/bfd_shared.h` by hand,** so editing the
digest or the authentication layout rebuilt neither plane. That cost a
debugging cycle: a stack-size fix that appeared to change nothing
because the object was never rebuilt. Every object now depends on every
shared header.

**The injection matrix had to be kept off authenticated sessions.**
Every frame it builds is unauthenticated, which is exactly what an
authenticated session must discard. Its session picker already skipped
sessions the fast path was not answering for — but an authenticated one
*does* answer, so it became eligible. Only on some runs, because which
session the map hands back first is stable within an engine and
reshuffles when it restarts, so it would have surfaced as the suite
failing after an unrelated restart.

**A demanding session cannot notice its key changed.** Changing the key
on one end of the live mesh took down seven of eight authenticated
sessions on detect timeout, exactly as intended, with `auth-bad`
climbing and none of the other fifty-six touched. The eighth — demanding
at both ends — stayed Up throughout. Neither side transmits, so neither
receives anything to reject, and detection is held on both.
Authentication protects the packets a session sends; it cannot protect a
session that has agreed to stop sending. Everything recovered on its own
when the key was put back.

## 12. Not covered

Keyed MD5 (types 2 and 3) is not implemented, because bfdd cannot
produce it: no keychain algorithm maps onto those types, so nothing ever
sends one.

Interoperation with a conformant third-party implementation is not
possible for keyed SHA1 and was not attempted, for the digest reason in
the header of this document. Simple password has no such problem.

The key rollover in section 7 was measured on one async session. It was
not exercised on a demanding session, where section 11 says it cannot
work, nor across a peer restart landing inside the overlap window.

The 64-session ladder was not re-run with authentication on every
session. The fast-path cost of the digest is measured per session, not
at the session cap.
