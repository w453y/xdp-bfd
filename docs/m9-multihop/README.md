# m9: multihop BFD (RFC 5883)

Single-hop BFD (RFC 5881) leans on the TTL for its security: a control
packet must arrive at 255, so anything routed has been decremented and
is rejected. That check is the whole of GTSM, it costs one comparison,
and it runs before any session lookup.

Multihop gives that up by definition. Packets cross routers, arrive
below 255, and the receiver instead enforces a configured *minimum*.
The protocol also moves to UDP port 4784 so the two modes cannot be
confused on the wire.

The engine already had most of what it needed and was throwing it away.
`DP_ADD_SESSION` carries a `ttl` field and a `SESSION_MULTIHOP` flag;
bfdd fills both. The parse code read the `ttl` byte and discarded it,
and the reject mask refused any session with the multihop flag set.

## 1. The minimum, and where it can be enforced

bfdd sends the negotiated value: `mh_ttl` for a multihop session and
255 for a single-hop one. So one rule covers both cases —

    accept if ttl >= cfg->min_ttl

— and single-hop sessions, carrying 255, behave exactly as before. The
`SESSION_MULTIHOP` flag is not consulted for this at all.

The problem is *where*. The GTSM check sits in the parser, before the
session lookup, which is deliberate: a spoofed flood at TTL 64 dies in
a few instructions with no map access. But `min_ttl` is per session,
and at that point there is no session yet.

Deferring the check unconditionally would cost every rejected packet a
hash lookup first, so the parser keeps its cheap path and consults one
bit in `prog_flags`:

- TTL 255 — accepted here, unchanged, always.
- Our own echo returning (dst 3785, TTL 254, self-addressed) —
  unchanged.
- Anything else — if no multihop session exists on this box, drop
  immediately as before. Otherwise defer.

The deferred check runs after the config lookup and drops unless the
session exists *and* admits the TTL. The "exists" half matters: the
lookup's miss path returns `XDP_PASS` for the standalone observer, so
without it a low-TTL packet to an unconfigured pair would start
reaching userspace, which would undo the m5 property that rejects never
surface.

Userspace maintains the bit by scanning sessions on add and clear, as a
read-modify-write so the loader's promiscuous-observe bit survives. A
deployment with no multihop session is byte-identical to before,
including the cheap early filter.

## 2. Port 4784

This was missed on the first pass and is worth recording as such. The
TTL work was written, tested against an injector, and passed — but the
injector sent to 3784, so it validated the rule against packets that
were not multihop at all. Real traffic arrives on 4784, and the parser
accepted only 3784, so it was passed to a stack where nothing listens.

Three changes followed. The parser accepts both ports. The kernel
bounce captures the inbound destination port before rewriting L4 and
replies to whichever port the frame arrived on, so it needs no flag.
Userspace binds 4784 for both families, drains it in the main loop with
the same demux as single-hop (`your_disc` first, address pair as
fallback), and selects the destination port per session — and *that*
does need `SESSION_MULTIHOP`, because it cannot be inferred from
`min_ttl`: a multihop session with a minimum of 255 is legal.

For IPv6 the multihop socket deliberately does **not** set
`IPV6_MINHOPCOUNT`. The single-hop socket sets it to 255 so the kernel
discards low-hop packets before userspace sees them, which is right
there and fatal here — multihop packets arrive below 255 by definition.
The per-session minimum is enforced in XDP instead, so nothing is
given up.

## 3. Restoring TTL on the reply

The kernel bounce reuses the received frame as its reply. For
single-hop that is correct by accident: the packet arrives at 255 and
leaves at 255. For multihop it is wrong — the reply would go out
already decremented, lose more on the return path, and be measured
against the peer's own minimum. The session would come up in one
direction and fail in the other, presenting as a flapping peer rather
than a TTL problem.

RFC 5883 wants multihop sent at 255 so the receiver can count hops,
which is what the userspace path already did via `setsockopt`. The
bounce now matches: if the frame arrived below 255 it is restored,
with an incremental checksum update for v4 and a plain assignment for
v6, which has no IP checksum. Single-hop frames arrive at 255 and skip
the branch entirely.

## 4. What was measured

All four cases run from a third host on the same segment, against a
multihop session configured with `minimum-ttl 200`, with the
single-hop mesh live throughout.

| case | packet | v4 | v6 |
| --- | --- | --- | --- |
| A | above the minimum, on 4784 | accepted | accepted |
| B | below the minimum, on 4784 | dropped | dropped |
| C | below 255 to a **single-hop** session, on 3784 | dropped | dropped |
| D | valid Up packet below 255, reflected | reply at 255 | reply at 255 |

Case C is the one the design rests on. A packet at TTL 200 aimed at a
single-hop session is still dropped while multihop is active elsewhere
on the box, because that session's minimum is 255. Enabling multihop
anywhere does not weaken GTSM anywhere else.

Case D exercises the restore. Twenty injected packets at TTL 210 with a
correct discriminator produced twenty replies at TTL 255 and none at
210. The injected packets are separable from live session traffic by
their traffic class — scapy leaves it at zero, FRR sets 0xc0 — and the
bounce preserves it, so the replies to injected packets are
identifiable. For v6 those replies also read `udp sum ok`, confirming
the mandatory checksum is recomputed correctly over a frame whose
hop_limit was rewritten.

Establishment against a stock FRR peer works on both families:
`m9-establish-4784.pcap` shows both directions on 4784, and the reply's
source port is a per-slot port, so the kernel bounce is carrying it
rather than userspace. Turnaround measured at the bridge is 24 us.

Evidence: `m9-v4-ttl-restore.pcap`, `m9-v6-hoplimit-restore.pcap`,
`m9-establish-4784.pcap`.

## 5. Traps worth recording

The engine's own reject mask refused `SESSION_MULTIHOP`, logging
`rejected (unsupported flags 0x1)` — the same mask that had to lose
`SESSION_ECHO` in m8. The rejection was in the engine's log, not
bfdd's, and time was lost reading bfdd's dataplane code first.

`MAX_SESSIONS` is 64 and the test mesh fills every slot, so a multihop
peer is the 65th and hits `session table full`. The limit is tied to
the per-slot source port range 65472-65535, so it is architectural
rather than arbitrary; a slot has to be freed before testing.

tcpdump omits the `class`/`flowlabel` prefix from v6 output entirely
when both are zero, which is exactly the case for injected packets and
their replies. A pattern expecting that prefix silently misses them —
the twenty replies were in the capture the whole time. Match on
`IP6 (hlim` instead, or check the packet arithmetic.

## 6. Not covered

IPv6 multihop shares the parser and the deferred check with v4, but was
validated on its own socket path; the two were not exercised
simultaneously at scale. The 64-session ladder was not re-run with
multihop sessions present, so the cost of the always-on additions at
the session cap is measured only for the single-hop case (see
docs/m8-echo for the method).
