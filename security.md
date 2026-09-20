# Security model

This document states the threat model xdp-bfd is built against, what the
fast path does with a hostile packet, and what a packet flood costs. The
numbers are measured on the project testbed; where a defence has a trade,
the trade is named rather than hidden.

## Threat model

**Adversary.** Controls the directly attached neighbour, or any host on the
same L2 segment, or any host that can route packets to the box. Can sniff
every frame on the link, forge any frame with any source address, TTL and
content, and send at line rate. Does **not** have the authentication key,
and cannot execute code on the host.

**Assets.**

1. *Truthful session state.* An Up session must mean the peer is reachable
   and a Down one that it is not; the adversary must not be able to make
   either claim false for an **authenticated** session.
2. *Availability of the engine.* The host's other work, and BFD sessions to
   *other* peers, must survive what one neighbour can send.
3. *The key.*

**Out of scope.** An adversary holding the key (BFD's own model gives up
there), a compromised control plane (bfdd is trusted), and the host being
taken down by attacks unrelated to BFD.

## Authentication is required under this model

RFC 5880 without authentication is not resistant to an on-link forger: it
can hold a dead session Up by forging the peer's packets, or take a live
one Down by forging AdminDown, because every field is visible on the wire.
That is the protocol, not this implementation. xdp-bfd's job is to make
**authenticated** sessions actually immune and to make unauthenticated ones
no weaker than the RFC allows.

Note that driving authenticated offloaded sessions needs a data plane
protocol that carries keys; the capability is present here (RFC 5880 s6.7
keyed SHA1, computed as an HMAC to match bfdd), but stock FRR does not yet
push keys over bffdp. See the README and FRR issue 23274.

## What the fast path does with a hostile packet

Every rejection is counted (see the stats map) and, on a BFD port, the
packet is dropped in the XDP program rather than passed to the socket. The
BFD ports have no consumer on the host but the engine's own socket, so a
packet the fast path will not honour has nowhere useful to go, and passing
it only costs a syscall and, at a flood, evicts real datagrams from the
shared socket queue.

| Reaches | Disposition | Counter |
|---|---|---|
| non-IP / non-UDP / non-BFD port | passed to the stack, untouched | `seen` |
| UDP options / v4 header options to a BFD port | dropped | `ip-options` |
| first IPv4 fragment to a BFD port | dropped (a control packet never fragments) | `rejected` |
| UDP behind a v6 extension header to a BFD port | dropped | `v6-exthdr` |
| TTL/hop-limit not 255 (GTSM), no multihop session | dropped | `rejected` |
| malformed header, or an envelope that lies about length, to a BFD port | dropped | `malformed` |
| A-bit / M-bit the session cannot honour | dropped | `auth-mismatch`, `unsupported-flags` |
| well-formed, no configured session (engine mode) | dropped | `unknown-session` |
| authenticated, replay window then digest | dropped on failure | `auth-bad` |
| authenticated, too many digest failures this interval | dropped before the digest | `auth-ratelimited` |

The promiscuous observer (`xdp-bfd-observe`) passes unconfigured packets to
userspace for debugging; it must never run on a production interface.

## What a flood costs

The headline metric is **nanoseconds per frame on the drop path**, not
packets per second: a pps figure is a property of one testbed's NIC, while
ns-per-frame times a NIC's line rate is the answer for any NIC. Measured on
the testbed (`bpftool prog show` run-time delta, `kernel.bpf_stats_enabled`),
64-session mesh live, single 5-tuple so RSS pins one CPU:

| flood | before hardening | after |
|---|---|---|
| malformed to 3784, ~590k pps | passed to socket, `RcvbufErrors` +67k, mesh 61/64 | dropped in XDP, +0, 64/64, **42 ns/frame** |
| valid, unknown pair, ~580k pps | passed to socket, +9k, mesh 63/64 | dropped in XDP, +0, 64/64, **80 ns/frame** |
| valid at TTL 64 (GTSM), ~667k pps | already dropped in the driver, +0, 64/64 | unchanged (the reference) |

Before those two drops a forger could flap sessions it was **not addressing**, by
filling the shared socket queue so datagrams for sessions still coming up
were evicted. After, both flood arms match the GTSM reference: dropped in
the driver, nothing evicted, mesh holds 64/64, recovery within a second.
The drops are attributed, not inferred: under the unknown-pair flood the
`unknown-session` counter took every one of 3.66M frames while
`RcvbufErrors` stayed flat.

**Floods that name a real session.** Three more arms forge frames for an
address pair the fast path actually serves, so they reach the demux, the
authentication path and the echo reflector that an unknown-session drop
would otherwise hide. Measured live against individual sessions of the
64-session mesh:

| flood (aimed at a real session) | result |
|---|---|
| well-formed, wrong `your_disc`, ~513k frames | every frame dropped by the demux rule, `rejected` 1:1, **195 ns/frame**; the named session did not flap and the mesh held 64/64. A forger who knows the address pair but not the discriminator still cannot disturb the session (RFC 5880 s6.8.6). |
| A bit set, bad digest, at an authenticated session, ~554k frames | the per-session auth bucket let the expensive verify run **248 times** and rate-limited the other **553,497** before the digest; the targeted session went down by design (its real packets share the spent bucket) while the other 63 were untouched, recovering to 64/64 in ~1s. A bad-auth flood costs a bounded amount of CPU and cannot spread past the single session it targets. |
| self-addressed echo from a known echo peer, ~253k frames | reflected one-for-one (`XDP_TX`), **204 ns/frame**, mesh 64/64; UDP/3785 from any source that is not a peer of an echo-active session is counted `declined` and never reflected, which closes the reflection off as an amplification vector. |

The auth arm is the sharpest of the three: without the bucket every one of
those 554k frames would have cost a sequence check and, in window, a full
HMAC-SHA1 in softirq; with it the costly path ran 0.04% as often, and the
blast radius is one session rather than the host.

**Unrelated line-rate traffic.** Spread-port traffic (not aimed at a BFD
port) is left alone before it is even counted; ~1M pps of it dips the mesh
to 56/64 by softirq saturation and it self-recovers within 10s, with the
dead-man gate never tripping. On the virtualised testbed the ceiling is the
guest's RX path (~1M pps), not the engine; the per-frame ns figures are
what carry to a bare-metal host with more RX queues.

## The forced-HMAC bound and its trade

An authenticated session checks the replay window before the digest, so a
forger must supply an in-window sequence (visible on the wire); each such
packet then costs a full HMAC-SHA1 in softirq, per packet, per CPU. The bucket caps
this: once a session sees more than eight digest failures inside one detect
interval it drops further A-bit packets before the digest until the interval
turns over, counted `auth-ratelimited`.

**The trade, stated plainly.** Under a *sustained* in-window bad-digest
flood the bucket empties and the session's own real packets are then dropped
too, so that one session can go Down. That is the honest outcome of an
on-link attack on a single session, and it bounds the CPU either way. The
bucket is per-session: the other sessions are untouched. A key rollover
produces at most a handful of failures, well under the ceiling.

## The dead-man gate under a flood

If a flood saturates every CPU's softirq, userspace starves, the engine's
heartbeat goes stale, and after one second the gate stops the fast path
from answering, so peers take their sessions Down on their own timers.
Without the gate the fast path would keep answering from softirq while the
engine was frozen, holding sessions Up on a lie. A starved engine cannot
tell bfdd anything, so Down is the honest answer, and it is what any
userspace BFD daemon would produce under the same flood, only later. The
gate is the trade between a late-but-true Down and a timely lie, resolved
for the truth.

To keep the engine schedulable under softirq load the systemd unit runs it
`SCHED_FIFO`; pinning it away from the RX queues' CPUs with `CPUAffinity`
is a documented option for operators who have the cores.

## Memory

The engine allocates nothing per packet or per session after start. The
session table, the maps, the 256 KB event ring and the 64 KB data-plane
queue are all fixed. Under host memory pressure the risk is the OOM killer
taking the engine, at which point the XDP link detaches and peers detect on
their own timers, which is correct; the unit sets `OOMScoreAdjust` low to
make it a late target.
