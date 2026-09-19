# RFC conformance

"Full BFD support" is not a single target: the BFD RFC family covers
transports and deployments that are different protocols in practice. The
honest deliverable is this matrix, with every deviation named. What this
project aims to be complete for is everything bfdd can offload over the
bffdp data-plane protocol, tested, with deviations justified. Today that is
5880 / 5881 / 5883 plus echo and demand mode.

| RFC | Title | Status | Notes |
|---|---|---|---|
| 5880 | BFD base | **implemented**, two deviations | Async mode, full state machine, poll/final, demand mode (with the s6.6 verification poll the RFC leaves optional), echo. Passive role, AdminDown and diag codes present. Deviation 1: keyed SHA1 computes an HMAC as bfdd does, not the RFC's plain SHA1 with the embedded key (FRR issue 23274). Deviation 2: keyed MD5 (types 2, 3) not implemented; bfdd maps no keychain to them. |
| 5881 | Single-hop IPv4/IPv6 | **implemented** | GTSM on both planes, the control ports, the source-port range, echo on 3785. |
| 5882 | Generic application of BFD | n/a | Guidance for BFD clients; that is bfdd's side. |
| 5883 | Multihop | **implemented** | Port 4784, per-session minimum TTL, TTL restored on the reflected reply. |
| 5884 | BFD for MPLS LSPs | not implemented | Different encapsulation (MPLS echo bootstrap); not in bfdd's data plane. |
| 5885 | BFD for VCCV / pseudowires | not implemented | Same. |
| 7130 | micro-BFD on LAG members | not implemented | Would need per-member sessions on one address pair; the map key is address-only. Feasible later by keying on ifindex too. |
| 7419 | Common interval support | **partial** | The engine honours any interval; shipping the RFC's recommended set as presets is a configuration item, not an engine one. |
| 7880 / 7881 / 7882 | Seamless BFD (S-BFD) | not implemented | Reflector/initiator model with fixed discriminators. The XDP reflector is a natural fit for the S-BFD reflector role and is the first extension worth considering once bfdd's data plane can carry it. |
| 8562 / 8563 | Multipoint BFD | not implemented, **rejected on the wire** | The M bit is dropped (s6.8.6), multipoint being a different protocol. |
| 8971 | BFD for VXLAN | not implemented | Encapsulation. |
| 9127 | BFD YANG | n/a | Management; bfdd's. |
| 9468 | Unsolicited BFD | not implemented | Would need "accept a session from an unknown peer", which is exactly what the unknown-session drop removes by default. If wanted it is a per-interface allow rule, never a default. |
| 6428 | MPLS-TP CC/CV/RDI | not implemented | Different profile. |

## Deviation 1: keyed SHA1 is an HMAC

RFC 5880 s6.7.4 specifies keyed SHA1 as `SHA1(packet with the key bytes
embedded in the auth section)`. bfdd instead computes an HMAC-SHA1 over the
packet with the auth digest zeroed. This engine matches **bfdd**, because
bfdd is the control plane it serves and interop with it is the requirement
that matters; a packet this engine accepts is exactly one bfdd would. The
divergence from the letter of the RFC is bfdd's, and is filed upstream as
FRR issue 23274.

## Deviation 2: no keyed MD5

Types 2 (keyed MD5) and 3 (meticulous keyed MD5) exist in the RFC and in
bfdd's enum, but bfdd maps no keychain algorithm to them, so nothing can
drive them over the data plane. They are not implemented here. Simple
password (type 1) and keyed / meticulous keyed SHA1 (types 4, 5) are.
