# Testing the userspace receive path

`inject_matrix.py` asserts on BPF counters, so it can only ever test what
XDP does. Everything the engine does once a packet reaches userspace - the
acceptance predicate, GTSM on the sockets, the demux - had no coverage at
all. Two of the review branch's own fixes lived there, unverified, and one
of them turned out not to work.

`tests/netns_userspace.py` covers it. Twelve cases per family, on one
machine, in about fifteen seconds.

## How it works

Two namespaces on a veth pair in 10.77.0.0/24 and fd77::/64, so nothing
touches the live mesh on ens19.

The engine runs in **static mode** - no `--dplane`, no `--kernel-tx` - so
there is no control plane to stand up, no contention for port 50700, and
every packet goes through `recvmsg` and `fsm_rx` rather than being answered
in XDP.

The injector is a plain UDP socket with `IP_TTL` or `IPV6_UNICAST_HOPS`
set. No scapy, no raw sockets, no layer-2 crafting: the userspace path
receives datagrams, so a datagram reaches every check worth testing there.
Fragments and IP options are XDP-path concerns and stay in
`inject_matrix.py`, where the counters can see them.

Assertions read per-session `rx_pkts` out of the SIGUSR1 stats snapshot. A
rejected case leaves it flat and an accepted one moves it by the injected
count - the same delta discipline the matrix uses, against a counter that
exists in userspace. That counter only became a real number when the
counter-fidelity fix landed earlier in the branch; before that it was
structurally zero and none of this would have been possible.

`accepted` runs first and `accepted-again` last, so every `+0` in between
has a live-injector witness at both ends.

## What it found

Three defects, on its first working run, on a path four review documents
and two reviewers never reached.

**IP_MINTTL does nothing on a UDP socket.** Linux enforces it only in
`tcp_v4_rcv`, which has its own MIB counter, `TCPMinTtlDrop`. The
`setsockopt` succeeds and the value is never consulted. The single-hop v4
GTSM added earlier in this branch was inert from the day it was written.

**IPV6_MINHOPCOUNT does nothing either**, for the same reason, and that one
predates the branch entirely - the v6 single-hop socket had been unguarded
for as long as it has existed. It was confirmed by measurement rather than
inferred from the v4 result, which is the whole reason static mode learned
IPv6 first.

**The demux fell back to the address pair on any miss.** XDP requires
`your_disc` to name our session, or to be zero with the peer in Down or
AdminDown. Userspace looked the discriminator up and, on a miss, matched on
addresses regardless - so a packet naming a discriminator we had never
issued was accepted. This was listed in the code review's finding 2 and
never implemented; the shared predicate and the socket GTSM landed without
it.

## Evidence

| case | before | after |
| --- | --- | --- |
| `gtsm-v4` | rx +10 | rx +0 |
| `gtsm-v6` | rx +10 | rx +0 |
| `disc-mismatch-v4` | rx +10 | rx +0 |
| `disc-mismatch-v6` | rx +10 | rx +0 |

The rig was committed red, with those four failures in its commit message,
before anything was fixed. Each fix then flipped its own pair and left the
rest untouched.

The GTSM fix is what the multihop sockets had been doing correctly all
along - `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` and a per-packet check - against
a fixed 255 rather than a per-session minimum. Both control buffers had to
grow by one `CMSG_SPACE(sizeof(int))`; a buffer sized for one cmsg
truncates the second silently, and the check would then never see a value.

## What it does not cover

Anything below the socket: fragments, IP options, layer-2 framing, the
echo reflector, and the RX-clocked TX bounce. Those are XDP's, and
`inject_matrix.py` tests them against the stat map on real hardware.

It also does not test multihop. Static mode creates a single-hop session,
so the per-session TTL minimum and the 4784 sockets are exercised only by
the live testbed.

## Running it

    make
    python3 tests/netns_userspace.py
    python3 tests/netns_userspace.py --only gtsm
    python3 tests/netns_userspace.py --keep   # leave the namespaces up

Needs root. If a run is interrupted, `sudo ip netns del bfdrig-a bfdrig-b`
cleans up.
