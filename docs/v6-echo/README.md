# IPv6 echo origination

The m8b originator was v4 only. `docs/m8-echo/README.md` recorded the
reason as a property of the kernel: that a self-addressed IPv6 packet is
not looped by a neighbour's forwarding plane the way a v4 one is, which is
why FRR reflects v6 echo in software instead. That was inferred from FRR's
behaviour, never measured, and it is wrong.

## The measurement that retracted it

Injected from bfd-chaos to bfd-peer's MAC, captured on the hypervisor
bridge, with a v4 arm as a positive control so a v6 zero could not be a
broken rig:

| arm | neighbour forwarding | injected | returned at 254 |
|-----|---------------------|----------|-----------------|
| v4 control | `ip_forward=1` | 10 | 10 |
| v6 | `conf.all.forwarding=0` | 10 | 0 |
| v6 | `conf.all.forwarding=1` | 10 | 10 |

Self-addressed v6 loops. FRR sourcing its v6 echoes at the peer is a choice
in FRR, not a limit in the kernel. The v6 reflector already in `echo.h` is
therefore not serving a pattern that never occurs.

## What was then built

Three pieces, because the return path was dead before the first of them:

- `parse.h` gained the same narrow GTSM exception the v4 branch already
  had: hop limit 254, self-addressed, on the echo port. The `c->udp`
  assignment moved above the check so the port is readable there, which is
  the identical reordering the v4 path needed. Without it,
  `echo_reflect_v6`'s return branch is unreachable and v6 echo RTT never
  updates.
- `echo.h` gained the hop-limit-254 return branch, demuxing on `echo_disc`
  and stamping `echo_last_seen_ns`, `echo_last_nonce` and `echo_rx_pkts`.
  It is ordered before the GTSM check and every miss inside it returns
  rather than falling through, so `BFD_STAT_ECHO_TTL` stays unreachable on
  both families.
- `echo_tx.c` gained the v6 frame builder: 86 bytes, no IP checksum, and a
  UDP checksum folded over the 40-byte v6 pseudo-header. The payload writer
  is now shared, since it is byte-identical across families.

`stats.c` carried a second family gate reporting `echo.active` as false for
any v6 session. It was found only because this test needed the field as an
oracle, and `active` now means the interval is non-zero rather than the
family is v4.

## Results

Full run in `parse.txt`, captures in `v6echo-noforward.pcap` and
`v6echo-forward.pcap`. One config, 15s per arm at a 50ms interval, changing
only the neighbour's sysctl between them:

| arm | sent | valid checksum | returned | payload matched a sent frame |
|-----|------|----------------|----------|------------------------------|
| forwarding off | 295 | 295 | 0 | 0 |
| forwarding on | 295 | 295 | 295 | 295 |

Engine on the forwarding arm: `rx` 6 to 304, `rtt_last_us` 59, `alive`
true.

Three things make those numbers mean something. The checksum is validated
by tcpdump, which folds the v6 pseudo-header independently of
`echo_build_v6` — recomputing it in the test would only prove the test
agrees with itself. The payload match ties each return to a specific
transmission, where a count of 254 frames would have passed on any 254
frame on the bridge. And the negative arm is the same code sending the same
frames with nothing coming back, so the difference is the forwarding plane
and nothing else.

First frame, sent and returned identically:

    20 c0 03 18   version 1, diag 0, state Up, mult 3, length 24
    e1131e4d      my discriminator
    00000000      your discriminator, zero: a classic echo never loops it
    00002710      min tx 10000us
    00002710      min rx 10000us
    000008e4      nonce, in the Required Min Echo RX field

The nonce is what `ktx_poll_map` matches on return, so a non-zero
`rtt_last_us` is itself evidence the demux resolved to the right session.

## Reproducing

    ~/mode_b_opt.sh && sleep 25
    python3 tests/v6_echo_wire.py

It picks the first v6 mesh peer out of the running config, copies that peer
line verbatim, enables echo on it, runs both arms and reverts. Nothing is
written to startup config.

## Reading the output

- `echo.lost` is a running total, not a rate. It only increments when an
  echo is outstanding as the next falls due, and never decrements, so it
  carries whatever accumulated during the negative arm straight through the
  passing one. It read 379 across a run where every frame returned.
- The neighbour's `net.ipv6.conf.all.forwarding` is not persistent and is
  0 by default on this testbed, unlike `ip_forward`. A v6 echo session
  against a neighbour without it will transmit and report `alive` false,
  which is correct advisory behaviour rather than a fault.
- The per-100 echo report line in the engine is `log_debug`, so it needs
  `--log-level debug`. The SIGUSR1 dump is the oracle otherwise.
- `check_fresh` exists because `make` replaces `bfd_tx` rather than writing
  through it. An engine started before the build produces an empty capture
  that looks exactly like a broken frame builder. That misreading cost a
  full run.

## Unit coverage

`tests/unit/xdp_run.c` carries seven cases for this: the return with a
known discriminator, the same frame with one we never sent, 254 that is not
self-addressed, off-link, not-self at 255, declined, and reflect. The
unknown-discriminator arm is what keeps the map-write assertions from being
vacuous, and the reflect arm guards the reflect path against being
swallowed by the return branch above it.
