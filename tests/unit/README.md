# Unit checks

## abi_check.c

Pins the layout of every struct shared between the XDP program and the
engine: sizes for all six, and field offsets for the four that both
planes read or write.

`bfd_shared.h` warns that a field added on one side is a silent map
misread. Nothing enforced that before this file. The assertions are
compiled by the host compiler and by clang for the BPF target, so a
divergence between the two is a build error rather than a runtime
corruption. There is no runtime component: if `make` succeeds, the check
passed. It runs first in the default target.

### When an assertion fails

Two cases, and they are not the same.

If the layout change was deliberate (a field added, a struct reordered),
regenerate the numbers rather than editing them by hand. Hand-editing an
offset to match a change you did not intend is exactly the silent misread
this file exists to catch:

    gcc -O2 -Iinclude tests/unit/abi_probe.c -o /tmp/abi_probe
    /tmp/abi_probe

and rebuild the assertion list from that output.

If it was not deliberate, the two compilers now disagree about a struct
both planes use, and the map contents are already wrong at runtime. Do
not regenerate; find the divergence first.

### Coverage

Six structs pinned by size: `bfd_ctrl_pkt`, `bfd_addr`, `session_key`,
`session_state`, `bfd_event`, `tx_cfg`.

Offsets pinned for `session_state`, `tx_cfg`, `bfd_event`,
`session_key`, and the two `bfd_ctrl_pkt` fields the kernel rewrites.

Enums pinned by value rather than by count, so inserting a member in the
middle fails rather than silently shifting everything below it: all
eleven `BFD_STAT_LIST` slots plus `BFD_STAT_MAX`, both `bfd_tunable`
members, and the four `bfd_state` values.

Not covered: map value sizes as declared in the BPF object. A map whose
declared value size no longer matches the struct it carries still fails
only at load time, and only if the mismatch is large enough to be
rejected. That check needs the loaded object rather than the header, so
it belongs with the Layer 1 harness.

## xdp_run.c

Runs the XDP program in the kernel through `BPF_PROG_TEST_RUN`: no NIC, no
testbed, no FRR. The program is a pure function of (frame bytes, map state)
to (verdict, frame bytes, map state), and this drives it as one. Needs root.

    make test-xdp

58 cases, about two seconds.

### Why, given tests/ already exists

The injection suite reaches the same program through the wire, from the
three-host lab, and it cannot set map state. That makes several things
unreachable from it:

- The bounce frame itself. The injector sees that a reply happened; it
  cannot compare the reply byte by byte against what `tx.h` says it should
  be.
- The v6 UDP checksum. The hand-rolled 34-word fold had no independent
  verification of any kind before this.
- The sweep. It runs from a `bpf_timer`, so nothing outside the lab ever
  exercised the detect arithmetic, the interval fallback, the
  negative-delta guard or the echo advisory verdict.
- Anything needing a specific map state, such as a Poll sequence
  outstanding with a chosen sequence number.

### What it covers

- **Parse and validate**: non-BFD ports, GTSM, IP options (both a BFD port
  and an unrelated one), IPv4 fragments including that DF is not a
  fragment.
- **Header matrix**, both families: the five `bfd_ctrl_check` malformed
  conditions and the two unsupported-flag conditions, each asserting the
  verdict, the stat slot, and that the session was not touched.
- **Demux**, both families: your_disc matching, a wrong discriminator
  rejected even though the address pair is in the map, and the
  zero-discriminator restart rule with the peer Down and with the peer Up.
- **Bounce**: the frame checked field by field (MAC swap, address swap,
  TTL, tot_len, IP checksum, source and destination ports, UDP length, and
  the payload rebuilt from `tx_cfg`), plus the v6 arm with the UDP checksum
  verified independently.
- **Trim**: oversized inbound frames at +8 and +64 bytes, both families,
  asserting the reply is exactly 66 or 86 bytes with correct lengths and
  checksums.
- **Map effects**: `last_seen_ns`, `rx_pkts`, the `alive` compare-and-swap,
  `remote_disc`, and Poll termination writing `final_seq` (with the two
  negative arms: no outstanding poll, and a plain packet).
- **Echo reflector**: our own echo consumed, not-self, declined for a peer
  that is not echo-active, reflected for one that is, and two arms showing
  that the TTL 254 exception in `parse.h` requires self-addressing as well,
  so it is not a general TTL bypass.
- **Sweep**: silence past and under the budget, the compare-and-swap not
  firing twice, the `detect_iv_us` fallback to
  `max(min_tx_us, cfg->min_rx_us)`, the negative-delta guard, and the echo
  advisory verdict in four configurations, each asserting that it never
  changes `alive`.

### What it does not cover

- The engine. `fsm.c`, `session.c` and `dplane.c` have no tests at all.
  That is Layer 2 of the test plan and none of it is done.
- Timing. Everything here is single-shot; the timing claims live in
  `docs/` and in the lab suite.
- The verifier across kernels. This runs on whatever kernel you are on.

### The sweep object

`check_session` only ever runs from a `bpf_timer`, and a timer does not
fire under `test_run`. `bfd_xdp_test.c` is a second BPF object carrying one
extra program that drives the same callback through the same
`bpf_for_each_map_elem` helper, at a time the test supplies.

It is built only by the test target and never shipped. A test entry point
inside `bfd_xdp.o` would mean a loader could attach it by mistake, and one
more program for the verifier to accept on every supported kernel.

Its include block must match `src/xdp/bfd_xdp.c` exactly. Same headers,
same clang flags, so the only thing that differs between the two objects is
the entry point. If you change one include block, change the other.

Note that `check_session` takes its clock through `ctx` rather than calling
`bpf_ktime_get_ns()` itself, which is what makes any of this testable.
`sweep_fire` is the one reading the clock, and it is not covered.

### Notes worth keeping

No bugs were found writing these. Everything covered was already correct.
The value is that it can no longer change silently, and that several of
these behaviours had no verification of any kind before.

Three expectations turned out to be wrong during writing, each time
because a disposition was assumed rather than read:

- The five malformed-header cases were written expecting `XDP_DROP` and
  return `XDP_PASS`. `validate.h` says why: a broken header is not evidence
  of an attack and the stack may want it, while a well-formed header we
  cannot honour is dropped because passing it hands userspace something it
  would accept as what it is not. Had the failures been trusted, a "fix"
  would have broken intended behaviour and pinned it forever.
- Two echo cases expected the echo path's own GTSM check to fire. It
  cannot: `parse.h` rejects everything that is neither TTL 255 nor the
  254-and-self-addressed exception, so `BFD_STAT_ECHO_TTL` is unreachable
  from a v4 frame.

A corollary from the first of those: once a rejection returns `XDP_PASS`,
the verdict assertion is nearly vacuous, because an unmatched packet also
passes. The stat slot is what makes those fourteen cases real assertions.

