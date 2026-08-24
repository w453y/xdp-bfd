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
