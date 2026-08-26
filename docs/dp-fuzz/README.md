# `dp_read` out-of-bounds read: finding, debugging record, and fix

Date: 2026-08-26
Branch: `review-fixes`
Commits: `3f550b3` (seam), `054120f` (fuzz target), `0441f6c` (fix)

This document records a real out-of-bounds read found in the engine's only
network-facing parser, and the full path taken to find it. The debugging
record is deliberately complete, including the wrong turns, because most of
the elapsed time went into a harness design that was wrong from the start and
the reasons it was wrong are reusable.

---

## 1. The finding

`dp_read()` in `src/engine/dplane.c` reads past the end of `dp_buf`, a 4096
byte static buffer, while parsing a byte stream from bfdd.

**Trigger.** A bffdp message that causes the engine to reply, arriving while
the output queue is already full.

**Chain.**

```
dp_read()
  └─ loop: while (dp_have - off >= sizeof(header))
       └─ dp_process(dp_buf + off, mlen)
            └─ dp_send(...)                       dplane.c:210, 418, 492
                 └─ dp_drop_conn("output queue overflow")   dplane.c:182
                      └─ dp_have = 0                        dplane.c:146
```

`dp_drop_conn` zeroes `dp_have` while the loop is still running. `off` keeps
whatever value it had reached. Both are `size_t`, so `dp_have - off`
underflows to a value near `SIZE_MAX`, the loop condition stays true, and
`off` advances until the loop finally exits. The `memmove` below the loop then
reads from `dp_buf + off` with `off` far past the end of the buffer.

**Observed.** `off` reached 4132 against a 4096 byte buffer, a read 42 bytes
past `dp_buf`, from a 45 byte input.

```
src/engine/dplane.c:564:26: runtime error: index 4132 out of bounds
  for type 'uint8_t[4096]' (aka 'unsigned char[4096]')
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior dplane.c:564:26

==1177357==ERROR: AddressSanitizer: global-buffer-overflow
READ of size 2 at 0x6074efc46eea thread T0
    #0 in dp_read /home/w453y/xdp-bfd/src/engine/dplane.c:565:19
0x6074efc46eea is located 42 bytes after global variable 'dp_buf'
  defined in 'src/engine/dplane.c:45' of size 4096
SUMMARY: AddressSanitizer: global-buffer-overflow dplane.c:565:19 in dp_read
```

**Reproducer**, 45 bytes, committed at
`tests/unit/fuzz-regress/dp_read-off-walk-past-buf`:

```
00000000: 0000 0000 0000 0024 ffbf ffff 0000 00fb  .......$........
00000010: d8ff ffff ffff ffff ffff ffff ffff fff7  ................
00000020: ff00 000a 0000 ffff ff00 1000 08         .............
```

Bytes 0 through 7 are the first message header. `length` sits at offset 6 and
reads `0x0024`, so message one claims 36 bytes. `dp_process` runs on it,
`off` becomes 36. The remaining 9 bytes still exceed the 8 byte header, so the
loop runs again and finds `length = 0x000a` = 10, which correctly fails the
`dp_have - off < mlen` guard and breaks.

So the walk is not a second iteration overrunning within a single input. `off`
reached 4132, far beyond 45, because `dp_have` had accumulated across several
`dp_read` calls and the drop reset it between them. The same sequence arrives
naturally on a live socket as separate reads.

**Severity.** Remote-triggerable from the bfdd side of the dataplane socket.
An out-of-bounds read only, not a write, and the value read is discarded into
a `memmove` whose destination is in bounds. The practical worst case is a
crash on an unmapped page.

---

## 2. The fix

Two changes, both in `dp_read`. Committed as `0441f6c`.

**Make the loop condition underflow-proof by construction.**

```c
-       while (dp_have - off >= sizeof(struct bfddp_message_header)) {
+       while (off + sizeof(struct bfddp_message_header) <= dp_have) {
```

Both operands are `size_t`. `off + sizeof(header)` cannot underflow, so the
comparison is correct regardless of what happens to `dp_have` inside the loop.
This does not depend on knowing which callees can shrink it.

**Stop parsing once the connection is gone.**

```c
                dp_process(dp_buf + off, mlen);
                off += mlen;
+               /* dp_process can reply, and a reply on a full output
+                * queue calls dp_drop_conn, which zeroes dp_have.
+                * Both are size_t, so dp_have - off then underflows,
+                * the loop condition stays true, and off walks past
+                * the buffer - an out-of-bounds read in the memmove
+                * below. Found by tests/unit/dp_fuzz. Nothing after a
+                * drop is meaningful anyway: the buffer belongs to a
+                * connection that no longer exists. */
+               if (dp_conn < 0)
+                       return;
        }
```

The first change is the safety property. The second is the correctness
property: continuing to parse into a connection that has been dropped is
wrong independently of the memory error, since the buffer belongs to a
connection that no longer exists.

**Verification.**

- The 45 byte reproducer runs clean where it previously aborted.
- `make check` green: all four suites, including `dp_run`'s 11 framing cases
  which exercise the real `recv` path.
- 100000 fuzz iterations in 90 seconds, exit 0, no further findings.

---

## 3. Relation to FRR #22694

Same family, different mechanism. #22694 was `bfd_dplane_expect` never
reclaiming consumed inbuf space, so a full buffer made `stream_read_try` issue
a zero-length read and zero was misread as peer close. Both are length versus
buffer bookkeeping where an unsigned quantity is trusted.

The direct #22694 analogue was checked here and is **not** present. `dp_read`'s
`recv` has the same shape:

```c
ssize_t n = recv(dp_conn, dp_buf + dp_have, sizeof(dp_buf) - dp_have, 0);
if (n == 0 || ...) { dp_drop_conn("bfdd disconnected"); return; }
```

If `dp_have` reached `sizeof(dp_buf)` the length would be 0, `recv` would
return 0, and the engine would declare bfdd gone while it is still connected.
Unlike #22694, `dp_read` does have the pulldown (the `memmove` plus
`dp_have -= off`). The residual risk would be a buffer that fills with bytes
that never yield a parseable message, so nothing compacts. That is blocked by
the `mlen > sizeof(dp_buf)` guard, which drops the connection before the loop
can stall. `dp_run`'s `bad-length-over-buffer` case covers it. Clean negative
result.

---

## 4. Debugging record

### 4.1 Why a fuzzer

03-testing's Layer 2 asked for `dp_read` plus `dp_process` behind a read seam
as a libFuzzer target, with a corpus seeded from a real bfdd conversation.

`dp_run` already covers the enumerable edges with a real socketpair, 11 cases:
`whole-message`, `three-in-one-read`, `torn-at-every-boundary`, the three
`bad-length-*` classes, and five `add-*` lifecycle cases. Those are cases a
person can list. The fuzzer's value was always the combinations nobody
enumerates: a header claiming one type with another type's payload length,
nonsense type codes at plausible lengths, bodies that parse as one message and
mean another.

Toolchain confirmed available: clang 21.1.8, `-fsanitize=fuzzer` present.

### 4.2 Build

Linking from source rather than the prebuilt objects surfaced three symbols
beyond `dp_run`'s stub group: `ktx_clear`, `ktx_clear_key`,
`echo_peer_refresh`. Also `-lbpf`, because `dplane.c:445` calls
`bpf_map_lookup_elem` directly on the stats path. `sess_fd` stays -1 in the
target, so that lookup fails and its branch is skipped, which is why the real
library is linked rather than a stub shadowing the symbol.

### 4.3 The socket harness detour

The first target drove a real unix socket per iteration: `dp_listen_init`,
`connect`, `dp_accept`, write the input, `dp_read`, tear down. This was the
wrong design and cost roughly fifteen rounds. What follows is what each stage
produced.

**Stage 1: SIGPIPE.** Exit 13, two iterations, no libFuzzer report at all.
`dp_read` replies on `dp_conn` in the ADD path; the harness had closed its end
first, so the write landed on a closed peer. libFuzzer installs no SIGPIPE
handler, so the process died silently. Fixed with `signal(SIGPIPE, SIG_IGN)`,
which is also the state worth fuzzing: bfdd gone mid-message.

**Stage 2: apparent hang.** After the SIGPIPE fix the process ran to the
`timeout` limit. `/proc/<pid>/wchan` read `hrtimer_nanosleep` with near-zero
CPU. This was read as a blocking syscall and produced several wrong
hypotheses in sequence: a blocking `recv`, a saturated listen backlog, a stale
listen fd, a libFuzzer fork server. Each was checked and none held.

**Stage 3: the timing measurement that mattered.** 90 seconds wall, 0.035s
user, 0.073s sys. That ruled out "slow" definitively and established the
process was doing essentially nothing. It should have been taken four rounds
earlier.

**Stage 4: first useful strace.** Filtered to network syscalls, it showed two
complete iterations of bind, listen, connect, accept, all succeeding, then
nothing. So `rig_up` worked and the block was after it, not in setup. Three
prior hypotheses about setup were dead.

**Stage 5: `recvfrom` returning EAGAIN repeatedly.** Tracing read and close
syscalls showed a run of `recvfrom(5, ...) = -1 EAGAIN`. Reading `dp_read`
directly established it does exactly one `recv` per call and returns on
EAGAIN, so this was many no-op calls, not a spin inside one. The fuzzer was
running fine and doing nothing, because `dp_conn` was left from a previous
iteration with no data behind it.

**Stage 6: printf instrumentation.** Counters at every step of an iteration.
This is what finally localised it: iteration 2 skipped the write entirely.

**Stage 7: the write error.** Making the silently-swallowed write guard loud
gave `write(cli=4, 1) = -1: Broken pipe` on a socket that had just connected
successfully.

**Stage 8: root cause of the harness bug.** Printing `dp_conn` before and
after `dp_accept` showed the same value 5 on both sides. Full strace resolved
it:

```
connect(4, {AF_UNIX, "/tmp/dp_fuzz.N.sock"}) = 0
accept(3, NULL, NULL)                        = 5
close(5)                                     = 0     <-- inside dp_accept
```

`rig_connect` closed `dp_conn` at the top of the iteration. That freed the
descriptor number. The kernel then handed the *same* number back for the new
`accept`. `dp_accept` saw `dp_conn >= 0`, believed it was replacing an older
connection, and closed the fd it had just accepted. The next write had no
peer.

The harness must not close `dp_conn` at all: `dp_accept` owns it and closes it
itself on the replacement path. Fixing that removed the EPIPE. Iteration 3
then blocked for a different reason, and at that point the design was
abandoned.

### 4.4 The pivot: a read seam

03-testing specified this from the start. `dp_process` is static, so the seam
goes at the single `recv` in `dp_read`.

```c
/* The one read. A fuzz build replaces it so dp_read can be driven from a
 * buffer with no socket at all. Production keeps recv(2). */
ssize_t (*dp_recv_hook)(int fd, void *buf, size_t len) = NULL;

/* Companion: dp_conn is static and dp_read returns at once when it is
 * negative, so a buffer-driven test needs a way past that guard without
 * a real connection. Never called in production. */
void dp_set_conn_for_test(int fd)
{
        dp_conn = fd;
        dp_have = 0;
}
```

`dp_read` then chooses between the hook and `recv`. With the hook at NULL the
production path is unchanged, which `dp_run`'s 11 socketpair cases verify on
every `make check`.

The target collapses to a buffer, a length, and a call. No socket, no accept,
no connection lifecycle. `dp_set_conn_for_test` also zeroes `dp_have`, giving
each iteration a clean parser buffer, which is the isolation the socket
version never achieved.

The pattern from the FRR `bfd_dplane_listener` work does **not** apply here,
and the reason is worth recording. That listener is a separate process
standing in for the counterparty, driven by topotests, because integration
tests need real processes on both ends. A libFuzzer target has the opposite
constraint: the code under test must run in-process so the coverage counters
feed the mutator. A separate listener would put the parser on the far side of
a socket where libFuzzer cannot see it.

### 4.5 The find

First run with the seam: 6338 executions, coverage climbing from 25 to 43, a
corpus of 15 inputs being reduced and recombined. A functioning fuzzer
exploring the parser.

First run with a persistent corpus directory: crash at roughly 50000 runs.
Both sanitizers fired, UBSan on the index and ASan on the read. Reproduced
standalone from the single 45 byte input, so the finding stands on its own.

### 4.6 Tooling errors that cost time

Four distinct classes, all mine, all worth naming because each cost multiple
rounds.

1. **Pipes swallowing output.** Three separate times, `cmd | grep | head` or
   `| tail` printed nothing because `timeout` killed the process and the
   downstream tool closed early. Each time the empty output was read as data.
   Redirect to a file and grep the file.

2. **Filtering strace by the current hypothesis.** Every early trace was
   scoped to the syscalls already suspected, so it could only confirm or deny
   the current guess and never show the thing not yet thought of. The trace
   that solved it was unfiltered.

3. **Treating absent log lines as evidence.** `grep -c 'bfdd connected'`
   returned 0 across several runs and was used to argue that `dp_accept` never
   succeeded, while strace showed `accept` returning a valid fd. The log
   output was simply not routed to the captured stream. Four rounds of
   reasoning rested on it.

4. **Reading a stale binary.** After the fix landed, the reproducer still
   aborted with the *old* line numbers, which is what should have given it
   away. `make` had rebuilt `bfd_tx` but not `tests/unit/dp_fuzz`. A `touch`
   plus explicit rebuild showed the fix worked.

The single generalisation: I repeatedly proposed a mechanism when a
measurement was one command away. The two tools that produced real answers
were unfiltered strace and a printf at every step of the iteration.

---

## 5. What is committed, and what is not

| Item | Path | Committed |
|---|---|---|
| Read seam and test setter | `src/engine/dplane.{c,h}` | `3f550b3` |
| Fuzz target | `tests/unit/dp_fuzz.c` | `054120f` |
| Makefile rule, gitignore | `Makefile`, `.gitignore` | `054120f` |
| Parser fix | `src/engine/dplane.c` | `0441f6c` |
| Reproducer | `tests/unit/fuzz-regress/dp_read-off-walk-past-buf` | `0441f6c` |
| Live corpus | `tests/unit/corpus/` | **no**, gitignored |

The corpus was minimised with `-merge=1` and came out at 39 files and 156K,
barely compressed. It is regenerable in 90 seconds and would be dead weight
that nobody updates, so it stays out of the repo. The reproducer is the
durable half of the finding and is one file.

`dp_fuzz` is deliberately **not** part of `make check`. A fuzz run is
open-ended, and the enumerable edges are already `dp_run`'s 11 cases.

## 6. How to run it

```sh
# build (needs clang; -fsanitize=fuzzer is not in gcc)
make tests/unit/dp_fuzz

# regression check, milliseconds
./tests/unit/dp_fuzz tests/unit/fuzz-regress/*

# a real run, with a corpus that persists across invocations
mkdir -p tests/unit/corpus
./tests/unit/dp_fuzz -runs=100000 tests/unit/corpus/

# minimise a grown corpus
./tests/unit/dp_fuzz -merge=1 /tmp/corpus-min tests/unit/corpus
```

Findings are written into the working directory as `crash-<sha1>`, which
`.gitignore` covers. To keep one, move it into `tests/unit/fuzz-regress/`
under a name that says what it is.

## 7. Open follow-ups from this work

- The seam exists now and is cheap to reuse. `dp_process` is still static; if
  a target for message bodies alone is ever wanted, that is the next seam.
- The fuzz target is not wired into CI. It belongs in the kernel-matrix CI
  work as a timed run rather than in the fast gate.
- No corpus is seeded from a real bfdd conversation. 03-testing suggested
  seeding from a pcap; the current corpus is entirely synthesised by the
  mutator, which found the bug anyway.

