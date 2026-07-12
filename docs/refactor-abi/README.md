# refactor-shared-abi (merged to main)

Branch off main at 7311f8e (m5-hardening merge); merged to main after the verification below. Wire-verified on the
standard testbed (bfd-dut / bfd-peer, FRR 10.5.1, 3x10ms session,
capture on Proxmox vmbr3). Origin of the work: an external code-review
pass over bfd_tx.c, bfd_xdp.c and loader.c. Each suggestion was
evaluated against the code; accepted items are below, rejected items
are listed at the end with reasons. Two issues the review flagged as
open (an IP-options validation bypass and stream-desync handling) were
resolved after the initial pass and are documented in sections 7-8.

## Commits

| Commit  | Content |
|---|---|
| e6ef8cf | shared kernel/userspace ABI header, loader error paths, notify FRR on map-path peer Down |
| a2425c9 | regression evidence (ladder L1-L4, dp-hold double restart, pcap + window files) |
| f9c40f3 | mult-1 jitter cap (RFC 5880 s6.8.7), trim oversized echo frames, README flap-count reconciliation |
| 369f206 | trim-verification capture |
| 6170c82 | README truncation fix (transfer artifact, not a content change), spoof_long.py evidence |
| b3d73ab | XDP_DROP IP-options packets to the BFD port (closes the options bypass), spoof_options.py evidence |
| 91a4b86 | drop connection on bad frame length instead of resyncing mid-stream, bad_frame.py harness |

## Changes

### 1. Shared ABI header (include/bfd_shared.h)

`session_key`, `session_state`, `bfd_event` and `tx_cfg` existed as
three hand-synced copies across bfd_xdp.c, bfd_tx.c (as map_key /
map_cfg / map_state) and loader.c. These structs are the BPF map value
formats: a field added on one side but not the other is not a compile
error, it is silent map misreads. All three binaries now include one
header, which also carries the shared constants (ports, BFD flag bits,
BFD_MAX_SESSIONS, BFD_MIN_LEN). bfd_tx.c keeps F_P / F_F / PORT_CTRL /
SRC_PORT as aliases to avoid call-site churn. Net effect on the tree
is negative lines: the header replaces more code than it adds.

Verified by ABI dump: `bpftool map dump name bfd_sessions` and
`tx_config` print every field in order with sane live values
(detect_iv_us converged to the interval, tx_pkts tracking rx_pkts, the
poll flag in the old pad slot). bpftool reads the layout from the BPF
object's BTF, so a matching, correctly-ordered dump confirms the
kernel-compiled struct and the userspace header agree.

### 2. FRR notify on map-path peer Down (bfd_tx.c)

The `ktx_poll_map` backstop (kernel map reports peer sent Down, used
when the userspace socket missed the packet) assigned `s->state`
directly, skipping `dp_notify_state()`. Consequence: FRR could report
the session up while the dataplane FSM was Down, until the next
transition. The path now goes through `state_transition()`, same as
every other transition. This is the only behavior change in commit
e6ef8cf.

### 3. Loader error paths (loader.c)

- `bpf_object__find_program_by_name()` result was passed to
  `bpf_program__fd()` unchecked: NULL deref if the section is renamed.
  Now checked, as are the three map fd lookups.
- XDP attachment outlives the process. Error exits after attach
  (map lookup failure, ringbuf setup failure) previously left the
  program attached to the interface with no owner. Both paths now
  detach before exiting.
- events.csv / observer.csv are opened in append mode but the header
  row was written unconditionally, injecting a header mid-file on
  every run. Header is now written only when `ftell == 0`.

### 4. Jitter cap for detect_mult == 1 (bfd_tx.c)

RFC 5880 s6.8.7: transmit jitter is 75-100% of the interval, but
75-90% when detect_mult is 1. `fsm_tx` applied 75-100%
unconditionally. Jitter span is now `iv*3/20` when mult is 1, `iv/4`
otherwise. Verified by inspection; the mult-3 path is unchanged and
covered by the regression ladder.

### 5. Trim oversized echo frames (bfd_xdp.c)

The kernel TX path set `bfd->len = 24` but echoed the frame at its
original length, so a peer packet longer than 24 BFD bytes (auth
section, trailer) went back out with trailing bytes. The echo is now
shrunk to eth+ip+udp+24 with `bpf_xdp_adjust_tail`; `tot_len` and
`udp->len` are rewritten and the IP checksum recomputed (the
swap-halves checksum invariance no longer holds once tot_len
changes). On adjust_tail failure the packet is dropped rather than
passed: the frame is half-rewritten by that point and liveness was
already refreshed. The common 66-byte path is untouched: no length
rewrite, no checksum recompute, no added cost.

### 6. README flap-count reconciliation

The document cited bfdd at "44 flaps in 120s", "continuous", and a
107-flap capture without stating these are different load levels (L3
timer storm vs two L4 SCHED_FIFO runs of different durations). One
clarifying paragraph added after the Results table.

### 7. IP-options bypass closed (bfd_xdp.c, commit b3d73ab)

Flagged as open by the review pass. `iph->ihl != 5` returned XDP_PASS,
so a BFD packet carrying IP options (ihl >= 6) skipped the TTL-255 and
your-discriminator drops and reached the userspace socket, where
fsm_rx processed it unvalidated: the same leak class as an XDP_PASS
reject, reachable through the options door. Single-hop BFD control
packets never carry IP options (RFC 5881), so the fix drops them:
UDP + ihl != 5 to the BFD path is now XDP_DROP, counted at stats
idx 3. The port check could not simply be reordered ahead of the ihl
check because with options present the UDP header sits at a variable
offset (iph + ihl*4); dropping optioned UDP outright is correct and
verifier-cheap.

Scope: the drop covers all optioned UDP on the interface, not
just port 3784, because the ihl check precedes the port check (the
port sits at a variable offset once options are present). This is a
deliberate tradeoff over parsing UDP at ihl*4 to narrow the drop:
legitimate optioned UDP on a BFD link is a null set and IP options
are effectively extinct in real traffic.

Verified (docs/refactor-abi/spoof_options.py): 200 optioned packets
(ihl=6, TTL 255, correct discriminators) injected at a live 3x10ms
session. stats idx 3 climbed 0 -> 200 (every packet dropped and
counted), session uptime held across the injection (5:47 -> 6:19, no
reset). Pre-fix these 200 forged-discriminator packets would have
churned the FSM exactly as the m5h leak did. Delivery is proven by the
drop counter itself: count() runs only inside the XDP program, which
only executes on packets that reach the NIC, so idx-3 +200 is
dispositive that 200 optioned packets arrived and all 200 were dropped. Note stats idx 3 (the loader's `rej` counter) aggregates three
reject reasons: your_disc demux, TTL/GTSM, and now ip-options. The
0 -> 200 reading is clean because nothing else was rejecting during
the window; a mixed count would not attribute to options alone.

### 8. Drop connection on bad frame length (bfd_tx.c, commit 91a4b86)

Raised by a second review observation: the bfddp receive loop reset
`dp_have = 0` on a bad frame length but kept the TCP connection open.
bfddp is a length-prefixed stream protocol; once framing is lost,
discarding the buffer and reading more from the same socket resyncs
onto arbitrary mid-stream bytes, which on a channel carrying
ADD/DELETE/UPDATE can misparse into session state changes. Every other
error path in the file (send failure, disconnect, connection replaced)
drops the connection; this branch alone did not. Reference dataplanes
drop and let bfdd reconnect from a clean boundary.

Fixed to match: on a bad length the connection is closed
(dp_conn = -1), the buffer cleared, and dp_sessions_orphan() called,
then bfdd reconnects. The --dp-hold work from m5 makes this safe:
a control-channel reset now orphans sessions and re-adopts them on
reconnect with zero data-plane interruption, so correct framing-error
behavior composes with graceful restart rather than costing an outage.

Under the default --dp-hold 0, dp_sessions_orphan() tears sessions
down (its first branch), so the bad-frame path behaves identically
to every other disconnect in default mode; the hold/adopt behavior
applies only when --dp-hold is set.

Verified (docs/refactor-abi/bad_frame.py): a harness connects to the
dplane listener as a fake bfdd and sends a header with an invalid
length field. Engine logs "bad frame length 0, dropping connection"
and the harness's recv returns b'' (orderly close from the engine),
confirming the connection is dropped rather than resynced. The bad
length landed via the `mlen < sizeof(*h)` half of the guard rather
than the oversized half (harness header offset vs the real bfddp
layout), but both halves lead to the same drop-connection code, so the
branch is exercised. The reconnect+adopt safety half rides on the
m5g-proven orphan/adopt machinery, which the orphan call re-enters
directly.

## Test results

### Full regression (docs/refactor-abi/, regress-abi.pcap)

Stress ladder on bfd-dut, session 3x10ms, kernel-tx mode, host-side
capture. Inter-packet gaps, dut -> peer:

| Level | Load | n | p50 | p99 | p99.9 | max |
|---|---|---|---|---|---|---|
| L1 | 4x cpu | 13697 | 8.80 | 10.01 | 10.49 | 13.50 ms |
| L2 | 8x cpu + switch + yield | 13699 | 8.80 | 10.01 | 10.55 | 12.19 ms |
| L3 | cpu + timer + timerfd + hrtimers | 13713 | 8.72 | 10.02 | 10.49 | 11.53 ms |
| L4 | 4x cpu SCHED_FIFO prio 50 | 6851 | 8.72 | 10.01 | 10.48 | 11.49 ms |

Zero flaps in all stress windows (max gap 13.5ms vs 30ms detect
budget). Matches main's m5 result (L4: 8.75 / 11.0 / 12.5); the
RX-clocked p50 signature is intact, confirming the constant renames
changed nothing on the wire.

Peer-side state transitions in the capture map 1:1 to deliberate
lifecycle events (peer restart, drop-and-recreate double FRR restart,
hold-expiry teardown from a rate-limited first attempt, graceful
restart bring-up, engine stop for the loader test, final bring-up).
None fall inside stress windows.

### Graceful restart (dp-hold window, docs/refactor-abi/hold.txt)

Engine with --dp-hold 30, two back-to-back FRR restarts. Engine log
shows hold + adopt on both cycles (lid 3921861556 -> 2495252149 ->
2086502520). Peer-side transitions inside the window: only the initial
bring-up Init -> Up. Zero peer-visible events across both restarts,
matching the m5 verification.

### FRR notify fix

Peer bfdd restart during the run: dut detect timeout at 32.1ms silent,
FRR tracked the transition both ways (uptime reset, remote ID
changed). The map-path variant of the same transition is
timing-dependent and was not separately provoked; it is four lines
calling the function the timeout path exercised.

### Loader CSV fix

Two consecutive 5s bfd_loader runs on fresh files:
`grep -c epoch events.csv observer.csv` -> 1 and 1.

### Echo trim (docs/refactor-abi/trim.pcap, spoof_long.py)

One valid 76-byte control packet (24 BFD bytes + 10 pad, TTL 255,
correct discriminators) injected from bfd-peer via spoof_long.py.
Capture shows the 76-byte frame arriving at the dut and zero dut-side
frames other than 66 bytes: the echo went out trimmed with a valid
recomputed checksum, and the session stayed up. The injection passing
GTSM and demux and being echoed also re-validates the demux path
adjacent to the edit.

### IP-options bypass (docs/refactor-abi/spoof_options.py)

200 optioned packets injected at a live session: stats idx 3 climbed
0 -> 200, uptime held (5:47 -> 6:19, no reset). Drop counter is the
delivery proof (count() runs only on packets that reach the XDP
program). See section 7.

### Bad frame length (docs/refactor-abi/bad_frame.py)

Fake-bfdd harness sends an invalid-length header: engine logs "bad
frame length 0, dropping connection", harness recv returns b'' (engine
closed the connection). Confirms drop-and-reconnect rather than
mid-stream resync. See section 8.

## Regression note after items 7-8

Neither fix touches the steady-state path: item 7 drops packets that
never occur in normal single-hop operation, item 8 fires only on
malformed frames that bfdd never emits. The L1-L4 ladder in a2425c9
therefore still holds by construction and was not re-run. This is the
one place in the branch where a code change postdates its regression
evidence; the reasoning for not re-capturing is that the hot path is
provably unaffected.

