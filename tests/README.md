# Tests

Three scripts. All run on the engine host and read the BPF maps directly,
because the two verdicts that matter most — `XDP_DROP` and `XDP_TX` — are
both invisible to a capture taken on the DUT.

| Script | Shape | What it proves |
|---|---|---|
| `inject_matrix.py` | 33 single-packet cases | every accept/reject rule the fast path applies |
| `dp_hold.py` | lifecycle | `--dp-hold` keeps sessions up across a bfdd crash |
| `poll_final.py` | observation | a real Poll sequence terminates |

## Running them

    ./tests/inject_matrix.py                 all cases
    ./tests/inject_matrix.py --list          show them without sending
    ./tests/inject_matrix.py --only gtsm-v4  one case
    ./tests/inject_matrix.py --verbose       raw before -> after, not just the delta
    ./tests/inject_matrix.py --json          machine-readable, for a pre-push hook

    ./tests/dp_hold.py
    ./tests/poll_final.py

`--injector`, `--iface`, `--count`, `--settle`, `--unknown-echo` and
`--unknown-echo6` override the lab defaults.

## Testbed prerequisites

The matrix discovers what it can test and **skips** cases whose session is
absent rather than passing vacuously, so a missing prerequisite shows up as
fewer cases, not as green.

- **An injector host** reachable over ssh with passwordless sudo and scapy
  installed. `inject_matrix.py` pipes *itself* there with `--send <json>`
  for each injection, so nothing needs installing on that side.
- **Echo on one session per family.** `echo-mode` on a single-hop v4 and a
  single-hop v6 peer populates `echo_peers`, which is what the reflect and
  echo-GTSM cases key on. FRR refuses `echo-mode` on multihop.
- **Two phantom sessions** — peers configured on the DUT that nothing
  answers on:

        peer 10.66.0.200 multihop local-address <local v4>
         minimum-ttl 200
        peer fd66::200 multihop local-address <local v6>
         minimum-ttl 200

  These carry the positive controls. See "Oracles" below for why.
- **`write memory`** after any of the above, or the next `frrinit.sh`
  restart loses it.

The session cap is 64 and it is architectural (tied to the per-slot source
port range), so free a slot before adding anything.

## Oracles

Three, because no single one covers everything.

**Global counter deltas.** Snapshot `bfd_stats`, inject, settle, snapshot
again. Works for every reject-class case because nothing legitimate touches
those counters — a delta *is* the injection.

**Per-session `rx_pkts`.** Global counters are useless for anything the live
mesh also drives: `well-formed` climbs at roughly 6400/sec here, so an
expected +20 came back +14561 the first time a positive control was tried.
The fix is a session nothing else feeds. A phantom peer never comes up, so
`cfg->enable` stays 0, the TX bounce never fires, nothing is emitted at a
nonexistent host — and its `rx_pkts` moves only when the injector sends.

**Capture.** A counter proves the program reached a `count()` call, not that
a correct frame left the NIC. For the reflect and Poll/Final cases the
injector starts a sniffer, sends, stops, and counts frames whose Ethernet
destination is its own MAC — both paths swap MACs, so replies come back
addressed to the injector even though the IP is the spoofed peer's. Results
ride into the assertion loop as `cap:*` pseudo-counters, so a capture
assertion is written exactly like a counter one.

## Two rules the cases follow

**Every `+0` assertion needs a witness.** `reflected +0` alone cannot tell
"correctly declined" from "the frame never arrived" — and that is not
hypothetical: `echo-unknown-peer` once passed for months because it set an
`l2dst` key `send()` never implemented, so nothing reached the DUT at all.
Every such case now asserts a second counter that must *move*.

**Nothing may disturb a live session.** After the matrix runs, every session
that was alive is checked for `alive`, `remote_disc`, `detect_iv_us`,
`min_tx_us`, `min_rx_us`, `detect_mult` and `peer_mac`. `remote_disc` is the
sharp one: an accepted payload's `my_disc` is exactly what would overwrite
it. The check has been self-tested by inverting its comparison and
confirming it reports.

## Engine changes made for testability

Adding tests required four changes to `bfd_xdp.c`. None alter a verdict; all
add counters to branches that previously fell out with a bare `XDP_PASS`.

| Slot | Name | Why it was added |
|---|---|---|
| 6 | `echo-declined` | both `echo_peers` misses; gives the unknown-peer cases a delivery witness |
| 7 | `echo-not-self` | both `saddr != daddr` returns; **also fires in normal use**, since FRR sources its own v6 echoes at the peer rather than self-addressed |
| 8 | `echo-ttl` | both echo GTSM checks |

`bfd_stats` grew from 6 entries to 9. Slot 1 was renamed from `accepted` to
`well-formed` in the harness: its `count(1)` sits *before* the GTSM and
demux drops, so a rejected packet increments slot 1 and slot 3 both.

Slots 2, 3 and 6 should stay flat on an idle link. Slots 0, 1, 4, 5 and 7 do
not.

Note the map grew, so a rebuilt program must actually be reattached — a
stale attach against the new harness fails on the missing indices.

## What is covered

Run `--list` for the current set. By group:

- **GTSM** — single-hop below 255 rejected, both families; multihop below
  its negotiated minimum rejected, both families; a low TTL at a single-hop
  session while multihop is live still rejected (the case the whole
  multihop design rests on); multihop *at* the minimum accepted.
- **Demux** — `your_disc` naming no session of ours, both families.
- **Malformed headers** — bad version, zero `my_discriminator`, zero detect
  multiplier, length below the 24-byte minimum, length overrunning the UDP
  payload, header truncated. Both families. Each breaks exactly one rule
  with everything else well-formed, so each isolates its own check even
  though all six share one counter.
- **Echo** — reflected for a peer of an echo-active session; declined for a
  peer we do not serve; not reflected when not self-addressed; not
  reflected below TTL 255. Both families, and the reflect cases assert the
  reply on the wire.
- **Accept path** — a well-formed packet reaches the session state update;
  trailing bytes past the BFD payload do not confuse the parser. Both
  families, against the phantoms.
- **Poll/Final** — a packet with P set is answered with F, verified by
  capture.

## Known limits

- The matrix cannot express anything stateful across packets. `--dp-hold`
  and Poll-sequence termination are separate scripts for that reason.
- `poll_final.py` observes rather than injects: `cfg->poll` is only mirrored
  for a session in `ST_UP`, so a phantom never polls, and on a live session
  the real peer answers within milliseconds so an injected F could not be
  attributed. It changes `transmit-interval` on a live session and restores
  it — without `write memory`, so a botched restore lasts only until the
  next reload.
- `dp_hold.py` must use SIGKILL. A clean bfdd shutdown DELETEs every session
  first, so there is nothing left to hold; `--dp-hold` is for the unclean
  case.
- IPv6 has no analogue of the `ip-options` case. The v4 `ihl != 5` check is
  real hardening because options shift the UDP header; IPv6 has no
  variable-length base header, so an extension header simply makes
  `nexthdr != UDP` and falls out of the top-level dispatch, deliberately.
