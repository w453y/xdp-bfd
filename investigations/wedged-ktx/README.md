# Kernel-TX carries sessions through a stopped userspace

Date: 2026-08-30
Branch: `review-fixes`
Script: `tests/wedged_ktx.py` (`c9e8cfd`)
Evidence: `run-10s.txt`, `run-60s.txt`, `loop-rate-baseline.txt`

With `--kernel-tx` active, 57 BFD sessions stayed Up for 60 seconds while the
engine's userspace process was stopped dead. The peer kept receiving control
packets throughout and recorded zero state transitions. 60 seconds is roughly
2000 times the negotiated 30ms detect budget.

This is the *wedged-but-alive* case, and it had never been tested.

---

## 1. What was measured

```
baseline: 59 of 59 up, kernel_tx True
STOP pid 1195269: stat T
after 60s: stat T, resumed

peer, over the 60s window (57 sessions)
  session-down       +0
  session-up         +0
  control-pkt-input  57 climbing, 0 flat
```

`stat T` at both ends of the window is the proof the process really was
stopped, taken from `ps -o stat=` rather than inferred. The same run at 10
seconds gives the same result (`run-10s.txt`).

57 rather than 59 because the DUT has 59 configured peers and the peer host
has 61; the four extra are stale peer-side config from mesh slots freed on the
DUT for the multihop sessions. Those four have never been up and contribute
nothing. The script only reads sessions that exist on both ends.

## 2. What this establishes, and what it does not

**Established.** With kernel-TX enabled, a session's liveness signal is
produced entirely in softirq by the XDP program. Userspace progress is not
required to keep a peer believing the session is healthy. BFD exists to detect
that a neighbour has stopped forwarding; this engine will report health while
its control plane is making no progress at all.

**Not established.** That a real wedge can occur. SIGSTOP is a synthetic
stand-in for a stuck loop. The one known mechanism that could wedge the loop —
the unbounded `MSG_DONTWAIT` receive drains — was fixed by `88a1eef`.

So this is a demonstrated *consequence* with no demonstrated *cause*. The
distinction matters: "the engine reports health while its control plane is
dead" and "the engine can be made to do so by an external SIGSTOP" are
different claims, and only the second is proven end to end.

**What `88a1eef` did and did not do.** It bounded each receive drain per loop
pass, 17 insertions in `main.c` only. That removed one *cause* of a wedged
loop, not the class. The dead-man switch was dropped at the time on the
reasoning that `bpf_link` (`13819dd`) handles process death — which it does,
correctly and provably: SIGKILL closes the link and the program leaves the
interface. Process death is simply not this case. The earlier note that the
dead-man was "unnecessary" was over-scoped, and this run is the evidence.

## 3. The open design question

This is not obviously a bug, and the write-up should not pretend otherwise.

RX-clocked kernel TX exists *precisely so that the dataplane keeps answering
when userspace is degraded*. That property is what the headline result rests
on: 0 flaps under CPU stress against bfdd's 44. A dead-man switch that
disabled the bounce whenever userspace went quiet would reintroduce exactly
the failure mode the design was built to avoid, with a longer threshold.

So the real question is not "is this a defect" but "where is the boundary".
At what point does *userspace is slow* become *userspace is gone*? The design
currently draws no line at all, and the answer is not obvious:

- Too short a threshold and ordinary scheduling jitter kills sessions the
  design is meant to protect.
- Too long and the engine reports health during an outage for that long.
- No threshold, which is today, means it reports health indefinitely.

A dead-man would be a counter userspace bumps each pass, read by the sweep,
with the bounce disabled once it goes stale. Roughly the shape sketched when
finding 1 was fixed. Choosing the staleness threshold is the whole design
problem and it needs a number nobody has picked.

## 4. Instrument: why SIGSTOP, after three things that did not work

The loop is **not CPU-bound**. It sleeps on a timer, wakes for microseconds,
and sleeps again: 504 passes/s at roughly 2ms each (`loop-rate-baseline.txt`).
It never wants a meaningful share of a CPU, so nothing that competes for CPU
or caps CPU has any effect.

| Instrument | Result |
|---|---|
| `stress-ng --cpu 4 --sched fifo --sched-prio 50` | 504 → 429 passes/s |
| `stress-ng --cpu 16 --sched fifo --sched-prio 90` | 504 → 385 passes/s |
| cgroup `cpu.max` at a hard 5% | 504 → **505** passes/s |

The 16-worker run is the informative failure: the stress itself took 80
seconds to finish a 20-second timeout. With `sched_rt_runtime_us` at 950000
per 1000000 period, sixteen FIFO workers on four CPUs share 95% of the machine
and each gets throttled — the RT throttle was slowing *stress-ng*, not the
engine. Oversubscribing made the stressor worse, not the target quieter.

The cgroup result is the conclusive one. The engine runs SCHED_OTHER priority
0; a 5% hard quota applied cleanly (`cpu.max` read back `5000 100000`) and
changed the loop rate by 1 pass/s. A quota only bites a process that wants
more than the quota.

Getting the engine into its own cgroup at all required restarting it under
`systemd-run --unit=bfd-engine --scope --slice=bfd`, and then
`systemctl set-property --runtime bfd-engine.scope CPUQuota=5%` rather than
writing `cpu.max` directly — the `cpu` controller was not in
`bfd.slice/cgroup.subtree_control`, so a direct write returned EACCES even as
root. All of that effort measured the wrong resource.

**SIGSTOP** stops userspace dead while the process stays alive and its
`bpf_link` stays open. That is exactly the state under test, and it is
deterministic rather than emergent.

## 5. Measurement pitfalls hit along the way

**`loop_passes` cannot measure the window.** A stopped process cannot answer
SIGUSR1, so any snapshot must be taken after CONT — by which point the resumed
engine has drained its backlog. A 5-second stopped window measured `+677`
passes this way. The number is real; it just describes the second *after* the
window, not the window. The fix is to not measure the DUT across the window at
all: `ps -o stat=` proves the stop, and everything else comes from the peer.

**Read the peer while the engine is still stopped.** Reading after CONT lets a
session that dropped and recovered inside the window look untouched. The
script closes the window by sampling the peer before issuing CONT.

**`session-down` as a delta, not a state sample.** A single state reading
cannot see a flap that healed. This is on record from the echo6 topotest,
where a standalone stability test passed against unpatched code because a
~1.3s flap cycle spends most of its time up.

**Signal the pid, not the process group.** An early attempt suspended the
backgrounded `sudo systemd-run` wrapper instead of the engine, and the run
reported 39 of 59 sessions still transmitting — i.e. a healthy engine while
something else was frozen. Same shape as the wrapper trap already documented
in `tests/lib/netns.py`. The `stat T` check exists because of this.

## 6. Reproducing

```sh
# needs the mesh fully up and --kernel-tx active; the script refuses otherwise
python3 tests/wedged_ktx.py --seconds 10
python3 tests/wedged_ktx.py --seconds 60
```

Both refuse to run unless `sessions_up == sessions_configured` and
`kernel_tx` is true, and both abort if the process does not reach `T` or does
not stay there. Peer access is passwordless ssh to `w453y@10.66.0.2` with
`sudo vtysh` there.

Restore afterwards and confirm 59 up on the DUT and 57 on the peer before
trusting any later result — RT experiments on this mesh have produced
surprises before.

## 7. Status

Open. Demonstrated, not fixed, and deliberately so: the fix is a threshold
nobody has chosen yet, and choosing it wrong costs the property the whole
design exists for. The README's claim about detection under stress remains
accurate for the case it describes; what has no line in the README is what
happens when userspace stops entirely.

