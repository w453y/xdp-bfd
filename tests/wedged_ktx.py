#!/usr/bin/env python3
"""Does kernel-TX keep sessions Up while userspace makes no progress?

The wedged-but-alive case. 88a1eef bounded the receive drains, which
removed one CAUSE of a wedged loop, not the class: with --kernel-tx
active, XDP answers the peer from softirq regardless of userspace state,
so an engine that stops making progress WITHOUT dying should keep its
sessions up indefinitely. That has never been tested.

INSTRUMENT: SIGSTOP. Three others were tried and none works.
  stress-ng, 4 FIFO workers at prio 50   504 -> 429 passes/s
  stress-ng, 16 workers at prio 90       504 -> 385 passes/s, and the
                                         stress itself took 80s for a
                                         20s timeout - the RT throttle
                                         was slowing stress-ng, not the
                                         engine
  cgroup cpu.max at a hard 5%            504 -> 505 passes/s, no effect
The loop is not CPU-bound: it sleeps on a timer, wakes for microseconds,
sleeps again. It never wanted 5% of a CPU, so throttling CPU does
nothing. SIGSTOP stops userspace dead while the process stays alive and
its bpf_link stays open, which is exactly the case under test.

MEASUREMENT: entirely from the peer. A stopped engine cannot answer
SIGUSR1, so nothing about the window can be read from its snapshot -
loop_passes read after CONT includes the resumed engine draining its
backlog and is not a window measurement. The DUT's only job here is to
prove it was stopped, which `ps -o stat=` reading T does directly.

session-down is a DELTA per session, not a state sample: a session that
flapped and recovered inside the window is invisible to a single sample.
That trap is on record from the echo6 topotest.

    python3 tests/wedged_ktx.py --seconds 10
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_ladder as sl          # noqa: E402


def peer_counters():
    # sweep_ladder.VTYSH, not a bare name: the peer also carries a distro
    # vtysh whose daemons are not running, and that one answers "failed to
    # connect to any daemons", which the caller cannot tell from a mesh
    # that is simply empty.
    out = sl.peer_sh("sudo %s -c 'show bfd peers counters json'" % sl.VTYSH)
    return {(s["peer"], s["local"]): s for s in json.loads(out)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=10,
                    help="stop window; anything past the 30ms budget does")
    args = ap.parse_args()

    d0 = sl.dump()
    print("baseline: %d of %d up, kernel_tx %s"
          % (d0["sessions_up"], d0["sessions_configured"], d0.get("kernel_tx")))
    if d0["sessions_up"] != d0["sessions_configured"]:
        print("REFUSING: mesh is not fully up")
        return 1
    if not d0.get("kernel_tx"):
        print("REFUSING: kernel_tx is false; this arm needs it")
        return 1

    ours = {(s["peer"], s["local"]) for s in d0["sessions"]}

    # Not `pgrep -x bfd_tx | head -1`. A previous run can leave a defunct
    # engine behind (see below), and pgrep lists it first by pid order, so
    # the run would STOP a corpse and measure a healthy mesh through it.
    pid = ppid = None
    for line in sl.sh("ps -eo pid=,ppid=,stat=,comm=").splitlines():
        f = line.split()
        if len(f) == 4 and f[3] == "bfd_tx" and not f[2].startswith("Z"):
            pid, ppid = int(f[0]), int(f[1])
            break
    if pid is None:
        print("REFUSING: no live bfd_tx")
        return 1

    p0 = peer_counters()
    sl.sh("sudo kill -STOP %d" % pid)
    stat_in = sl.sh("ps -o stat= -p %d" % pid).strip()
    print("STOP pid %d: stat %s" % (pid, stat_in))
    if not stat_in.startswith("T"):
        sl.sh("sudo kill -CONT %d" % pid, check=False)
        print("REFUSING: process is not stopped")
        return 1
    try:
        time.sleep(args.seconds)
        stat_out = sl.sh("ps -o stat= -p %d" % pid).strip()
        # Peer read WHILE the engine is still stopped, so the window is
        # closed before anything can recover and hide a flap.
        p1 = peer_counters()
    finally:
        # The parent as well as the engine. The engine is started under
        # sudo, and sudo follows job-control convention: when the child it
        # is waiting on stops, it stops itself, so the shell sees the whole
        # job stopped. Resuming only the child leaves sudo in T for good,
        # and a stopped parent cannot reap - so the next `pkill -x bfd_tx`
        # produces a defunct engine that never goes away and that pgrep
        # then hands to the following run. Costs nothing when the parent
        # was never stopped.
        sl.sh("sudo kill -CONT %d" % pid)
        sl.sh("sudo kill -CONT %d" % ppid, check=False)
    print("after %ds: stat %s, resumed" % (args.seconds, stat_out))
    if not stat_out.startswith("T"):
        print("REFUSING: process did not stay stopped")
        return 1

    # Classified per session, not summed. "The peer received something"
    # is not the question: a gate that answers for its first second and
    # then stops still moves that counter, and the run would read as a
    # session carried all the way through. What separates the two is
    # whether the peer ever concluded the session was down.
    downs = ups = 0
    carried = dropped = silent = 0
    for peer, local in ours:
        a, b = p0.get((local, peer)), p1.get((local, peer))
        if not a or not b:
            continue
        dd = b["session-down"] - a["session-down"]
        downs += dd
        ups += b["session-up"] - a["session-up"]
        drx = b["control-packet-input"] - a["control-packet-input"]
        if dd:
            dropped += 1
        elif drx > 0:
            carried += 1
        else:
            silent += 1

    print("\npeer, over the %ds window (%d sessions)"
          % (args.seconds, carried + dropped + silent))
    print("  session-down       +%d" % downs)
    print("  session-up         +%d" % ups)
    print("  carried            %d  (heard from, never declared down)"
          % carried)
    print("  dropped            %d  (peer declared down)" % dropped)
    print("  silent             %d  (no traffic either way)" % silent)

    print("\nverdict")
    if not carried and not dropped:
        print("  peer sent nothing; the window measured nothing")
        return 1

    # Not "any down event at all". The mesh is two populations, and only
    # one of them is under test: sessions the fast path carries, where
    # XDP answers from softirq, and sessions it does not, which transmit
    # from the loop and are SUPPOSED to go down the moment the loop
    # stops. Counting a down event from the second population as a
    # refutation reads the control group as the result - it reported
    # "unfounded" off 4 userspace-TX sessions while 55 kernel-TX ones sat
    # there being carried, which is the finding, not the noise.
    if carried:
        print("  %d session(s) stayed Up for %ds with userspace stopped,"
              " the peer still receiving." % (carried, args.seconds))
        print("  Kernel-TX alone carried them: WEDGED-BUT-ALIVE IS REAL,")
        print("  and 88a1eef did not close it.")
        if dropped:
            print("  (%d went down: sessions the fast path does not carry"
                  " transmit from the loop, so a stopped loop takes them"
                  " down. That is the control arm working.)" % dropped)
    else:
        print("  nothing was carried: every session the peer was hearing"
              " from went down inside the window.")
        print("  A stopped engine is visible to its peers, which is what"
              " the dead-man gate is for. Check stats.deadman-hold on the"
              " DUT to confirm the gate is what did it rather than some"
              " unrelated breakage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
