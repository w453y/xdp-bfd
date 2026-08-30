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
    out = sl.peer_sh("sudo vtysh -c 'show bfd peers counters json'")
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
    pid = int(sl.sh("pgrep -x bfd_tx").split()[0])

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
        sl.sh("sudo kill -CONT %d" % pid)
    print("after %ds: stat %s, resumed" % (args.seconds, stat_out))
    if not stat_out.startswith("T"):
        print("REFUSING: process did not stay stopped")
        return 1

    downs = ups = rx_moved = rx_flat = 0
    for peer, local in ours:
        a, b = p0.get((local, peer)), p1.get((local, peer))
        if not a or not b:
            continue
        downs += b["session-down"] - a["session-down"]
        ups += b["session-up"] - a["session-up"]
        if b["control-packet-input"] > a["control-packet-input"]:
            rx_moved += 1
        else:
            rx_flat += 1

    print("\npeer, over the %ds window (%d sessions)"
          % (args.seconds, rx_moved + rx_flat))
    print("  session-down       +%d" % downs)
    print("  session-up         +%d" % ups)
    print("  control-pkt-input  %d climbing, %d flat" % (rx_moved, rx_flat))

    print("\nverdict")
    if rx_flat and not rx_moved:
        print("  peer sent nothing; the window measured nothing")
        return 1
    if downs == 0:
        print("  %d sessions stayed Up for %ds with userspace stopped,"
              " while the peer kept receiving." % (rx_moved, args.seconds))
        print("  Kernel-TX alone carried them: WEDGED-BUT-ALIVE IS REAL,")
        print("  and 88a1eef did not close it.")
    else:
        print("  %d down event(s): kernel-TX did NOT carry the sessions"
              " through a stopped userspace." % downs)
        print("  The wedged-but-alive concern is unfounded on this path.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
