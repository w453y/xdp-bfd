#!/usr/bin/env python3
"""Graceful restart check for --dp-hold.

--dp-hold does not survive an engine restart; it survives the bffdp
connection dropping. When bfdd goes away the engine orphans its wire
sessions and keeps transmitting for the hold window instead of tearing
them down, so a control-plane restart is invisible to the neighbour.

The neighbour is therefore the judge: it has no idea our bfdd restarted,
and its own session-down counters are what a flap would show up in. This
restarts bfdd on the DUT and asserts the peer recorded nothing.

Cannot run inside inject_matrix.py: restarting bfdd would wreck every
counter delta there. Run it separately.
"""

import os
import json
import subprocess
import sys
import time

PEER_HOST = "w453y@10.66.0.2"

# The peer-side read must use w453y's keys even when this script runs under
# sudo, which it must for the SIGKILL. root has no key on the peer and its
# HOME is /root, so a plain ssh from here fails on publickey - and the peer
# is the only witness that can say whether a flap happened, so losing it
# turns a failed run into one that prints nothing and looks fine.
SSH = ("sudo -u w453y -H ssh" if os.geteuid() == 0 else "ssh") + \
      " -o BatchMode=yes"
VTYSH = "/opt/frr-master/bin/vtysh"
SETTLE = 25


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def peer_downs():
    """(peer, local) -> session-down, as the neighbour sees it."""
    r = sh(SSH + " %s \"sudo vtysh -c 'show bfd peers "
           "counters json'\"" % PEER_HOST)
    if r.returncode:
        sys.exit("cannot read peer counters: %s" % (r.stderr.strip() or "?"))
    return {(e["peer"], e["local"]): e.get("session-down", 0)
            for e in json.loads(r.stdout)}


def dut_up():
    r = sh("sudo %s -c 'show bfd peers brief'" % VTYSH)
    return sum(1 for line in r.stdout.splitlines()
               if line.split()[3:4] == ["up"])


def main():
    hold = sh("pgrep -a -x bfd_tx").stdout
    if "--dp-hold" not in hold:
        sys.exit("engine is not running with --dp-hold: %s" % hold.strip())

    before_up = dut_up()
    before = peer_downs()
    print("before: %d sessions up on the DUT, %d known to the peer"
          % (before_up, len(before)))

    logmark = sh("wc -l < /tmp/eng_run.log").stdout.strip()
    # SIGKILL, not SIGTERM. A clean bfdd shutdown DELETEs every session
    # first, so the engine removes them and there is nothing left to hold;
    # --dp-hold is for the unclean case, where the socket simply drops.
    print("killing bfdd (watchfrr will bring it back)")
    sh("sudo pkill -KILL -x bfdd")

    held = None
    for _ in range(10):
        time.sleep(1)
        tail = sh("tail -n +%s /tmp/eng_run.log" % logmark).stdout
        if "holding" in tail:
            held = [l for l in tail.splitlines() if "holding" in l][-1]
            break
    if held:
        print("engine: %s" % held.strip())
    else:
        print("WARNING: engine never logged a hold; is --dp-hold in effect?")

    print("waiting %ds for reconnect and reconciliation" % SETTLE)
    time.sleep(SETTLE)

    after_up = dut_up()
    after = peer_downs()

    failures = 0
    for k, v in before.items():
        if after.get(k, v) != v:
            print("FAIL %s -> %s recorded %d new down event(s)"
                  % (k[1], k[0], after[k] - v))
            failures += 1
    if after_up < before_up:
        print("FAIL DUT has %d sessions up, was %d" % (after_up, before_up))
        failures += 1

    print()
    if failures:
        print("%d problem(s): the restart was visible to the neighbour"
              % failures)
        return 1
    print("bfdd restarted, %d sessions up, peer saw no flap" % after_up)
    return 0


if __name__ == "__main__":
    sys.exit(main())
