"""An orderly shutdown is announced, not discovered.

test_engine_death.py pins SIGKILL: the wire goes silent and the peer times
out on its own budget, reporting diag 1, control detection expired. That is
correct for a process that was shot, and wrong for `systemctl stop`, which
is the common case and sends SIGTERM.

The companion claim is asserted as a DIAGNOSTIC, not a stopwatch. "Faster
than the detect budget" is what this is really about, but measuring it from
here cannot show it: each poll costs a SIGUSR1 round trip plus a sleep, so
the harness bound reads in hundreds of milliseconds against a ~30ms budget
either way - the same trap test_peer_detects_on_own_budget documents. What
separates the two paths exactly, and with no timing at all, is which code
put the session down. diag 3 (RFC 5880 s6.8.6, neighbour signalled session
down) can ONLY come from a packet that arrived saying so, and diag 1 can
only come from a timer that expired. A session down with diag 3 is proof
the peer was told, and being told is what makes it fast.
"""

import time

import pytest

from conftest import (NS_A, NS_B, STATS, STATS_B, DOWN_WAIT, sh, setup,
                      teardown, ns_pids, start_engine, wait_both_up,
                      only_session, engine_tails)


@pytest.fixture(scope="module")
def term(request):
    root = request.config.rootpath
    binary = str(root / "bfd_tx")
    obj = str(root / "bfd_xdp.o")

    setup()
    try:
        # The kernel-tx side is the one that gets the signal, because it
        # is the side with something to go wrong: XDP answers from
        # softirq, so a shutdown that only stops the loop would leave the
        # fast path replying into the gap. The epilogue has to run before
        # the link closes, and the peer has to see AdminDown rather than
        # silence.
        start_engine(binary, 4, ns=NS_A, stats=STATS,
                     kernel_tx="rig-a", xdp_mode="generic",
                     extra=("--bpf-obj", obj))
        start_engine(binary, 4, ns=NS_B, stats=STATS_B)
        wait_both_up()

        for pid in ns_pids(NS_A):
            sh("sudo kill -TERM %d" % pid, check=False)

        res = {"down": False}
        end = time.time() + DOWN_WAIT
        while time.time() < end:
            s = only_session(NS_B, STATS_B)
            if s["state"] != "Up":
                res["down"] = True
                res["session"] = s
                break
            time.sleep(0.1)
        else:
            res["tails"] = engine_tails()
        yield res
    finally:
        if not request.config.getoption("--keep-ns"):
            teardown()


def test_sigterm_brings_the_peer_down(term):
    assert term["down"], (
        "peer still Up %.0fs after SIGTERM\n%s"
        % (DOWN_WAIT, term.get("tails", "")))


def test_sigterm_announces_rather_than_going_silent(term):
    s = term["session"]
    assert s["diag"] == 3, (
        "peer went down with diag %s (%r), not 3 - it timed the engine"
        " out instead of being told, which is the SIGKILL path and the"
        " outcome the epilogue exists to avoid"
        % (s["diag"], s.get("last_reason")))
