"""An orderly shutdown is announced. On SIGTERM the peer goes down with diag
3 (neighbour signalled down, RFC 5880 s6.8.6), which only a received
AdminDown produces; SIGKILL yields diag 1 (test_engine_death.py).
Asserted by diagnostic, since the harness cannot resolve the timing.
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
        # Signal the kernel-tx side: XDP would keep replying after the loop
        # stops, so AdminDown must go out before the link closes.
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
