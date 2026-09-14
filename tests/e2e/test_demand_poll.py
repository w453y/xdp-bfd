"""A demanding session verifies its own path (RFC 5880 s6.6).

While a system is demanding, its detection timer does not run: it told
the peer to go quiet, so silence is what it asked for and cannot be read
as a fault. Nothing then ever takes the session down, and it reports Up
against a peer that may be long gone. That is not theoretical - changing
an authentication key on one end of the 64-session mesh took down every
authenticated session except the one demanding at both ends, which stayed
Up against a key it could no longer have verified.

s6.6 leaves the timing to the implementation ("MAY send a Poll Sequence"),
and stock bfdd reaches bfd_set_polling only from a parameter change, so in
practice never does.

Both arms, because "it went Down while the peer was silenced" is equally
well explained by any session with a running detection timer. With
--demand-poll-us 0 the same silence produces nothing at all, which is the
behaviour this replaces.
"""

import time

import pytest

from conftest import (NS_A, NS_B, STATS, STATS_B, sh, setup, teardown,
                      ns_pids, start_engine, wait_both_up, only_session)

# Comfortably past one poll interval plus A's detect budget, and long
# enough that the disarmed arm is a real wait rather than a near miss.
SILENCE_S = 8.0


def run_arm(rootpath, poll_us):
    binary = str(rootpath / "bfd_tx")
    obj = str(rootpath / "bfd_xdp.o")

    setup()
    try:
        # A demands; B does not. A's detection is therefore held while B,
        # having been asked to, stops transmitting - so A is the end that
        # cannot see B disappear. Demanding at both ends is the same
        # thing twice; this is the smaller case that still has the bug.
        start_engine(binary, 4, ns=NS_A, stats=STATS,
                     kernel_tx="rig-a", xdp_mode="generic",
                     extra=("--bpf-obj", obj, "--demand",
                            "--demand-poll-us", str(poll_us)))
        start_engine(binary, 4, ns=NS_B, stats=STATS_B)
        wait_both_up()

        # Wait for demand to actually engage before measuring. Up is not
        # enough: the D bit goes out only once both ends are Up, and the
        # announcement quota has to clear before transmission ceases.
        held = False
        for _ in range(50):
            s = only_session(NS_A, STATS)
            if s["demand"]["detect_held"]:
                held = True
                break
            time.sleep(0.2)
        assert held, "demand never engaged on A: %r" % (s["demand"],)

        polls0 = s["demand_polls"]
        # Kill B outright rather than filtering: B is not transmitting
        # anyway, so what has to disappear is its ANSWER to A's poll.
        for pid in ns_pids(NS_B):
            sh("sudo kill -KILL %d" % pid, check=False)

        t0 = time.time()
        while time.time() - t0 < SILENCE_S:
            s = only_session(NS_A, STATS)
            if s["state"] != "Up":
                s["took_s"] = time.time() - t0
                return s
            time.sleep(0.2)
        s["took_s"] = None
        s["polls_delta"] = s["demand_polls"] - polls0
        return s
    finally:
        teardown()


@pytest.fixture(scope="module")
def arms(request):
    root = request.config.rootpath
    try:
        yield {"armed": run_arm(root, 1000000),
               "disarmed": run_arm(root, 0)}
    finally:
        if not request.config.getoption("--keep-ns"):
            teardown()


def test_a_demanding_session_notices_its_peer_is_gone(arms):
    s = arms["armed"]
    assert s["took_s"] is not None, (
        "session still Up %.0fs after the peer died, having started %d"
        " poll(s): the verification is not running"
        % (SILENCE_S, s.get("polls_delta", 0)))
    assert s["demand_polls"] > 0, (
        "session went down without ever polling, so something other than"
        " the verification did it: reason %r" % s.get("last_reason"))
    assert s["diag"] == 1, (
        "expected diag 1 - the poll re-arms detection and the missing"
        " Final expires it - got %s (%r)" % (s["diag"], s.get("last_reason")))


def test_without_the_poll_it_does_not(arms):
    s = arms["disarmed"]
    assert s["took_s"] is None, (
        "session went down in %.2fs with polling off, so the armed arm"
        " proves nothing about the poll: reason %r"
        % (s["took_s"], s.get("last_reason")))
    assert s["demand_polls"] == 0, (
        "polling off but %d poll(s) started" % s["demand_polls"])
