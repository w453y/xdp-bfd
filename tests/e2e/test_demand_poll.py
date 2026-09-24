"""RFC 5880 s6.6: detection is held while demanding, so the periodic Poll is what
takes the session down when the peer vanishes; with --demand-poll-us 0 nothing
does.
"""

import time

import pytest

from conftest import (
    NS_A,
    NS_B,
    STATS,
    STATS_B,
    sh,
    setup,
    teardown,
    ns_pids,
    start_engine,
    wait_both_up,
    only_session,
)

# One poll interval plus A's detect budget.
SILENCE_S = 8.0


def run_arm(rootpath, poll_us):
    binary = str(rootpath / "bfd_tx")
    obj = str(rootpath / "bfd_xdp.o")

    setup()
    try:
        # A demands, so its detection is held: it cannot see B go.
        start_engine(
            binary,
            4,
            ns=NS_A,
            stats=STATS,
            kernel_tx="rig-a",
            xdp_mode="generic",
            extra=("--bpf-obj", obj, "--demand", "--demand-poll-us", str(poll_us)),
        )
        start_engine(binary, 4, ns=NS_B, stats=STATS_B)
        wait_both_up()

        # D goes out only with both ends Up, and the quota must clear.
        held = False
        for _ in range(50):
            s = only_session(NS_A, STATS)
            if s["demand"]["detect_held"]:
                held = True
                break
            time.sleep(0.2)
        assert held, "demand never engaged on A: %r" % (s["demand"],)

        polls0 = s["demand_polls"]
        # B is silent anyway; what disappears is its answer to A's poll.
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
        yield {"armed": run_arm(root, 1000000), "disarmed": run_arm(root, 0)}
    finally:
        if not request.config.getoption("--keep-ns"):
            teardown()


def test_a_demanding_session_notices_its_peer_is_gone(arms):
    s = arms["armed"]
    assert s["took_s"] is not None, (
        "session still Up %.0fs after the peer died, having started %d"
        " poll(s): the verification is not running"
        % (SILENCE_S, s.get("polls_delta", 0))
    )
    assert s["demand_polls"] > 0, (
        "session went down without ever polling, so something other than"
        " the verification did it: reason %r" % s.get("last_reason")
    )
    assert s["diag"] == 1, (
        "expected diag 1 - the poll re-arms detection and the missing"
        " Final expires it - got %s (%r)" % (s["diag"], s.get("last_reason"))
    )


def test_without_the_poll_it_does_not(arms):
    s = arms["disarmed"]
    assert s["took_s"] is None, (
        "session went down in %.2fs with polling off, so the armed arm"
        " proves nothing about the poll: reason %r"
        % (s["took_s"], s.get("last_reason"))
    )
    assert s["demand_polls"] == 0, (
        "polling off but %d poll(s) started" % s["demand_polls"]
    )
