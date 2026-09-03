"""What happens to a session when the engine dies.

Two claims, asserted separately:

  link-detaches-on-death      SIGKILL closes the bpf_link and the program
                              leaves the interface
  peer-detects-on-own-budget  the surviving peer times out on its own
                              detect budget, since the wire goes silent

Neither is the wedged-but-alive case: with --kernel-tx active XDP answers
the peer from softirq regardless of userspace state, so an engine that
wedges without dying keeps the peer Up. Killing a process cannot test
that; tests/wedged_ktx.py covers it.

No tight timing bound here. The engine records last_overshoot_us for
diag 1 and the test asserts it exists and is sane; thresholds belong in
the perf harness.
"""

import time

import pytest

from conftest import (NS_A, NS_B, STATS, STATS_B, DOWN_WAIT, sh, setup,
                      teardown, ns_pids, start_engine, wait_both_up,
                      xdp_progs, only_session, engine_tails)

OVERSHOOT_SANITY_US = 50_000


@pytest.fixture(scope="module")
def death(request):
    """Bring both engines up, kill the kernel-tx side, capture everything
    the two tests below assert on. One run, two named assertions, no
    ordering dependency between them."""
    root = request.config.rootpath
    binary = str(root / "bfd_tx")
    obj = str(root / "bfd_xdp.o")

    setup()
    try:
        start_engine(binary, 4, ns=NS_A, stats=STATS,
                     kernel_tx="rig-a", xdp_mode="generic",
                     extra=("--bpf-obj", obj))
        start_engine(binary, 4, ns=NS_B, stats=STATS_B)
        wait_both_up()

        res = {"before": xdp_progs(NS_A, "rig-a")}

        for pid in ns_pids(NS_A):
            sh("sudo kill -KILL %d" % pid, check=False)
        killed = time.time()
        # The detach read needs a moment for the link to close, but it
        # must NOT sit between the kill and the detection loop below:
        # detection completes in ~30ms at these timers, so half a second
        # here meant the loop always found the session already Down and
        # elapsed_s could never read under 500ms. Detach is checked after
        # the loop instead.
        res["down"] = False
        end = time.time() + DOWN_WAIT
        while time.time() < end:
            s = only_session(NS_B, STATS_B)
            # state is a STRING here ("Up", "Down"), not an int.
            if s["state"] != "Up":
                res["down"] = True
                res["elapsed_s"] = time.time() - killed
                res["session"] = s
                break
            time.sleep(0.1)
        else:
            res["tails"] = engine_tails()
        time.sleep(0.5)
        res["after"] = xdp_progs(NS_A, "rig-a")
        yield res
    finally:
        if not request.config.getoption("--keep-ns"):
            teardown()


def test_link_detaches_on_death(death):
    assert len(death["before"]) == 1, (
        "expected one attached program before the kill, got %r"
        % death["before"])
    assert death["after"] == [], (
        "program still attached after SIGKILL: %r" % death["after"])


def test_peer_detects_on_own_budget(death):
    assert death["down"], (
        "peer still Up %.0fs after the engine died\n%s"
        % (DOWN_WAIT, death.get("tails", "")))
    s = death["session"]
    assert s["diag"] == 1, (
        "expected diag 1 (control detection expired), got %s (%s)"
        % (s["diag"], s.get("last_reason")))
    overshoot = s["last_overshoot_us"]
    assert 0 < overshoot < OVERSHOOT_SANITY_US, (
        "implausible overshoot %sus" % overshoot)
    # elapsed_s is an UPPER BOUND, not a detection time: each poll
    # costs a SIGUSR1 round trip plus the 0.1s sleep between polls, so
    # it reads a few hundred ms against a ~30ms budget. last_overshoot_us
    # is the engine's own measurement and is the number that means
    # something.
    print("peer Down within %.0fms (harness-bound), overshoot %.2fms"
          % (death["elapsed_s"] * 1000, overshoot / 1000.0))
