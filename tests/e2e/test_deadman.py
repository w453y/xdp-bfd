"""The dead-man gate, armed and disarmed, in two namespaces.

  armed     engine A is SIGSTOPped, XDP stops answering for it, and B goes
            Down on its own detection timer
  disarmed  the same stop with --deadman-us 0, and B stays Up, since XDP
            keeps answering for the stopped engine

The disarmed arm shows it is the gate, not the stop, that takes B down.
SIGSTOP freezes userspace while the process and its bpf_link stay alive.
"""

import time

import pytest

from conftest import (NS_A, NS_B, STATS, STATS_B, sh, setup, teardown,
                      ns_pids, start_engine, wait_both_up, only_session,
                      dump)

# Past the 1s bound plus B's 30ms detect budget.
STOP_S = 4.0


def run_arm(rootpath, deadman):
    """Stop A for STOP_S with the gate set as given, and report B."""
    binary = str(rootpath / "bfd_tx")
    obj = str(rootpath / "bfd_xdp.o")

    setup()
    try:
        start_engine(binary, 4, ns=NS_A, stats=STATS,
                     kernel_tx="rig-a", xdp_mode="generic",
                     extra=("--bpf-obj", obj, "--deadman-us", str(deadman)))
        start_engine(binary, 4, ns=NS_B, stats=STATS_B)
        wait_both_up()

        # Read back what is in force: a failed map write or mmap disarms the
        # gate.
        assert dump(NS_A, STATS)["deadman_us"] == deadman, (
            "engine did not apply --deadman-us %d" % deadman)

        pids = ns_pids(NS_A)
        assert pids, "no engine in %s" % NS_A
        for pid in pids:
            sh("sudo kill -STOP %d" % pid, check=False)
        try:
            stat = sh("ps -o stat= -p %d" % pids[0]).strip()
            assert stat.startswith("T"), (
                "engine is %r, not stopped" % stat)
            time.sleep(STOP_S)
            # Read B while A is still stopped, so the window closes
            # before anything can recover and hide the transition.
            return only_session(NS_B, STATS_B)
        finally:
            for pid in pids:
                sh("sudo kill -CONT %d" % pid, check=False)
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


def test_armed_the_peer_notices(arms):
    s = arms["armed"]
    assert s["state"] != "Up", (
        "peer still Up after %.0fs with the engine stopped and the gate"
        " armed; XDP answered for a control plane that was not running"
        % STOP_S)
    assert s["diag"] == 1, (
        "expected diag 1 (control detection expired) - the gate withholds"
        " replies and lets the peer time out, it does not announce"
        " anything - got %s (%s)" % (s["diag"], s.get("last_reason")))


def test_disarmed_the_peer_does_not(arms):
    s = arms["disarmed"]
    assert s["state"] == "Up", (
        "peer went %s with the gate disarmed, so the armed arm above"
        " proves nothing about the gate: reason %r"
        % (s["state"], s.get("last_reason")))
