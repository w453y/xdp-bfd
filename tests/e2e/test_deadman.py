"""The dead-man gate, arm and disarm, in two namespaces.

tools/measure/wedged_ktx.py asserts the same thing against the 64-session mesh and
needs that mesh; this is the version CI can run. The claim is narrow and
the negative arm is what makes it mean anything:

  armed     engine A is SIGSTOPped, XDP stops answering for it, and B
            reaches its own conclusion on its own detection timer
  disarmed  the same stop with --deadman-us 0, and B stays Up - because
            XDP goes on answering on behalf of a control plane that is no
            longer there

Without the second, "B went Down while A was stopped" is equally well
explained by A simply being stopped, which is true of any engine with no
fast path at all.

SIGSTOP rather than load: the loop is not CPU-bound - it sleeps on a
timer, wakes for microseconds, sleeps again - so throttling CPU does not
slow it. sweep_ladder's ladder measured a hard 5% cgroup cap at 505
passes/s against 504 uncapped. SIGSTOP stops userspace dead while the
process stays alive and its bpf_link stays open, which is the case under
test.
"""

import time

import pytest

from conftest import (NS_A, NS_B, STATS, STATS_B, sh, setup, teardown,
                      ns_pids, start_engine, wait_both_up, only_session,
                      dump)

# Comfortably past the 1s bound plus B's detect budget (~150ms at the
# rig's timers), and short enough that the disarmed arm is not just
# waiting out the clock.
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

        # What the engine says is in force, not what was asked for: a
        # bound that failed to reach the map, or a heartbeat that failed
        # to mmap, disarms the gate on the way through. Reading it back
        # is what stops the armed arm from silently becoming a second
        # copy of the disarmed one.
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
