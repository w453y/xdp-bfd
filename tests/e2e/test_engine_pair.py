"""Two engines facing each other, both answering in XDP. Each answers the
other's packets at once, so without the TX turn they bounce every packet:
each side sees the other's answers too fast and drops them. With it, every
packet is either one side's own or an answer to it, and none comes too fast.
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
    dump,
)

# The static session's 10 ms; jittered to 75-100%, so up to 1/7.5ms.
IV_S = 0.010
WINDOW_S = 5.0
DOWN_WAIT = 2.0


def both(rootpath, family):
    obj = str(rootpath / "bfd_xdp.o")
    for ns, stats, dev in ((NS_A, STATS, "rig-a"), (NS_B, STATS_B, "rig-b")):
        start_engine(
            str(rootpath / "bfd_tx"),
            family,
            ns=ns,
            stats=stats,
            kernel_tx=dev,
            xdp_mode="generic",
            extra=("--bpf-obj", obj),
        )
    wait_both_up()


def counters():
    out = {}
    for ns, stats in ((NS_A, STATS), (NS_B, STATS_B)):
        d = dump(ns, stats)
        out[ns] = d["stats"]
    return out


@pytest.mark.parametrize("family", [4, 6])
def test_pair_keeps_its_rate(request, family):
    setup()
    try:
        both(request.config.rootpath, family)
        # Past the handshake, whose first Up packet goes at once.
        time.sleep(1.0)
        c0 = counters()
        time.sleep(WINDOW_S)
        c1 = counters()
        spaced = 0
        for ns in (NS_A, NS_B):
            d = {k: c1[ns][k] - c0[ns][k] for k in ("seen", "too-fast", "tx-spaced")}
            rate = d["seen"] / WINDOW_S
            assert d["too-fast"] == 0, "%s: %d packets came too fast" % (
                ns,
                d["too-fast"],
            )
            assert 0.9 / IV_S <= rate <= 1.4 / IV_S, "%s: %.0f packets/s, want ~%d" % (
                ns,
                rate,
                1 / IV_S,
            )
            spaced += d["tx-spaced"]
        # Whichever side clocks the session withholds the answers to it.
        assert spaced > 0, "no answer withheld: the gate never ran"
        for ns, stats in ((NS_A, STATS), (NS_B, STATS_B)):
            s = only_session(ns, stats)
            assert s["state"] == "Up" and s["down_events"] == 0, "%s flapped" % ns
    finally:
        teardown()


@pytest.mark.parametrize("sig", ["KILL", "STOP"])
def test_pair_detects_a_dead_peer(request, sig):
    """KILL detaches B's program; STOP leaves it answering until the
    dead-man gate, which --deadman-us shortens here.
    """
    root = request.config.rootpath
    obj = str(root / "bfd_xdp.o")
    setup()
    try:
        for ns, stats, dev in ((NS_A, STATS, "rig-a"), (NS_B, STATS_B, "rig-b")):
            start_engine(
                str(root / "bfd_tx"),
                4,
                ns=ns,
                stats=stats,
                kernel_tx=dev,
                xdp_mode="generic",
                extra=("--bpf-obj", obj, "--deadman-us", "200000"),
            )
        wait_both_up()
        for pid in ns_pids(NS_B):
            sh("sudo kill -%s %d" % (sig, pid), check=False)
        end = time.time() + DOWN_WAIT
        while time.time() < end:
            if dump(NS_A, STATS)["sessions_up"] == 0:
                break
            time.sleep(0.1)
        else:
            pytest.fail("A still Up %.1fs after B got SIG%s" % (DOWN_WAIT, sig))
    finally:
        for pid in ns_pids(NS_B):
            sh("sudo kill -CONT %d" % pid, check=False)
        teardown()
