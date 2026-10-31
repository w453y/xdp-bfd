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
KEY = "p41r-s3cr3t"


def both(rootpath, family, extra=()):
    obj = str(rootpath / "bfd_xdp.o")
    for ns, stats, dev in ((NS_A, STATS, "rig-a"), (NS_B, STATS_B, "rig-b")):
        start_engine(
            str(rootpath / "bfd_tx"),
            family,
            ns=ns,
            stats=stats,
            kernel_tx=dev,
            xdp_mode="generic",
            extra=("--bpf-obj", obj) + tuple(extra),
        )
    wait_both_up()


def counters():
    out = {}
    for ns, stats in ((NS_A, STATS), (NS_B, STATS_B)):
        d = dump(ns, stats)
        out[ns] = d["stats"]
    return out


def window():
    """Past the handshake, whose first Up packet goes at once."""
    time.sleep(1.0)
    c0 = counters()
    time.sleep(WINDOW_S)
    c1 = counters()
    keys = ("seen", "too-fast", "tx-spaced", "auth-bad", "auth-mismatch")
    return {ns: {k: c1[ns].get(k, 0) - c0[ns].get(k, 0) for k in keys} for ns in c1}


def no_flaps():
    for ns, stats in ((NS_A, STATS), (NS_B, STATS_B)):
        s = only_session(ns, stats)
        assert s["state"] == "Up" and s["down_events"] == 0, "%s flapped" % ns


@pytest.mark.parametrize(
    "family,auth",
    [
        (4, None),
        (6, None),
        (4, "simple"),
        (4, "keyed-sha1"),
        (4, "meticulous-sha1"),
        (4, "keyed-sha1-rfc"),
        (4, "meticulous-sha1-rfc"),
    ],
)
def test_pair_keeps_its_rate(request, family, auth):
    """Signed replies go through the same turn: the program signs what it
    sends, so with auth a bounced packet would also cost a digest each way.
    """
    setup()
    try:
        both(
            request.config.rootpath,
            family,
            ("--auth", "%s:5:%s" % (auth, KEY)) if auth else (),
        )
        w = window()
        spaced = 0
        for ns in (NS_A, NS_B):
            d = w[ns]
            rate = d["seen"] / WINDOW_S
            assert d["too-fast"] == 0, "%s: %d packets came too fast" % (
                ns,
                d["too-fast"],
            )
            assert (
                d["auth-bad"] == 0 and d["auth-mismatch"] == 0
            ), "%s: authentication drops %r" % (ns, d)
            assert 0.9 / IV_S <= rate <= 1.4 / IV_S, "%s: %.0f packets/s, want ~%d" % (
                ns,
                rate,
                1 / IV_S,
            )
            spaced += d["tx-spaced"]
        # Whichever side clocks the session withholds the answers to it.
        assert spaced > 0, "no answer withheld: the gate never ran"
        no_flaps()
    finally:
        teardown()


def test_pair_in_demand_mode_stays_quiet(request):
    """RFC 5880 s6.6: once both sides demand, neither sends periodically. A
    program answering the other's answers would keep the wire busy anyway.
    """
    setup()
    try:
        both(request.config.rootpath, 4, ("--demand",))
        # The switch to demand rides a Poll sequence.
        time.sleep(2.0)
        w = window()
        for ns in (NS_A, NS_B):
            d = w[ns]
            assert d["too-fast"] == 0, "%s: %d packets came too fast" % (
                ns,
                d["too-fast"],
            )
            # Only the demand-mode Polls are left, well under the 10 ms rate.
            assert d["seen"] / WINDOW_S < 0.1 / IV_S, "%s: %.0f packets/s in demand" % (
                ns,
                d["seen"] / WINDOW_S,
            )
        no_flaps()
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
