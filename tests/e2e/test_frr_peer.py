"""Against stock bfdd. Needs a container runtime and an FRR image.

    container A                         container B
      bfdd --bfddp--> engine              bfdd, stock
      eth-a  <--------- veth --------->  eth-b

The engine runs under `nsenter -n`, so it is the host's build and reaches
A's bfdd on 127.0.0.1.
"""

import json
import os
import time

import pytest

from conftest import (
    RUNTIME,
    FRR_IMAGE,
    NAME_A,
    NAME_B,
    DAEMONS,
    DPLANE_OPT,
    sh,
    frr_rm,
    frr_start,
    frr_ns,
    frr_vtysh,
    frr_conf_dir,
    frr_daemon_pid,
)
from lib.netns import bpf_map_for_dev

pytestmark = pytest.mark.frr

IP_A, IP_B = "10.78.0.1", "10.78.0.2"
UP_WAIT = 25.0

CONF = (
    "hostname %s\n"
    "bfd\n"
    " peer %s local-address %s interface %s\n"
    "  no shutdown\n"
    " exit\n"
    "exit\n"
    "line vty\n"
)


def _brief_up(name):
    return "up" in frr_vtysh(name, "show bfd peers brief").lower().split()


# The hold tests reuse the container names and veth.
@pytest.fixture
def frr_pair(request):
    if not sh("command -v %s" % RUNTIME, check=False).strip():
        pytest.skip("no container runtime %r" % RUNTIME)

    root = str(request.config.rootpath)
    ca = frr_conf_dir(DAEMONS % DPLANE_OPT, CONF % ("a", IP_B, IP_A, "eth-a"))
    cb = frr_conf_dir(DAEMONS % "", CONF % ("b", IP_A, IP_B, "eth-b"))
    pa = pb = None
    try:
        pa = frr_start(NAME_A, ca)
        pb = frr_start(NAME_B, cb)
        sh("sudo ip link add eth-a type veth peer name eth-b", check=False)
        sh("sudo ip link set eth-a netns %d" % pa)
        sh("sudo ip link set eth-b netns %d" % pb)
        for pid, dev, ip in ((pa, "eth-a", IP_A), (pb, "eth-b", IP_B)):
            frr_ns(pid, "ip addr add %s/24 dev %s" % (ip, dev))
            frr_ns(pid, "ip link set %s up" % dev)
            frr_ns(pid, "ip link set lo up")

        sh(
            "sudo nsenter -t %d -n nohup %s/bfd_tx --dplane 50700"
            " --kernel-tx eth-a --xdp-mode generic --bpf-obj %s/bfd_xdp.o"
            " --stats-dump /tmp/frr_rig.json >/tmp/frr_rig_engine.log 2>&1 &"
            % (pa, root, root),
            capture=False,
        )
        yield pa, pb
    finally:
        sh("sudo pkill -f 'bfd_tx --dplane 50700 --kernel-tx eth-a'", check=False)
        frr_rm(NAME_A)
        frr_rm(NAME_B)
        sh("sudo ip link del eth-a", check=False)


def test_engine_accepts_the_bfddp_connection(frr_pair):
    """The control channel first, so its failure is not taken for a BFD one."""
    end = time.time() + UP_WAIT
    while time.time() < end:
        if "bfdd connected" in sh("cat /tmp/frr_rig_engine.log", check=False):
            return
        time.sleep(0.5)
    pytest.fail(
        "bfdd never connected over bfddp\n%s"
        % sh("tail -20 /tmp/frr_rig_engine.log", check=False)
    )


def test_both_sides_reach_up(frr_pair):
    end = time.time() + UP_WAIT
    while time.time() < end:
        if _brief_up(NAME_A) and _brief_up(NAME_B):
            return
        time.sleep(1.0)
    pytest.fail(
        "not both up\nA: %s\nB: %s\nengine:\n%s"
        % (
            frr_vtysh(NAME_A, "show bfd peers brief"),
            frr_vtysh(NAME_B, "show bfd peers brief"),
            sh("tail -20 /tmp/frr_rig_engine.log", check=False),
        )
    )


HOLD_S = 60


@pytest.fixture
def frr_hold(request):
    """Its own fixture: it kills bfdd."""
    if not sh("command -v %s" % RUNTIME, check=False).strip():
        pytest.skip("no container runtime %r" % RUNTIME)

    root = str(request.config.rootpath)
    ca = frr_conf_dir(DAEMONS % DPLANE_OPT, CONF % ("a", IP_B, IP_A, "eth-a"))
    cb = frr_conf_dir(DAEMONS % "", CONF % ("b", IP_A, IP_B, "eth-b"))
    try:
        pa = frr_start(NAME_A, ca)
        pb = frr_start(NAME_B, cb)
        sh("sudo ip link add eth-a type veth peer name eth-b", check=False)
        sh("sudo ip link set eth-a netns %d" % pa)
        sh("sudo ip link set eth-b netns %d" % pb)
        for pid, dev, ip in ((pa, "eth-a", IP_A), (pb, "eth-b", IP_B)):
            frr_ns(pid, "ip addr add %s/24 dev %s" % (ip, dev))
            frr_ns(pid, "ip link set %s up" % dev)
            frr_ns(pid, "ip link set lo up")
        sh(
            "sudo nsenter -t %d -n nohup %s/bfd_tx --dplane 50700"
            " --dp-hold %d --kernel-tx eth-a --xdp-mode generic"
            " --bpf-obj %s/bfd_xdp.o --stats-dump /tmp/frr_hold.json"
            " >/tmp/frr_hold_engine.log 2>&1 &" % (pa, root, HOLD_S, root),
            capture=False,
        )
        end = time.time() + UP_WAIT
        while time.time() < end:
            if _brief_up(NAME_A) and _brief_up(NAME_B):
                break
            time.sleep(1.0)
        else:
            pytest.fail("never came up before the kill")
        yield pa, pb
    finally:
        sh("sudo pkill -f 'bfd_tx --dplane 50700 --dp-hold'", check=False)
        frr_rm(NAME_A)
        frr_rm(NAME_B)
        sh("sudo ip link del eth-a", check=False)


def test_without_dp_hold_the_peer_goes_down(request):
    """Without --dp-hold the peer must notice, or the hold test proves nothing."""
    if not sh("command -v %s" % RUNTIME, check=False).strip():
        pytest.skip("no container runtime %r" % RUNTIME)
    root = str(request.config.rootpath)
    ca = frr_conf_dir(DAEMONS % DPLANE_OPT, CONF % ("a", IP_B, IP_A, "eth-a"))
    cb = frr_conf_dir(DAEMONS % "", CONF % ("b", IP_A, IP_B, "eth-b"))
    try:
        pa = frr_start(NAME_A, ca)
        pb = frr_start(NAME_B, cb)
        sh("sudo ip link add eth-a type veth peer name eth-b", check=False)
        sh("sudo ip link set eth-a netns %d" % pa)
        sh("sudo ip link set eth-b netns %d" % pb)
        for pid, dev, ip in ((pa, "eth-a", IP_A), (pb, "eth-b", IP_B)):
            frr_ns(pid, "ip addr add %s/24 dev %s" % (ip, dev))
            frr_ns(pid, "ip link set %s up" % dev)
            frr_ns(pid, "ip link set lo up")
        sh(
            "sudo nsenter -t %d -n nohup %s/bfd_tx --dplane 50700"
            " --kernel-tx eth-a --xdp-mode generic --bpf-obj %s/bfd_xdp.o"
            " --stats-dump /tmp/frr_nohold.json >/tmp/frr_nohold.log 2>&1 &"
            % (pa, root, root),
            capture=False,
        )
        end = time.time() + UP_WAIT
        while time.time() < end:
            if _brief_up(NAME_A) and _brief_up(NAME_B):
                break
            time.sleep(1.0)
        else:
            pytest.fail("never came up before the kill")

        sh("sudo kill -9 %d" % frr_daemon_pid(pa, "bfdd"))
        end = time.time() + 20.0
        while time.time() < end:
            if not _brief_up(NAME_B):
                return
            time.sleep(1.0)
        pytest.fail(
            "peer stayed Up without --dp-hold; the hold test proves"
            " nothing\n%s" % frr_vtysh(NAME_B, "show bfd peers brief")
        )
    finally:
        sh("sudo pkill -f 'bfd_tx --dplane 50700 --kernel-tx eth-a'", check=False)
        frr_rm(NAME_A)
        frr_rm(NAME_B)
        sh("sudo ip link del eth-a", check=False)


def _peer_downs(name):
    out = frr_vtysh(name, "show bfd peers counters json")
    return sum(s["session-down"] for s in json.loads(out))


def test_dp_hold_survives_a_bfdd_crash(frr_hold):
    """SIGKILL: SIGTERM deletes every session first, leaving nothing to orphan."""
    before = _peer_downs(NAME_B)
    pa, _ = frr_hold
    bfdd = frr_daemon_pid(pa, "bfdd")
    sh("sudo kill -9 %d" % bfdd)

    end = time.time() + 15.0
    while time.time() < end:
        if "holding" in sh("cat /tmp/frr_hold_engine.log", check=False):
            break
        time.sleep(0.5)
    else:
        pytest.fail(
            "engine never logged the orphan hold\n%s"
            % sh("tail -20 /tmp/frr_hold_engine.log", check=False)
        )

    time.sleep(5.0)
    assert _brief_up(
        NAME_B
    ), "peer went down after bfdd was killed; --dp-hold did not hold\n%s" % frr_vtysh(
        NAME_B, "show bfd peers brief"
    )
    assert (
        _peer_downs(NAME_B) == before
    ), "peer recorded a down event across the crash (%d -> %d)" % (
        before,
        _peer_downs(NAME_B),
    )


RAISED_MS = 50


def _cfg(pa):
    """Through the program on eth-a, since map names also match the host's engine."""
    entries = bpf_map_for_dev("eth-a", "tx_config", ns_pid=pa)
    assert len(entries) == 1, "expected one session, got %d" % len(entries)
    return entries[0]["value"]


def _state(pa):
    entries = bpf_map_for_dev("eth-a", "bfd_sessions", ns_pid=pa)
    assert len(entries) == 1, "expected one session, got %d" % len(entries)
    return entries[0]["value"]


def test_renegotiation_completes_a_poll_sequence(frr_pair):
    """The Poll terminates and min_tx_us moves; the injection matrix cannot
    attribute this.
    """
    pa, _ = frr_pair
    if "not found" in sh("bpftool version 2>&1", check=False):
        pytest.skip("bpftool is not installed for this kernel")
    # The fixture yields before XDP attaches.
    end = time.time() + UP_WAIT
    while time.time() < end:
        if _brief_up(NAME_A) and _brief_up(NAME_B):
            break
        time.sleep(1.0)
    else:
        pytest.fail("never came up before the renegotiation")

    before = _cfg(pa)
    seq0, tx0 = before["poll_seq"], before["min_tx_us"]
    assert tx0 != RAISED_MS * 1000, "session already at the raised interval"

    sh(
        "sudo %s exec %s vtysh -c 'configure terminal' -c 'bfd'"
        " -c 'peer %s local-address %s interface eth-a'"
        " -c 'transmit-interval %d'" % (RUNTIME, NAME_A, IP_B, IP_A, RAISED_MS),
        check=False,
    )

    end = time.time() + 20.0
    seq1 = final = None
    while time.time() < end:
        cfg, st = _cfg(pa), _state(pa)
        if cfg["poll_seq"] != seq0:
            seq1, final = cfg["poll_seq"], st["final_seq"]
            if final == seq1:
                break
        time.sleep(0.5)

    assert seq1 is not None, (
        "poll_seq never advanced from %d; did the interval change apply?"
        " min_tx_us is %d" % (seq0, _cfg(pa)["min_tx_us"])
    )
    assert final == seq1, (
        "poll_seq advanced to %d but final_seq stayed at %s: the peer never"
        " answered with F" % (seq1, final)
    )
    assert _cfg(pa)["min_tx_us"] == RAISED_MS * 1000, "min_tx_us is %d, want %d" % (
        _cfg(pa)["min_tx_us"],
        RAISED_MS * 1000,
    )
    assert _brief_up(NAME_B), "peer went down across the renegotiation"
    print(
        "poll_seq %d -> %d, final_seq caught up, min_tx_us %d -> %d"
        % (seq0, seq1, tx0, _cfg(pa)["min_tx_us"])
    )
