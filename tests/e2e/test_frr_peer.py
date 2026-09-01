"""03-testing Layer 3 scenario 1: full handshake to Up against stock bfdd.

Three parties, not two. The doc's diagram shows engine in one namespace and
an FRR container in the other, but the scenario also says it pins the bffdp
integration against real FRR - and bffdp is the channel between bfdd and the
engine, so bfdd has to be the engine's control plane rather than the far end.

    container A (netns)          container B (netns)
      bfdd  --bffdp-->  engine     bfdd, stock, no dataplane
      running via nsenter -n
              eth-a  <---veth--->  eth-b

Containers rather than `ip netns`, because `ip netns exec` remounts /sys for
the new namespace and the cgroup2 mount does not come with it: /sys/fs/cgroup
reads as plain sysfs inside the exec and crun refuses to start with "invalid
file system type". Moving a veth end into a container's netns by pid avoids
that entirely, and works identically under docker and podman.

The engine runs via `nsenter -t <pid> -n`, which changes ONLY the network
namespace, so it uses the host's bfd_tx and bfd_xdp.o while sharing a netns
with the bfdd that drives it. bffdp then works over 127.0.0.1.

Marked `frr`: needs a container runtime and pulls a ~100MB image, so it is
not part of the default netns run.
"""

import json
import os
import time

import pytest

from conftest import (RUNTIME, FRR_IMAGE, NAME_A, NAME_B, DAEMONS, DPLANE_OPT,
                      sh, frr_rm, frr_start, frr_ns, frr_vtysh,
                      frr_conf_dir, frr_daemon_pid)

pytestmark = pytest.mark.frr

IP_A, IP_B = "10.78.0.1", "10.78.0.2"
UP_WAIT = 25.0

CONF = ("hostname %s\n"
        "bfd\n"
        " peer %s local-address %s interface %s\n"
        "  no shutdown\n"
        " exit\n"
        "exit\n"
        "line vty\n")


def _brief_up(name):
    return "up" in frr_vtysh(name, "show bfd peers brief").lower().split()


@pytest.fixture(scope="module")
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

        sh("sudo nsenter -t %d -n nohup %s/bfd_tx --dplane 50700"
           " --kernel-tx eth-a --xdp-mode generic --bpf-obj %s/bfd_xdp.o"
           " --stats-dump /tmp/frr_rig.json >/tmp/frr_rig_engine.log 2>&1 &"
           % (pa, root, root), capture=False)
        yield pa, pb
    finally:
        sh("sudo pkill -f 'bfd_tx --dplane 50700 --kernel-tx eth-a'",
           check=False)
        frr_rm(NAME_A)
        frr_rm(NAME_B)
        sh("sudo ip link del eth-a", check=False)


def test_engine_accepts_the_bffdp_connection(frr_pair):
    """The control channel, before anything about the wire. A failure here
    and the handshake test below would fail for a reason that has nothing
    to do with BFD."""
    end = time.time() + UP_WAIT
    while time.time() < end:
        if "bfdd connected" in sh("cat /tmp/frr_rig_engine.log",
                                  check=False):
            return
        time.sleep(0.5)
    pytest.fail("bfdd never connected over bffdp\n%s"
                % sh("tail -20 /tmp/frr_rig_engine.log", check=False))


def test_both_sides_reach_up(frr_pair):
    end = time.time() + UP_WAIT
    while time.time() < end:
        if _brief_up(NAME_A) and _brief_up(NAME_B):
            return
        time.sleep(1.0)
    pytest.fail("not both up\nA: %s\nB: %s\nengine:\n%s"
                % (frr_vtysh(NAME_A, "show bfd peers brief"),
                   frr_vtysh(NAME_B, "show bfd peers brief"),
                   sh("tail -20 /tmp/frr_rig_engine.log", check=False)))


# ---- scenario 2: --dp-hold lifecycle ------------------------------------

HOLD_S = 60


@pytest.fixture(scope="module")
def frr_hold(request):
    """Separate from frr_pair: this one kills bfdd, and nothing else should
    depend on a fixture that does that."""
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
        sh("sudo nsenter -t %d -n nohup %s/bfd_tx --dplane 50700"
           " --dp-hold %d --kernel-tx eth-a --xdp-mode generic"
           " --bpf-obj %s/bfd_xdp.o --stats-dump /tmp/frr_hold.json"
           " >/tmp/frr_hold_engine.log 2>&1 &"
           % (pa, root, HOLD_S, root), capture=False)
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
    """Negative arm for the test below. Same crash, no --dp-hold, so the
    engine tears its sessions down instead of orphaning them and the peer
    must notice. Without this, that test would pass just as well if the
    kill did nothing at all - a live bfdd also keeps a session up."""
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
        sh("sudo nsenter -t %d -n nohup %s/bfd_tx --dplane 50700"
           " --kernel-tx eth-a --xdp-mode generic --bpf-obj %s/bfd_xdp.o"
           " --stats-dump /tmp/frr_nohold.json >/tmp/frr_nohold.log 2>&1 &"
           % (pa, root, root), capture=False)
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
        pytest.fail("peer stayed Up without --dp-hold; the hold test proves"
                    " nothing\n%s" % frr_vtysh(NAME_B, "show bfd peers brief"))
    finally:
        sh("sudo pkill -f 'bfd_tx --dplane 50700 --kernel-tx eth-a'",
           check=False)
        frr_rm(NAME_A)
        frr_rm(NAME_B)
        sh("sudo ip link del eth-a", check=False)


def _peer_downs(name):
    out = frr_vtysh(name, "show bfd peers counters json")
    return sum(s["session-down"] for s in json.loads(out))


def test_dp_hold_survives_a_bfdd_crash(frr_hold):
    """SIGKILL, not SIGTERM. A clean shutdown makes bfdd DELETE every
    session first, so there is nothing left to orphan and the test would
    measure the wrong thing entirely - that is how the lab version first
    failed, with 55 peer-visible down events.

    The far side is the judge: it never learns our control plane died."""
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
        pytest.fail("engine never logged the orphan hold\n%s"
                    % sh("tail -20 /tmp/frr_hold_engine.log", check=False))

    time.sleep(5.0)
    assert _brief_up(NAME_B), (
        "peer went down after bfdd was killed; --dp-hold did not hold\n%s"
        % frr_vtysh(NAME_B, "show bfd peers brief"))
    assert _peer_downs(NAME_B) == before, (
        "peer recorded a down event across the crash (%d -> %d)"
        % (before, _peer_downs(NAME_B)))
