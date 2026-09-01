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

import os
import time

import pytest

from conftest import (RUNTIME, FRR_IMAGE, NAME_A, NAME_B, DAEMONS, DPLANE_OPT,
                      sh, frr_rm, frr_start, frr_ns, frr_vtysh, frr_conf_dir)

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
