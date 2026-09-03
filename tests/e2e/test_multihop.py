"""Multihop over a router namespace.

    container A (bfdd + engine)     router ns      container B (bfdd)
      eth-a 10.79.1.1/24  <-veth->  r1 10.79.1.2
                                    r2 10.79.2.2  <-veth->  eth-b 10.79.2.1

Different subnets, so the session between A and B is genuinely routed: its
packets cross the router, arrive decremented, and use port 4784.

WHY THIS REACHES THE FAST PATH AT ALL. dplane.c excludes multihop from
ktx_attach_if - a routed session can ingress anywhere, so its ADD ifindex
does not name the interface that would need covering. But that only stops
the engine attaching a NEW interface on a multihop session's behalf.
ktx_mirror still pushes the session into tx_config, and ktx.c never
consults is_mhop, so when the packets do arrive on an already-attached
interface the bounce runs normally. Here there is only one interface, so
they always do.

The scale half of scenario 7 is deliberately not built. 32 multihop
sessions is just config, but the number it would produce is a measurement,
and measurements on a shared CI machine mean nothing.
"""

import os
import re
import time

import pytest

from conftest import (RUNTIME, NAME_A, NAME_B, DAEMONS, DPLANE_OPT, sh,
                      frr_rm, frr_start, frr_ns, frr_vtysh, frr_conf_dir)

pytestmark = pytest.mark.frr

RTR = "bfdrtr"
A_IP, B_IP = "10.79.1.1", "10.79.2.1"
R1, R2 = "10.79.1.2", "10.79.2.2"
UP_WAIT = 30.0

CONF_A = ("hostname a\nbfd\n peer %s multihop local-address %s\n"
          "  no shutdown\n exit\nexit\nline vty\n" % (B_IP, A_IP))
CONF_B = ("hostname b\nbfd\n peer %s multihop local-address %s\n"
          "  no shutdown\n exit\nexit\nline vty\n" % (A_IP, B_IP))

TTL = re.compile(r"ttl (\d+)")
SRC = re.compile(r"(10\.79\.\d+\.\d+)\.(\d+) >")


def _teardown():
    sh("sudo pkill -f 'bfd_tx --dplane 50700 --kernel-tx eth-a'", check=False)
    frr_rm(NAME_A)
    frr_rm(NAME_B)
    sh("sudo ip netns del %s" % RTR, check=False)
    sh("sudo ip link del eth-a", check=False)
    sh("sudo ip link del eth-b", check=False)


@pytest.fixture(scope="module")
def mhop(request):
    if not sh("command -v %s" % RUNTIME, check=False).strip():
        pytest.skip("no container runtime %r" % RUNTIME)
    root = str(request.config.rootpath)
    ca = frr_conf_dir(DAEMONS % DPLANE_OPT, CONF_A)
    cb = frr_conf_dir(DAEMONS % "", CONF_B)
    _teardown()
    try:
        pa = frr_start(NAME_A, ca)
        pb = frr_start(NAME_B, cb)
        sh("sudo ip netns add %s" % RTR, check=False)
        sh("sudo ip netns exec %s sysctl -qw net.ipv4.ip_forward=1" % RTR)
        sh("sudo ip link add eth-a type veth peer name r1", check=False)
        sh("sudo ip link add eth-b type veth peer name r2", check=False)
        sh("sudo ip link set eth-a netns %d" % pa)
        sh("sudo ip link set eth-b netns %d" % pb)
        sh("sudo ip link set r1 netns %s" % RTR)
        sh("sudo ip link set r2 netns %s" % RTR)
        for pid, dev, ip in ((pa, "eth-a", A_IP), (pb, "eth-b", B_IP)):
            frr_ns(pid, "ip addr add %s/24 dev %s" % (ip, dev))
            frr_ns(pid, "ip link set %s up" % dev)
            frr_ns(pid, "ip link set lo up")
        for dev, ip in (("r1", R1), ("r2", R2)):
            sh("sudo ip netns exec %s ip addr add %s/24 dev %s" % (RTR, ip, dev))
            sh("sudo ip netns exec %s ip link set %s up" % (RTR, dev))
        frr_ns(pa, "ip route add 10.79.2.0/24 via %s" % R1)
        frr_ns(pb, "ip route add 10.79.1.0/24 via %s" % R2)
        sh("sudo nsenter -t %d -n nohup %s/bfd_tx --dplane 50700"
           " --kernel-tx eth-a --xdp-mode generic --bpf-obj %s/bfd_xdp.o"
           " --stats-dump /tmp/mh_rig.json >/tmp/mh_rig.log 2>&1 &"
           % (pa, root, root), capture=False)

        end = time.time() + UP_WAIT
        while time.time() < end:
            if "up" in frr_vtysh(NAME_B, "show bfd peers brief").lower().split():
                break
            time.sleep(1.0)
        else:
            pytest.fail("multihop session never came up\n%s\n%s"
                        % (frr_vtysh(NAME_A, "show bfd peers brief"),
                           sh("tail -20 /tmp/mh_rig.log", check=False)))
        yield pa
    finally:
        if not request.config.getoption("--keep-ns"):
            _teardown()


@pytest.fixture(scope="module")
def capture(mhop):
    """Both directions on the router's A-facing side."""
    out = sh("sudo ip netns exec %s timeout 5 tcpdump -n -v -i r1"
             " 'udp port 4784' 2>/dev/null" % RTR, check=False)
    assert out.strip(), "captured nothing on r1"
    rows = []
    ttl = None
    for line in out.splitlines():
        m = TTL.search(line)
        if m:
            ttl = int(m.group(1))
        m = SRC.search(line)
        if m and ttl is not None:
            rows.append((m.group(1), int(m.group(2)), ttl))
            ttl = None
    assert rows, "no BFD packets parsed from the capture:\n%s" % out[:400]
    return rows


def test_multihop_session_comes_up_over_a_router(mhop):
    """The fixture asserts it; this names the claim."""
    assert "up" in frr_vtysh(NAME_B, "show bfd peers brief").lower().split()


def test_inbound_arrives_decremented(capture):
    inbound = [t for src, _, t in capture if src == B_IP]
    assert inbound, "nothing inbound from %s" % B_IP
    assert all(t == 254 for t in inbound), (
        "expected every inbound packet at ttl 254 after one hop, got %r"
        % sorted(set(inbound)))


def test_bounce_restores_the_ttl(capture):
    """tx.h sets ttl back to 255 with an incremental checksum fixup. A
    multihop packet arrives at 254, so a reflected ttl would show as 254
    here and a restored one as 255."""
    out = [t for src, _, t in capture if src == A_IP]
    assert out, "nothing outbound from %s" % A_IP
    assert all(t == 255 for t in out), (
        "expected every bounced packet at ttl 255, got %r" % sorted(set(out)))


def test_the_bounce_did_it_not_userspace(capture):
    """The assertion above passes just as well if userspace answered, since
    its socket also sends at 255. The kernel bounce uses SRC_PORT + slot,
    a distinct high port; userspace uses the session's own socket. Without
    this the TTL test proves nothing about the fast path."""
    ports = {p for src, p, _ in capture if src == A_IP}
    assert ports, "nothing outbound from %s" % A_IP
    assert all(p >= 65472 for p in ports), (
        "outbound source ports %r are not in the kernel-tx range; userspace"
        " answered and the ttl assertion above is vacuous" % sorted(ports))
