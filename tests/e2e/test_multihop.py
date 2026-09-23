"""Multihop through a router namespace: packets arrive decremented on 4784.

container A (bfdd + engine)     router ns      container B (bfdd)
  eth-a 10.79.1.1/24  <-veth->  r1 10.79.1.2
                                r2 10.79.2.2  <-veth->  eth-b 10.79.2.1
"""

import json
import os
import re
import time

import pytest

from conftest import (
    RUNTIME,
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
)

pytestmark = pytest.mark.frr

RTR = "bfdrtr"
A_IP, B_IP = "10.79.1.1", "10.79.2.1"
R1, R2 = "10.79.1.2", "10.79.2.2"
UP_WAIT = 30.0

CONF_A = (
    "hostname a\nbfd\n peer %s multihop local-address %s\n"
    "  no shutdown\n exit\nexit\nline vty\n" % (B_IP, A_IP)
)
CONF_B = (
    "hostname b\nbfd\n peer %s multihop local-address %s\n"
    "  no shutdown\n exit\nexit\nline vty\n" % (A_IP, B_IP)
)

TTL = re.compile(r"ttl (\d+)")
SRC = re.compile(r"(10\.79\.\d+\.\d+)\.(\d+) >")
STATS = "/tmp/mh_rig.json"


def _user_tx():
    pids = [
        p
        for p in sh("pgrep -x bfd_tx", check=False).split()
        if STATS in open("/proc/%s/cmdline" % p).read()
    ]
    assert len(pids) == 1, "rig engine not found: %r" % pids
    sh("sudo rm -f %s" % STATS, check=False)
    sh("sudo kill -USR1 %s" % pids[0])
    end = time.time() + 5.0
    while not os.path.exists(STATS):
        assert time.time() < end, "no stats dump from the rig engine"
        time.sleep(0.1)
    with open(STATS) as f:
        return json.load(f)["sessions"][0]["tx_pkts"]


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
        sh(
            "sudo nsenter -t %d -n nohup %s/bfd_tx --dplane 50700"
            " --kernel-tx eth-a --xdp-mode generic --bpf-obj %s/bfd_xdp.o"
            " --stats-dump %s >/tmp/mh_rig.log 2>&1 &" % (pa, root, root, STATS),
            capture=False,
        )

        end = time.time() + UP_WAIT
        while time.time() < end:
            if "up" in frr_vtysh(NAME_B, "show bfd peers brief").lower().split():
                break
            time.sleep(1.0)
        else:
            pytest.fail(
                "multihop session never came up\n%s\n%s"
                % (
                    frr_vtysh(NAME_A, "show bfd peers brief"),
                    sh("tail -20 /tmp/mh_rig.log", check=False),
                )
            )
        yield pa
    finally:
        if not request.config.getoption("--keep-ns"):
            _teardown()


@pytest.fixture(scope="module")
def capture(mhop):
    """Both directions on r1, and the userspace sends over a window containing the
    capture.
    """
    before = _user_tx()
    out = sh(
        "sudo ip netns exec %s timeout 5 tcpdump -n -v -i r1"
        " 'udp port 4784' 2>/dev/null" % RTR,
        check=False,
    )
    user_tx = _user_tx() - before
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
    return {"rows": rows, "user_tx": user_tx}


def test_multihop_session_comes_up_over_a_router(mhop):
    assert "up" in frr_vtysh(NAME_B, "show bfd peers brief").lower().split()


def test_inbound_arrives_decremented(capture):
    inbound = [t for src, _, t in capture["rows"] if src == B_IP]
    assert inbound, "nothing inbound from %s" % B_IP
    assert all(
        t == 254 for t in inbound
    ), "expected every inbound packet at ttl 254 after one hop, got %r" % sorted(
        set(inbound)
    )


def test_bounce_restores_the_ttl(capture):
    """Replies leave at 255 though requests arrive decremented."""
    out = [t for src, _, t in capture["rows"] if src == A_IP]
    assert out, "nothing outbound from %s" % A_IP
    assert all(
        t == 255 for t in out
    ), "expected every bounced packet at ttl 255, got %r" % sorted(set(out))


def test_the_bounce_did_it_not_userspace(capture):
    """Userspace also sends at 255 from the same port, so compare with its send
    count.
    """
    out = [p for src, p, _ in capture["rows"] if src == A_IP]
    assert out, "nothing outbound from %s" % A_IP
    assert len(out) > capture["user_tx"], (
        "%d packets outbound, %d sent by userspace over a wider window: no"
        " kernel bounce, and the ttl assertion above is vacuous"
        % (len(out), capture["user_tx"])
    )
