"""Hundreds of sessions through FRR at once: all come up, a few cut are
detected on time, and the rest never notice.

FRR master, since a release offloads only about 58 sessions from the burst
it registers them in. Kept under the default neighbour-table limit, which
every namespace on the host shares.
"""

import os
import tempfile
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

N = 256
IMAGE = os.environ.get("BFD_FRR_SCALE_IMAGE", "quay.io/frrouting/frr:master")
STATS = "/tmp/frr_scale.json"
LOG = "/tmp/frr_scale_engine.log"
CUT = range(0, N, N // 8)


def a_ip(i):
    return "10.91.%d.%d" % (1 + i // 250, 1 + i % 250)


def b_ip(i):
    return "10.91.%d.%d" % (101 + i // 250, 1 + i % 250)


def bfd_conf(mine, theirs, dev):
    out = ["bfd"]
    for i in range(N):
        out += [
            " peer %s local-address %s interface %s" % (theirs(i), mine(i), dev),
            "  transmit-interval 300",
            "  receive-interval 300",
            " exit",
        ]
    return "\n".join(out + ["exit", ""])


def engine():
    for p in sh("pgrep -x bfd_tx", check=False).split():
        if STATS in open("/proc/%s/cmdline" % p).read():
            return int(p)
    return 0


def snapshot():
    sh("sudo rm -f %s" % STATS)
    sh("sudo kill -USR1 %d" % engine())
    for _ in range(50):
        time.sleep(0.1)
        if os.path.exists(STATS):
            import json

            return json.load(open(STATS))
    raise AssertionError("no stats snapshot\n" + sh("tail %s" % LOG, check=False))


def up_count(name):
    out = frr_vtysh(name, "show bfd peers brief")
    return sum(1 for l in out.splitlines() if " up " in l)


@pytest.fixture
def scale(request):
    if not sh("command -v %s" % RUNTIME, check=False).strip():
        pytest.skip("no container runtime %r" % RUNTIME)
    root = str(request.config.rootpath)
    ca = frr_conf_dir(DAEMONS % DPLANE_OPT, "hostname a\n")
    cb = frr_conf_dir(DAEMONS % "", "hostname b\n")
    open(ca + "/bfd.conf", "w").write(bfd_conf(a_ip, b_ip, "eth-a"))
    open(cb + "/bfd.conf", "w").write(bfd_conf(b_ip, a_ip, "eth-b"))
    sh("chmod -R a+rX %s %s" % (ca, cb))
    try:
        pa = frr_start(NAME_A, ca, IMAGE)
        pb = frr_start(NAME_B, cb, IMAGE)
        sh("sudo ip link add eth-a type veth peer name eth-b", check=False)
        sh("sudo ip link set eth-a netns %d" % pa)
        sh("sudo ip link set eth-b netns %d" % pb)
        for pid, dev, ip in ((pa, "eth-a", a_ip), (pb, "eth-b", b_ip)):
            with tempfile.NamedTemporaryFile("w", delete=False) as f:
                for i in range(N):
                    f.write("addr add %s/16 dev %s\n" % (ip(i), dev))
            frr_ns(pid, "ip -b %s" % f.name)
            frr_ns(pid, "ip link set %s up" % dev)
            frr_ns(pid, "ip link set lo up")
        sh(
            "sudo nsenter -t %d -n nohup %s/bfd_tx --dplane 50700 --kernel-tx eth-a"
            " --xdp-mode generic --bpf-obj %s/bfd_xdp.o --stats-dump %s >%s 2>&1 &"
            % (pa, root, root, STATS, LOG),
            capture=False,
        )
        # The peers go in once the addresses exist.
        time.sleep(3)
        for name in (NAME_A, NAME_B):
            sh(
                "sudo %s exec %s vtysh -f /etc/frr/bfd.conf" % (RUNTIME, name),
                check=False,
            )
        yield pa, pb
    finally:
        sh("sudo pkill -f 'bfd_tx --dplane 50700 --kernel-tx eth-a'", check=False)
        frr_rm(NAME_A)
        frr_rm(NAME_B)
        sh("sudo ip link del eth-a", check=False)


def test_many_sessions_up_and_detected_on_time(scale):
    _, pb = scale
    end = time.time() + 60
    while time.time() < end and (up_count(NAME_A) < N or up_count(NAME_B) < N):
        time.sleep(2)
    assert (
        up_count(NAME_A) == N and up_count(NAME_B) == N
    ), "A %d, B %d of %d up\n%s" % (
        up_count(NAME_A),
        up_count(NAME_B),
        N,
        sh("tail %s" % LOG),
    )
    d = snapshot()
    assert d["sessions_up"] == N, "engine has %d of %d up" % (d["sessions_up"], N)
    downs = {s["lid"]: s["down_events"] for s in d["sessions"]}

    rules = "".join("-A OUTPUT -s %s -j DROP\n" % b_ip(i) for i in CUT)
    frr_ns(
        pb,
        "sh -c 'printf \"*filter\\n%sCOMMIT\\n\" | iptables-restore --noflush'" % rules,
    )
    time.sleep(3)
    d = snapshot()
    frr_ns(pb, "iptables -F OUTPUT")
    by = {s["peer"]: s for s in d["sessions"]}
    cut = [by[b_ip(i)] for i in CUT]
    assert all(s["state"] == "Down" for s in cut), [s["state"] for s in cut]
    late = [
        s["last_detect_us"] for s in cut if not 900000 <= s["last_detect_us"] <= 920000
    ]
    assert not late, "detection outside 900-920ms: %r" % late
    others = [s for s in d["sessions"] if s["peer"] not in {b_ip(i) for i in CUT}]
    flapped = [s["peer"] for s in others if s["down_events"] != downs[s["lid"]]]
    assert not flapped, "sessions not cut went down: %r" % flapped[:5]
