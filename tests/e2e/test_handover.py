"""--pin: an engine restart the peer does not notice. A second engine loads,
has the first hand over (SIGUSR2), takes over the pinned program and adopts
its sessions until bfdd re-adds them.
"""

import os
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
from test_frr_peer import CONF, IP_A, IP_B, UP_WAIT, _brief_up, _peer_downs

pytestmark = pytest.mark.frr

PIN = "/sys/fs/bpf/xdp-bfd-e2e"
LOG = "/tmp/frr_handover_engine.log"
RC = "/tmp/frr_handover.%d.rc"
PATTERN = "bfd_tx --dplane 50700 --dp-hold 30"


def _start(pa, root, n, pin=True):
    """Engine n; its exit status lands in RC % n."""
    sh("sudo rm -f %s" % (RC % n))
    sh(
        "sudo nsenter -t %d -n sh -c '%s/bfd_tx --dplane 50700 --dp-hold 30%s"
        " --kernel-tx eth-a --xdp-mode generic --bpf-obj %s/bfd_xdp.o"
        " >>%s 2>&1; echo $? >%s' >/dev/null 2>&1 &"
        % (pa, root, " --pin %s" % PIN if pin else "", root, LOG, RC % n),
        capture=False,
    )
    time.sleep(1.0)


def _engine_pid():
    for p in sh("pgrep -x bfd_tx", check=False).split():
        if PATTERN in open("/proc/%s/cmdline" % p).read().replace("\0", " "):
            return int(p)
    return 0


def _exit_code(n, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(RC % n):
            return int(open(RC % n).read().strip() or -1)
        time.sleep(0.1)
    return None


@pytest.fixture
def pair(request):
    if not sh("command -v %s" % RUNTIME, check=False).strip():
        pytest.skip("no container runtime %r" % RUNTIME)
    if not os.path.isdir("/sys/fs/bpf"):
        pytest.skip("no bpffs")
    root = str(request.config.rootpath)
    ca = frr_conf_dir(DAEMONS % DPLANE_OPT, CONF % ("a", IP_B, IP_A, "eth-a"))
    cb = frr_conf_dir(DAEMONS % "", CONF % ("b", IP_A, IP_B, "eth-b"))
    sh("sudo rm -rf %s %s" % (PIN, LOG), check=False)
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
        _start(pa, root, 1)
        end = time.time() + UP_WAIT
        while time.time() < end:
            if _brief_up(NAME_A) and _brief_up(NAME_B):
                break
            time.sleep(1.0)
        else:
            pytest.fail("never came up\n%s" % sh("tail -20 %s" % LOG, check=False))
        yield pa, root
    finally:
        sh("sudo pkill -f '%s'" % PATTERN, check=False)
        time.sleep(0.5)
        sh(
            "sudo rm -rf %s /run/xdp-bfd/%s.pid" % (PIN, os.path.basename(PIN)),
            check=False,
        )
        frr_rm(NAME_A)
        frr_rm(NAME_B)
        sh("sudo ip link del eth-a", check=False)


def _settled(before):
    """bfdd retries its data plane every 3s; the adopted session waits for it."""
    time.sleep(10.0)
    log = sh("sudo cat %s" % LOG, check=False)
    assert "took over the program on eth-a" in log, log[-1500:]
    assert "adopted 1 session(s), 1 Up" in log, log[-1500:]
    assert "adopts live session" in log, "bfdd's re-add did not adopt\n" + log[-1500:]
    assert _brief_up(NAME_A) and _brief_up(NAME_B)
    after = _peer_downs(NAME_B)
    assert after == before, "the peer saw the restart (%d -> %d down events)" % (
        before,
        after,
    )
    return log


def test_takeover_is_not_seen_by_the_peer(pair):
    """The way to restart: the new engine loads before the old one leaves."""
    pa, root = pair
    before = _peer_downs(NAME_B)
    _start(pa, root, 2)
    assert _exit_code(1) == 75, "the first engine did not hand over"
    assert "handed over in" in _settled(before)


def test_sigusr2_then_start_is_not_seen_by_the_peer(pair):
    """For a supervisor: SIGUSR2, exit 75, and the same command line again."""
    pa, root = pair
    before = _peer_downs(NAME_B)
    sh("sudo kill -USR2 %d" % _engine_pid())
    assert _exit_code(1) == 75
    _start(pa, root, 2)
    _settled(before)


def test_a_plain_restart_is_seen_by_the_peer(pair):
    """Without the handover the peer must notice, or the tests above prove nothing."""
    pa, root = pair
    before = _peer_downs(NAME_B)
    sh("sudo kill -TERM %d" % _engine_pid())
    assert _exit_code(1) == 0
    pins = sh("sudo ls %s" % PIN, check=False).split()
    assert not [p for p in pins if p.startswith("abi-")], (
        "SIGTERM left pins behind: %r" % pins
    )
    _start(pa, root, 2)
    time.sleep(10.0)
    assert _peer_downs(NAME_B) > before, "a SIGTERM restart went unnoticed"
