"""The packaged unit, run for real: its user, its bpffs mount, and a
systemctl reload the peer does not notice. The unit is generated from
packaging/xdp-bfd.service, changed only where a test must be.
"""

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
    frr_conf_dir,
)
from test_frr_peer import CONF, IP_A, IP_B, UP_WAIT, _brief_up, _peer_downs

pytestmark = pytest.mark.frr

UNIT = "xdp-bfd-e2e"
UNIT_PATH = "/run/systemd/system/%s.service" % UNIT
PIN_UNIT = "xdp-bfd-pin"
BIN = "/run/xdp-bfd-e2e-bin"
PIN = "/run/xdp-bfd-pin"


def _systemctl(*args):
    return sh("sudo systemctl %s" % " ".join(args), check=False)


def _main_pid():
    out = _systemctl("show", "-p", "MainPID", "--value", UNIT).strip()
    return int(out) if out.isdigit() else 0


def _journal():
    return sh("sudo journalctl -u %s --no-pager -o cat" % UNIT, check=False)


def _unit(root, pa):
    u = open(os.path.join(root, "packaging/xdp-bfd.service")).read()
    args = (
        "--dplane 50700 --kernel-tx eth-a --xdp-mode generic --dp-hold 30 --pin %s"
        " --bpf-obj %s/bfd_xdp.o" % (PIN, BIN)
    )
    u = u.replace(
        "EnvironmentFile=/etc/xdp-bfd/engine.conf",
        'Environment="XDP_BFD_ARGS=%s"' % args,
    )
    u = u.replace("/usr/sbin/xdp-bfd", "%s/bfd_tx" % BIN)
    u = u.replace("xdp-bfd-pin.service", "%s.service" % PIN_UNIT)
    u = u.replace(
        "[Service]\n",
        "[Service]\nNetworkNamespacePath=/proc/%d/ns/net\n"
        # Another engine on the host keeps its pid file there.
        "RuntimeDirectoryPreserve=yes\n" % pa,
        1,
    )
    return u


@pytest.fixture
def unit(request):
    if not sh("command -v %s" % RUNTIME, check=False).strip():
        pytest.skip("no container runtime %r" % RUNTIME)
    if not os.path.isdir("/run/systemd/system"):
        pytest.skip("not running under systemd")
    if not sh("getent passwd xdp-bfd", check=False).strip():
        sh(
            "sudo useradd --system --no-create-home --home-dir /nonexistent"
            " --shell /usr/sbin/nologin --user-group xdp-bfd"
        )
    root = str(request.config.rootpath)
    sh("sudo install -d -m 755 %s" % BIN)
    sh("sudo install -m 755 %s/bfd_tx %s/bfd_tx" % (root, BIN))
    sh("sudo install -m 644 %s/bfd_xdp.o %s/bfd_xdp.o" % (root, BIN))
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
        with open("/tmp/%s.service" % UNIT, "w") as f:
            f.write(_unit(root, pa))
        sh("sudo install -m 644 /tmp/%s.service %s" % (UNIT, UNIT_PATH))
        sh(
            "sudo install -m 644 %s/packaging/%s.service /run/systemd/system/%s.service"
            % (root, PIN_UNIT, PIN_UNIT)
        )
        _systemctl("daemon-reload")
        _systemctl("start", UNIT)
        assert _systemctl("is-active", UNIT).strip() == "active", _journal()[-2000:]
        end = time.time() + UP_WAIT
        while time.time() < end:
            if _brief_up(NAME_A) and _brief_up(NAME_B):
                break
            time.sleep(1.0)
        else:
            pytest.fail("never came up\n%s" % _journal()[-2000:])
        yield
    finally:
        _systemctl("stop", UNIT)
        sh(
            "sudo rm -f %s /run/systemd/system/%s.service" % (UNIT_PATH, PIN_UNIT),
            check=False,
        )
        _systemctl("daemon-reload")
        frr_rm(NAME_A)
        frr_rm(NAME_B)
        sh("sudo ip link del eth-a", check=False)


def test_the_unit_runs_unprivileged_with_its_bpffs(unit):
    pid = _main_pid()
    assert pid, _journal()[-2000:]
    assert (
        open("/proc/%d/status" % pid).read().count("Uid:\t0") == 0
    ), "the engine runs as root"
    assert "bpf" in sh("stat -f -c %%T %s" % PIN), "%s is not bpffs" % PIN
    assert re.search(r"abi-", sh("sudo ls %s" % PIN)), "nothing pinned in %s" % PIN


def test_reload_is_not_seen_by_the_peer(unit):
    before, old = _peer_downs(NAME_B), _main_pid()
    out = sh("sudo systemctl reload %s; echo rc=$?" % UNIT, check=False)
    assert "rc=0" in out, out + _journal()[-2000:]
    time.sleep(10.0)
    new = _main_pid()
    assert new and new != old, "MainPID %d -> %d" % (old, new)
    assert _systemctl("is-active", UNIT).strip() == "active"
    j = _journal()
    assert "handed over in" in j and "adopts live session" in j, j[-2000:]
    assert _brief_up(NAME_A) and _brief_up(NAME_B)
    assert _peer_downs(NAME_B) == before, "the peer saw the reload"


def test_restart_is_seen_and_stop_unpins(unit):
    before = _peer_downs(NAME_B)
    _systemctl("restart", UNIT)
    time.sleep(10.0)
    assert _peer_downs(NAME_B) > before, "a restart went unnoticed"
    _systemctl("stop", UNIT)
    assert not re.search(r"abi-", sh("sudo ls %s" % PIN, check=False)), "stop left pins"
