"""bfdd and an engine on both ends: what the static pair cannot drive.

container A                         container B
  bfdd --bfddp--> engine              bfdd --bfddp--> engine
  eth-a  <--------- veth --------->  eth-b
"""

import json
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

pytestmark = pytest.mark.frr

IP_A, IP_B = "10.77.0.1", "10.77.0.2"
UP_WAIT = 30.0
WINDOW_S = 5.0
SIDES = (("a", NAME_A, "eth-a"), ("b", NAME_B, "eth-b"))

CONF = (
    "hostname %s\n"
    "bfd\n"
    " peer %s local-address %s interface %s\n"
    "  transmit-interval 20\n"
    "  receive-interval 20\n"
    "%s"
    "  no shutdown\n"
    " exit\n"
    "exit\n"
    "line vty\n"
)
ECHO = "  echo-mode\n  echo transmit-interval 50\n  echo receive-interval 50\n"


def _stats(side):
    return "/tmp/frr_pair_%s.json" % side


def _pin(side):
    return "/sys/fs/bpf/xdp-bfd-e2e-pair-%s" % side


def _log(side):
    return "/tmp/frr_pair_%s.log" % side


def _start(pid, root, side, dev):
    sh(
        "sudo nsenter -t %d -n sh -c '%s/bfd_tx --dplane 50700 --dp-hold 30"
        " --pin %s --kernel-tx %s --xdp-mode generic --bpf-obj %s/bfd_xdp.o"
        " --stats-dump %s >>%s 2>&1' >/dev/null 2>&1 &"
        % (pid, root, _pin(side), dev, root, _stats(side), _log(side)),
        capture=False,
    )
    time.sleep(1.0)


def _engine_pids(side):
    out = []
    for p in sh("pgrep -x bfd_tx", check=False).split():
        try:
            if _stats(side) in open("/proc/%s/cmdline" % p).read():
                out.append(int(p))
        except OSError:
            pass
    return out


def _dump(side):
    pids = _engine_pids(side)
    assert len(pids) == 1, "engine %s: %r" % (side, pids)
    sh("sudo rm -f %s" % _stats(side))
    sh("sudo kill -USR1 %d" % pids[0])
    end = time.time() + 5.0
    while not os.path.exists(_stats(side)):
        assert time.time() < end, "no stats dump from engine %s" % side
        time.sleep(0.1)
    time.sleep(0.1)
    with open(_stats(side)) as f:
        return json.load(f)


def _session(side):
    s = _dump(side)["sessions"]
    assert len(s) == 1, "engine %s holds %d sessions" % (side, len(s))
    return s[0]


def _up(name):
    return "up" in frr_vtysh(name, "show bfd peers brief").lower().split()


def _window():
    keys = ("seen", "too-fast", "tx-spaced", "echo-returns", "reflected")
    d0 = {side: _dump(side)["stats"] for side, _, _ in SIDES}
    time.sleep(WINDOW_S)
    d1 = {side: _dump(side)["stats"] for side, _, _ in SIDES}
    return {s: {k: d1[s].get(k, 0) - d0[s].get(k, 0) for k in keys} for s in d1}


def _pair(request, extra):
    if not sh("command -v %s" % RUNTIME, check=False).strip():
        pytest.skip("no container runtime %r" % RUNTIME)
    if not os.path.isdir("/sys/fs/bpf"):
        pytest.skip("no bpffs")
    root = str(request.config.rootpath)
    ips = {"a": (IP_A, IP_B), "b": (IP_B, IP_A)}
    pids = {}
    for side, name, dev in SIDES:
        me, them = ips[side]
        conf = frr_conf_dir(DAEMONS % DPLANE_OPT, CONF % (side, them, me, dev, extra))
        sh("sudo rm -rf %s %s" % (_pin(side), _log(side)), check=False)
        pids[side] = frr_start(name, conf)
    sh("sudo ip link add eth-a type veth peer name eth-b", check=False)
    for side, _, dev in SIDES:
        me = ips[side][0]
        sh("sudo ip link set %s netns %d" % (dev, pids[side]))
        frr_ns(pids[side], "ip addr add %s/24 dev %s" % (me, dev))
        frr_ns(pids[side], "ip link set %s up" % dev)
        frr_ns(pids[side], "ip link set lo up")
    for side, _, dev in SIDES:
        _start(pids[side], root, side, dev)
    end = time.time() + UP_WAIT
    while time.time() < end:
        if _up(NAME_A) and _up(NAME_B):
            break
        time.sleep(1.0)
    else:
        pytest.fail(
            "never came up\n%s"
            % sh("tail -n 20 %s %s" % (_log("a"), _log("b")), check=False)
        )
    # Past the handshake, whose first Up packet goes at once.
    time.sleep(2.0)
    return pids, root


def _teardown():
    for side, _, _ in SIDES:
        for p in _engine_pids(side):
            sh("sudo kill %d" % p, check=False)
    time.sleep(0.5)
    for side, _, _ in SIDES:
        sh(
            "sudo rm -rf %s /run/xdp-bfd/%s.pid"
            % (_pin(side), os.path.basename(_pin(side))),
            check=False,
        )
    frr_rm(NAME_A)
    frr_rm(NAME_B)
    sh("sudo ip link del eth-a", check=False)


@pytest.fixture
def pair(request):
    try:
        yield _pair(request, "")
    finally:
        _teardown()


@pytest.fixture
def echo_pair(request):
    try:
        yield _pair(request, ECHO)
    finally:
        _teardown()


def test_echo_comes_back_on_both_ends(echo_pair):
    """Each program reflects the other's echoes and sees its own return, while
    the control packets keep their turn.
    """
    time.sleep(2.0)
    w = _window()
    for side, _, _ in SIDES:
        d = w[side]
        assert d["echo-returns"] > 0, "%s: none of its echoes came back: %r" % (side, d)
        assert d["reflected"] > 0, "%s: reflected none of the peer's: %r" % (side, d)
        assert d["too-fast"] == 0, "%s: %d packets came too fast" % (
            side,
            d["too-fast"],
        )
        assert _session(side)["down_events"] == 0, "%s flapped" % side


def test_takeover_on_one_end_is_not_seen_by_the_other(pair):
    """The other end's engine also answers in XDP; the handover must leave it
    nothing to time out on.
    """
    pids, root = pair
    before = _session("b")["down_events"]
    old = _engine_pids("a")
    _start(pids["a"], root, "a", "eth-a")
    end = time.time() + 10.0
    while time.time() < end and any(os.path.exists("/proc/%d" % p) for p in old):
        time.sleep(0.2)
    assert not any(
        os.path.exists("/proc/%d" % p) for p in old
    ), "the first engine stayed"
    # bfdd retries its data plane every 3s; the adopted session waits for it.
    time.sleep(10.0)
    log = sh("sudo cat %s" % _log("a"), check=False)
    assert "took over the program on eth-a" in log, log[-1500:]
    assert _up(NAME_A) and _up(NAME_B)
    assert _session("b")["down_events"] == before, "the peer engine saw the takeover"
    w = _window()
    for side, _, _ in SIDES:
        assert w[side]["too-fast"] == 0, "%s: %r" % (side, w[side])
