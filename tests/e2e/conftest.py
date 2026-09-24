"""End-to-end fixtures. Root: sudo python3 -m pytest tests/e2e"""

import json
import os
import sys
import tempfile
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
ROOT = os.path.dirname(TESTS)
sys.path.insert(0, TESTS)

from lib.netns import (
    NS_A,
    NS_B,
    STATS,
    STATS_B,
    sh,
    setup,
    teardown,
    ns_pids,
    start_engine,
    dump,
    engine_log,
)

UP_WAIT = 15.0
DOWN_WAIT = 10.0


def pytest_addoption(parser):
    parser.addoption(
        "--keep-ns", action="store_true", help="leave the namespaces up after the run"
    )


@pytest.fixture(autouse=True, scope="session")
def require_root():
    if os.geteuid() != 0:
        pytest.skip("needs root: sudo python3 -m pytest tests/e2e")


@pytest.fixture(scope="session")
def binary():
    p = os.path.join(ROOT, "bfd_tx")
    if not os.path.exists(p):
        pytest.skip("no bfd_tx at %s" % p)
    return p


@pytest.fixture(scope="session")
def bpf_obj():
    p = os.path.join(ROOT, "bfd_xdp.o")
    if not os.path.exists(p):
        pytest.skip("no bfd_xdp.o at %s" % p)
    return p


@pytest.fixture
def rig(request):
    setup()
    yield
    if not request.config.getoption("--keep-ns"):
        teardown()


def engine_tails():
    out = []
    for ns in (NS_A, NS_B):
        out.append(
            "--- %s\n%s"
            % (engine_log(ns), sh("tail -20 %s" % engine_log(ns), check=False))
        )
    return "\n".join(out)


def wait_both_up(timeout=UP_WAIT):
    a = b = None
    end = time.time() + timeout
    while time.time() < end:
        a = dump(NS_A, STATS)["sessions_up"]
        b = dump(NS_B, STATS_B)["sessions_up"]
        if a == 1 and b == 1:
            return
        time.sleep(0.5)
    raise AssertionError(
        "never came Up (A=%s B=%s after %.0fs)\n%s" % (a, b, timeout, engine_tails())
    )


def xdp_progs(ns, dev):
    """From `ip -d link show`; bpftool is missing on some runners."""
    out = sh("sudo ip netns exec %s ip -d link show %s" % (ns, dev), check=False)
    if not out.strip():
        raise AssertionError("no link %s in %s" % (dev, ns))
    progs = []
    for tok in out.split():
        if tok.startswith("prog/xdp"):
            progs.append(tok)
    if not progs and ("xdpgeneric" in out or " xdp " in out):
        progs.append("xdp")
    return progs


# FRR containers start with --network none and get a veth end by pid; `ip netns
# exec` + podman run remounts /sys without cgroup2 and crun refuses.
RUNTIME = os.environ.get("BFD_CONTAINER_RUNTIME", "podman")
FRR_IMAGE = os.environ.get("BFD_FRR_IMAGE", "quay.io/frrouting/frr:10.4.2")
NAME_A = "bfdrig-frr-a"  # engine's control plane, talks bfddp
NAME_B = "bfdrig-frr-b"  # the wire peer, plain stock bfdd

# The image's /etc/frr holds only daemons (bfdd=no), so mounting over it
# clobbers nothing.
DAEMONS = """zebra=yes
mgmtd=yes
bfdd=yes
staticd=yes
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bfdd_options="  -A 127.0.0.1%s"
staticd_options="  -A 127.0.0.1"
"""

# unixc: is broken in every FRR release through 10.7.1.
DPLANE_OPT = " --dplaneaddr ipv4c:127.0.0.1:50700"


def frr_rm(name):
    sh("sudo %s rm -f %s" % (RUNTIME, name), check=False)


def frr_start(name, confdir, image=None):
    """Returns the pid, to move a veth end in."""
    frr_rm(name)
    sh(
        "sudo %s run -d --name %s --network none --privileged -v %s:/etc/frr %s"
        % (RUNTIME, name, confdir, image or FRR_IMAGE),
        check=False,
    )
    for _ in range(50):
        out = sh(
            "sudo %s inspect -f '{{.State.Pid}}' %s" % (RUNTIME, name), check=False
        ).strip()
        if out.isdigit() and int(out) > 0:
            return int(out)
        time.sleep(0.2)
    raise AssertionError(
        "container %s did not start: %s"
        % (name, sh("sudo %s logs %s" % (RUNTIME, name), check=False))
    )


def frr_ns(pid, cmd):
    """Network namespace only, so the host's bfd_tx and bfd_xdp.o run inside."""
    return sh("sudo nsenter -t %d -n %s" % (pid, cmd), check=False)


def frr_daemon_pid(container_pid, comm):
    """Matched by PID namespace so the host's bfdd is never hit; `podman exec
    kill` does not work.
    """
    ns = sh("sudo readlink /proc/%d/ns/pid" % container_pid, check=False).strip()
    assert ns, "no pid namespace for container pid %d" % container_pid
    out = sh(
        "sudo ls /proc | grep -E '^[0-9]+$' | while read p; do"
        " c=$(cat /proc/$p/comm 2>/dev/null);"
        ' [ "$c" = %s ] && echo "$p $(readlink /proc/$p/ns/pid)";'
        " done" % comm,
        check=False,
    )
    hits = [int(l.split()[0]) for l in out.splitlines() if l.strip().endswith(ns)]
    assert len(hits) == 1, "expected one %s in %s, got %r\n%s" % (comm, ns, hits, out)
    return hits[0]


def frr_vtysh(name, cmd):
    return sh(
        "sudo %s exec %s vtysh -c %s" % (RUNTIME, name, json.dumps(cmd)), check=False
    )


def frr_conf_dir(daemons, conf):
    d = tempfile.mkdtemp(prefix="frr-rig-")
    open(os.path.join(d, "daemons"), "w").write(daemons)
    open(os.path.join(d, "frr.conf"), "w").write(conf)
    sh("chmod -R a+rX %s" % d)
    return d


def only_session(ns, stats):
    d = dump(ns, stats)
    assert d["sessions"], "%s has no session" % ns
    return d["sessions"][0]
