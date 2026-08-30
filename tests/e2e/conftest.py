"""Fixtures for the Layer 3 end-to-end scenarios.

Runs under sudo: `sudo python3 -m pytest tests/e2e`. The namespace
plumbing lives in tests/lib/netns.py, shared with tests/netns_userspace.py.
"""

import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
ROOT = os.path.dirname(TESTS)
sys.path.insert(0, TESTS)

from lib.netns import (NS_A, NS_B, STATS, STATS_B, sh, setup, teardown,
                       ns_pids, start_engine, dump, engine_log)

UP_WAIT = 15.0
DOWN_WAIT = 10.0


def pytest_addoption(parser):
    parser.addoption("--keep-ns", action="store_true",
                     help="leave the namespaces up after the run")


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
        out.append("--- %s\n%s"
                   % (engine_log(ns), sh("tail -20 %s" % engine_log(ns),
                                         check=False)))
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
    raise AssertionError("never came Up (A=%s B=%s after %.0fs)\n%s"
                         % (a, b, timeout, engine_tails()))


def xdp_progs(ns, dev):
    """Programs attached to dev, as a list.

    Reads `ip -d link show`, not bpftool: iproute2 is on every runner
    while bpftool lives in linux-tools-<uname -r>, which has no package
    for some kernels, and these cases were skipping in CI because of it.

    NOT a substring match on `bpftool net show` either - that prints its
    section headers unconditionally, so "xdp" matches whether or not
    anything is attached. That produced a vacuously passing assertion
    once already. `ip -d` prints an xdp/xdpgeneric clause only when a
    program is actually attached, so presence is the signal.
    """
    out = sh("sudo ip netns exec %s ip -d link show %s" % (ns, dev),
             check=False)
    if not out.strip():
        raise AssertionError("no link %s in %s" % (dev, ns))
    progs = []
    for tok in out.split():
        if tok.startswith("prog/xdp"):
            progs.append(tok)
    if not progs and ("xdpgeneric" in out or " xdp " in out):
        # Attached but the prog/xdp detail line is absent: still attached.
        progs.append("xdp")
    return progs


def only_session(ns, stats):
    d = dump(ns, stats)
    assert d["sessions"], "%s has no session" % ns
    return d["sessions"][0]
