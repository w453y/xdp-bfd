"""Namespace fixture shared by the netns rig
(tests/testbed/netns_userspace.py) and the e2e scenarios.
"""

import json
import os
import subprocess
import sys
import time

NS_A = "bfdrig-a"  # engine side
NS_B = "bfdrig-b"  # far end: injector, or a second engine
IP_A = "10.77.0.1"
IP_B = "10.77.0.2"
IP_A6 = "fd77::1"
IP_B6 = "fd77::2"
STATS = "/tmp/bfd_rig_stats.json"
STATS_B = "/tmp/bfd_rig_stats_b.json"


def sh(cmd, check=True, capture=True):
    """capture=False for anything that leaves a process behind: a captured
    pipe is not closed until every inheritor exits."""
    kw = dict(shell=True, text=True)
    if capture:
        kw["capture_output"] = True
    else:
        kw["stdout"] = subprocess.DEVNULL
        kw["stderr"] = subprocess.DEVNULL
    r = subprocess.run(cmd, **kw)
    if check and r.returncode:
        sys.exit("failed: %s\n%s%s" % (cmd, r.stdout or "", r.stderr or ""))
    return r.stdout or ""


def teardown():
    """TERM, wait, then KILL. `ip netns del` does not reap the namespace's
    processes, and a surviving engine keeps its XDP attach.
    """
    for ns in (NS_A, NS_B):
        sh("sudo ip netns pids %s 2>/dev/null | xargs -r sudo kill" % ns, check=False)
    for _ in range(20):
        left = sum(
            len(sh("sudo ip netns pids %s 2>/dev/null" % ns, check=False).split())
            for ns in (NS_A, NS_B)
        )
        if not left:
            break
        time.sleep(0.1)
    for ns in (NS_A, NS_B):
        sh(
            "sudo ip netns pids %s 2>/dev/null | xargs -r sudo kill -9" % ns,
            check=False,
        )
    sh("sudo ip netns del %s" % NS_A, check=False)
    sh("sudo ip netns del %s" % NS_B, check=False)


def setup():
    teardown()
    sh("sudo ip netns add %s" % NS_A)
    sh("sudo ip netns add %s" % NS_B)
    sh(
        "sudo ip link add rig-a netns %s type veth peer name rig-b netns %s"
        % (NS_A, NS_B)
    )
    for ns, dev, ip, ip6 in (
        (NS_A, "rig-a", IP_A, IP_A6),
        (NS_B, "rig-b", IP_B, IP_B6),
    ):
        sh("sudo ip netns exec %s ip addr add %s/24 dev %s" % (ns, ip, dev))
        # nodad: a tentative v6 address cannot be bound, so the engine would
        # fall back to an ephemeral socket.
        sh("sudo ip netns exec %s ip addr add %s/64 dev %s nodad" % (ns, ip6, dev))
        sh("sudo ip netns exec %s ip link set %s up" % (ns, dev))
        sh("sudo ip netns exec %s ip link set lo up" % ns)


def ns_pids(ns=NS_A):
    """Processes inside the engine namespace, from `ip netns pids`. Not
    pkill -f, which also matches the sudo and ip netns exec wrappers.
    """
    out = sh("sudo ip netns pids %s" % ns, check=False)
    return [int(x) for x in out.split()]


def engine_log(ns):
    return "/tmp/bfd_rig_%s.log" % ns


def start_engine(
    binary,
    fam=4,
    ns=NS_A,
    stats=STATS,
    local=None,
    peer=None,
    kernel_tx=None,
    xdp_mode=None,
    extra=(),
):
    """Start bfd_tx in static mode inside `ns`.

    local and peer default to this namespace's own address and the far
    end's, so a second engine facing the first is just
    start_engine(binary, ns=NS_B) with its own stats path.
    """
    if local is None or peer is None:
        a, b = (IP_A6, IP_B6) if fam == 6 else (IP_A, IP_B)
        local, peer = (a, b) if ns == NS_A else (b, a)
    # The snapshot is root-owned; remove it and any stale .tmp with sudo.
    sh("sudo rm -f %s %s.tmp" % (stats, stats))
    opts = ["--stats-dump", stats]
    if kernel_tx:
        opts += ["--kernel-tx", kernel_tx]
    if xdp_mode:
        opts += ["--xdp-mode", xdp_mode]
    opts += list(extra)
    log = engine_log(ns)
    sh(
        "sudo ip netns exec %s nohup %s %s %s %s >>%s 2>&1 &"
        % (ns, binary, local, peer, " ".join(opts), log),
        capture=False,
    )
    for _ in range(50):
        time.sleep(0.2)
        if ns_pids(ns):
            return
    sys.exit("engine did not start in %s; see %s" % (ns, log))


def dump(ns=NS_A, stats=STATS):
    """SIGUSR1 the engine in `ns` and read its snapshot, waiting for the
    rename so a stale file is never read.
    """
    pids = ns_pids(ns)
    if not pids:
        sys.exit("engine is gone in %s; see %s" % (ns, engine_log(ns)))
    sh("sudo rm -f %s %s.tmp" % (stats, stats))
    sh("sudo kill -USR1 %s" % " ".join(str(x) for x in pids))
    for _ in range(40):
        time.sleep(0.1)
        if os.path.exists(stats):
            with open(stats) as f:
                return json.load(f)
    sys.exit("no snapshot at %s after SIGUSR1; see %s" % (stats, engine_log(ns)))


def _one(out):
    """bpftool -j returns a list for `show id`, a dict for some others."""
    d = json.loads(out)
    return d[0] if isinstance(d, list) else d


def bpf_map_for_dev(dev, name, ns_pid=None):
    """Dump map `name` of the XDP program on `dev`, resolved by program id,
    since a map-name lookup matches every engine loaded. ns_pid runs the
    net show inside that pid's namespace.
    """
    pre = "sudo nsenter -t %d -n " % ns_pid if ns_pid else "sudo "
    xdp = _one(sh(pre + "bpftool net show dev %s -j" % dev))["xdp"]
    if not xdp:
        raise AssertionError("no XDP program on %s" % dev)
    prog = _one(sh("sudo bpftool prog show id %d -j" % xdp[0]["id"]))
    for mid in prog.get("map_ids", []):
        if _one(sh("sudo bpftool map show id %d -j" % mid)).get("name") == name:
            # No -j: with BTF, the plain dump is JSON with named fields.
            return json.loads(sh("sudo bpftool map dump id %d" % mid))
    raise AssertionError("prog %d has no map named %s" % (xdp[0]["id"], name))
