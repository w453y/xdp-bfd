"""--max-sessions sizes the table, the program's maps and the source-port
block, which is the top of the range.
"""

import json
import re
import time

from conftest import NS_A, NS_B, STATS, STATS_B, sh, start_engine, wait_both_up
from lib.netns import IP_A

N = 256
CAP = "/tmp/bfd_rig_maxs.txt"


def test_max_sessions_sizes_maps_and_ports(rig, binary, bpf_obj):
    sh("sudo rm -f %s" % CAP)
    sh(
        "sudo ip netns exec %s nohup timeout 30 tcpdump -n -l -i rig-b"
        " 'udp dst port 3784 and src host %s' >%s 2>/dev/null &" % (NS_B, IP_A, CAP),
        capture=False,
    )
    time.sleep(1)
    start_engine(
        binary,
        4,
        ns=NS_A,
        stats=STATS,
        kernel_tx="rig-a",
        xdp_mode="generic",
        extra=("--bpf-obj", bpf_obj, "--max-sessions", str(N)),
    )
    start_engine(binary, 4, ns=NS_B, stats=STATS_B)
    wait_both_up()
    sh("sudo ip netns exec %s pkill -x tcpdump" % NS_B, check=False)
    time.sleep(0.5)

    xdp = json.loads(sh("sudo ip netns exec %s ip -j link show rig-a" % NS_A))[0]["xdp"]
    prog = json.loads(sh("sudo bpftool prog show id %d -j" % xdp["prog"]["id"]))
    sizes = {}
    for mid in prog["map_ids"]:
        m = json.loads(sh("sudo bpftool map show id %d -j" % mid))
        sizes[m["name"]] = m["max_entries"]
    for name in (
        "bfd_sessions",
        "tx_config",
        "echo_peers",
        "echo_disc",
        "our_discs",
        "auth_seq",
    ):
        assert sizes.get(name) == N, "%s has %r entries, want %d" % (
            name,
            sizes.get(name),
            N,
        )

    ports = {
        int(p)
        for p in re.findall(r"IP %s\.(\d+) > " % re.escape(IP_A), open(CAP).read())
    }
    assert ports == {65536 - N}, "sent from %r, want slot 0 at %d" % (
        sorted(ports),
        65536 - N,
    )


def test_max_sessions_out_of_range_is_refused(binary):
    for bad in ("63", "8193", "x"):
        out = sh(
            "%s --dplane 50799 --max-sessions %s 2>&1; echo rc=$?" % (binary, bad),
            check=False,
        )
        assert "rc=1" in out and "--max-sessions" in out, out
