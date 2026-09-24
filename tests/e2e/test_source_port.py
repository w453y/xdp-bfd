"""RFC 5881 s4: one source port per session, in 49152-65535, from both planes,
even when the session's own port is taken.
"""

import re
import time

from conftest import (
    NS_A,
    NS_B,
    STATS,
    STATS_B,
    sh,
    start_engine,
    wait_both_up,
    only_session,
)
from lib.netns import IP_A

SLOT0_PORT = 65472  # BFD_SRC_PORT + slot 0
CAP = "/tmp/bfd_rig_sport.txt"
SPORT = re.compile(r"IP %s\.(\d+) > " % re.escape(IP_A))


def _hold_port(ns, ip, port):
    sh(
        "sudo ip netns exec %s nohup python3 -c 'import socket, time;"
        ' s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("%s", %d));'
        " time.sleep(3600)' >/dev/null 2>&1 &" % (ns, ip, port),
        capture=False,
    )
    end = time.time() + 5
    while time.time() < end:
        if ":%d " % port in sh("sudo ip netns exec %s ss -Huan" % ns, check=False):
            return
        time.sleep(0.1)
    raise AssertionError("could not hold %s:%d in %s" % (ip, port, ns))


def test_one_source_port_when_the_slot_port_is_taken(rig, binary, bpf_obj):
    """From before the engines start, so userspace's bring-up packets are in it
    as well as the program's replies after.
    """
    _hold_port(NS_A, IP_A, SLOT0_PORT)
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
        extra=("--bpf-obj", bpf_obj),
    )
    start_engine(binary, 4, ns=NS_B, stats=STATS_B)
    wait_both_up()

    end = time.time() + 5
    while not only_session(NS_A, STATS).get("last_ktx_us", 0):
        assert time.time() < end, "the program never answered"
        time.sleep(0.5)
    time.sleep(1)
    sh("sudo ip netns exec %s pkill -x tcpdump" % NS_B, check=False)
    time.sleep(0.5)
    out = open(CAP).read()

    ports = [int(p) for p in SPORT.findall(out)]
    assert only_session(NS_A, STATS)["tx_pkts"], "userspace sent nothing"
    assert ports, "captured nothing from %s:\n%s" % (IP_A, out[:400])
    assert len(set(ports)) == 1, "one session, several source ports: %r" % sorted(
        set(ports)
    )
    assert 49152 <= ports[0] <= 65535, (
        "source port %d is outside 49152-65535" % ports[0]
    )
    assert ports[0] != SLOT0_PORT, "sent from the port another socket holds"
