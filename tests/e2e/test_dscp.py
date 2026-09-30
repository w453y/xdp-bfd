"""Every control packet carries CS6, as bfdd marks them: sent by userspace and
answered by the program alike.
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
from lib.netns import IP_A, IP_B

CAP = "/tmp/bfd_rig_dscp.txt"
TOS = re.compile(r"IP \(tos (0x[0-9a-f]+),.*\n\s+(\S+)\.\d+ > ")


def test_control_packets_are_cs6(rig, binary, bpf_obj):
    sh("sudo rm -f %s" % CAP)
    sh(
        "sudo ip netns exec %s nohup timeout 30 tcpdump -n -l -v -i rig-b"
        " udp dst port 3784 >%s 2>/dev/null &" % (NS_B, CAP),
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

    seen = TOS.findall(out)
    assert only_session(NS_A, STATS)["tx_pkts"], "userspace sent nothing"
    for ip in (IP_A, IP_B):
        tos = {t for t, src in seen if src == ip}
        assert tos, "captured nothing from %s:\n%s" % (ip, out[:400])
        assert tos == {"0xc0"}, "%s sent TOS %r, want only 0xc0" % (ip, sorted(tos))
