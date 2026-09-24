"""RFC 5880 s6.3: once Your Discriminator is known, it alone selects the
session, so a peer whose source address moves keeps the session Up. B's
packets are rewritten to a new source after both sides are Up; A runs the
program, which no longer finds the address pair.
"""

import time

import pytest

from conftest import (
    NS_A,
    NS_B,
    STATS,
    STATS_B,
    sh,
    start_engine,
    wait_both_up,
    dump,
)

MOVED = "10.77.0.3"


def test_session_survives_the_peer_address_moving(rig, binary, bpf_obj):
    if not sh("command -v iptables", check=False).strip():
        pytest.skip("no iptables")
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

    sh("sudo ip netns exec %s ip addr add %s/24 dev rig-b" % (NS_B, MOVED))
    sh(
        "sudo ip netns exec %s iptables -t nat -A POSTROUTING -p udp --dport 3784"
        " -j SNAT --to-source %s" % (NS_B, MOVED)
    )
    # On B's egress: XDP on A drops before tcpdump there would see it.
    out = sh(
        "sudo ip netns exec %s timeout 2 tcpdump -n -c 3 -i rig-b"
        " 'udp dst port 3784 and src host %s' 2>/dev/null" % (NS_B, MOVED),
        check=False,
    )
    assert MOVED in out, "the rewrite did not take; nothing arrived from %s" % MOVED
    # Several detection times at the default 300ms x 3.
    time.sleep(5)

    a = dump(NS_A, STATS)
    b = dump(NS_B, STATS_B)
    assert (
        a["sessions_up"] == 1 and b["sessions_up"] == 1
    ), "went down after the peer's address moved: A=%d B=%d" % (
        a["sessions_up"],
        b["sessions_up"],
    )
    assert a["sessions"][0]["down_events"] == 0, "A went down and came back"
