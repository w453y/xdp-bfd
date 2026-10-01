"""--spread-pass: traffic that is not BFD still reaches the host, by way of
the cpumap, and the session it shares the link with stays Up."""

from conftest import (
    NS_A,
    NS_B,
    STATS,
    STATS_B,
    sh,
    setup,
    teardown,
    start_engine,
    wait_both_up,
    engine_log,
)
from lib.netns import IP_A


def test_other_traffic_still_arrives(request):
    root = request.config.rootpath
    setup()
    sh("sudo truncate -s 0 %s" % engine_log(NS_A), check=False)
    try:
        start_engine(
            str(root / "bfd_tx"),
            4,
            ns=NS_A,
            stats=STATS,
            kernel_tx="rig-a",
            xdp_mode="generic",
            extra=("--bpf-obj", str(root / "bfd_xdp.o"), "--spread-pass"),
        )
        start_engine(str(root / "bfd_tx"), 4, ns=NS_B, stats=STATS_B)
        wait_both_up()
        log = sh("sudo cat %s" % engine_log(NS_A), check=False)
        assert "other traffic spread over" in log, log
        out = sh(
            "sudo ip netns exec %s ping -c 50 -i 0.02 -q %s" % (NS_B, IP_A),
            check=False,
        )
        assert " 0% packet loss" in out, out
        wait_both_up()
    finally:
        teardown()
