"""Fixture self-test: two static engines reach Up over the veth pair.

Both run pure userspace. No --kernel-tx on either side: two RX-clocked
engines facing each other is 04-symmetric-deployment's ping-pong premise
and belongs in a deliberate experiment, not in the baseline fixture.
"""

import time

import pytest

from conftest import (NS_A, NS_B, STATS, STATS_B, DOWN_WAIT, sh, ns_pids,
                      start_engine, dump, wait_both_up)


@pytest.mark.parametrize("family", [4, 6])
def test_two_static_engines_reach_up(rig, binary, family):
    start_engine(binary, family, ns=NS_A, stats=STATS)
    start_engine(binary, family, ns=NS_B, stats=STATS_B)
    wait_both_up()


@pytest.mark.parametrize("family", [4, 6])
def test_session_goes_down_when_peer_dies(rig, binary, family):
    """Negative arm. Without it the Up assertion could pass on a snapshot
    that is never actually refreshed."""
    start_engine(binary, family, ns=NS_A, stats=STATS)
    start_engine(binary, family, ns=NS_B, stats=STATS_B)
    wait_both_up()

    for pid in ns_pids(NS_B):
        sh("sudo kill -KILL %d" % pid, check=False)

    end = time.time() + DOWN_WAIT
    while time.time() < end:
        if dump(NS_A, STATS)["sessions_up"] == 0:
            return
        time.sleep(0.25)
    pytest.fail("A still reports 1 up %.0fs after killing B" % DOWN_WAIT)
