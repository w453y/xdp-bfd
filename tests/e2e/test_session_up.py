"""Fixture self-test: two static engines reach Up over the veth pair."""

import time

import pytest

from conftest import (
    NS_A,
    NS_B,
    STATS,
    STATS_B,
    DOWN_WAIT,
    sh,
    ns_pids,
    start_engine,
    dump,
    wait_both_up,
)


@pytest.mark.parametrize("family", [4, 6])
def test_two_static_engines_reach_up(rig, binary, family):
    start_engine(binary, family, ns=NS_A, stats=STATS)
    start_engine(binary, family, ns=NS_B, stats=STATS_B)
    wait_both_up()


@pytest.mark.parametrize("family", [4, 6])
def test_session_goes_down_when_peer_dies(rig, binary, family):
    """Otherwise Up could pass on a snapshot that never refreshes."""
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


# Stock bfdd will not offload an authenticated session, so check-frr cannot
# cover this.
AUTH_KEY = "sup3rs3cr3tk3y"


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("auth", ["simple", "keyed-sha1", "meticulous-sha1"])
def test_two_static_engines_reach_up_authenticated(rig, binary, family, auth):
    spec = ["--auth", "%s:5:%s" % (auth, AUTH_KEY)]
    start_engine(binary, family, ns=NS_A, stats=STATS, extra=spec)
    start_engine(binary, family, ns=NS_B, stats=STATS_B, extra=spec)
    wait_both_up()


@pytest.mark.parametrize("auth", ["keyed-sha1", "meticulous-sha1"])
def test_mismatched_key_never_comes_up(rig, binary, auth):
    """Otherwise the rows above pass with the digest unchecked."""
    start_engine(
        binary, 4, ns=NS_A, stats=STATS, extra=["--auth", "%s:5:%s" % (auth, AUTH_KEY)]
    )
    start_engine(
        binary,
        4,
        ns=NS_B,
        stats=STATS_B,
        extra=["--auth", "%s:5:a-different-key" % auth],
    )

    end = time.time() + 6
    while time.time() < end:
        if dump(NS_A, STATS)["sessions_up"]:
            pytest.fail("came up with mismatched keys")
        time.sleep(0.5)


def test_one_side_unauthenticated_never_comes_up(rig, binary):
    """The A bit and the session must agree both ways."""
    start_engine(
        binary, 4, ns=NS_A, stats=STATS, extra=["--auth", "keyed-sha1:5:%s" % AUTH_KEY]
    )
    start_engine(binary, 4, ns=NS_B, stats=STATS_B)

    end = time.time() + 6
    while time.time() < end:
        if dump(NS_A, STATS)["sessions_up"]:
            pytest.fail("an authenticated session came up against a bare peer")
        time.sleep(0.5)
