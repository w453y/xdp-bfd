"""Authentication on the fast path. Stock bfdd will not offload it, so two static
engines stand in: A in XDP, B in userspace; Up needs their digests to agree.
"""

import time

import pytest

from conftest import (
    NS_A,
    NS_B,
    STATS,
    STATS_B,
    start_engine,
    wait_both_up,
    only_session,
    dump,
)

KEY = "f4stp4ths3cr3t"


@pytest.mark.parametrize("auth", ["keyed-sha1", "meticulous-sha1"])
def test_authenticated_session_up_over_the_fast_path(rig, binary, bpf_obj, auth):
    spec = ("--auth", "%s:5:%s" % (auth, KEY))

    if True:
        start_engine(
            binary,
            4,
            ns=NS_A,
            stats=STATS,
            kernel_tx="rig-a",
            xdp_mode="generic",
            extra=("--bpf-obj", bpf_obj) + spec,
        )
        start_engine(binary, 4, ns=NS_B, stats=STATS_B, extra=spec)
        wait_both_up()

        # last_ktx_us shows the program transmitted.
        end = time.time() + 5
        while time.time() < end:
            if only_session(NS_A, STATS).get("last_ktx_us", 0):
                return
            time.sleep(0.5)
        pytest.fail(
            "the program never answered for an authenticated "
            "session (last_ktx_us stayed 0)"
        )


def test_fast_path_rejects_a_mismatched_key(rig, binary, bpf_obj):
    """A key it does not hold is refused, not answered."""
    if True:
        start_engine(
            binary,
            4,
            ns=NS_A,
            stats=STATS,
            kernel_tx="rig-a",
            xdp_mode="generic",
            extra=("--bpf-obj", bpf_obj, "--auth", "keyed-sha1:5:%s" % KEY),
        )
        start_engine(
            binary,
            4,
            ns=NS_B,
            stats=STATS_B,
            extra=("--auth", "keyed-sha1:5:a-different-key"),
        )

        end = time.time() + 6
        while time.time() < end:
            if dump(NS_A, STATS)["sessions_up"]:
                pytest.fail("came up against a peer signing with another key")
            time.sleep(0.5)
