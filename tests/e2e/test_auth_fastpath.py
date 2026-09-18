"""An authenticated session on the fast path, end to end.

This is the one thing check-frr can never reach: stock bfdd will not
offload an authenticated session to a data plane it did not write, so the
handover of the authentication state from userspace to the program - the
transmit sequence seeded into bfd_sessions, the accept set pushed into
tx_config, and the digest the program then builds and verifies on its own
- was exercised only by the 64-session mesh. Two static engines with
--auth reproduce it in namespaces, which CI can run.

A on the fast path, B in pure userspace: that asymmetry is the point. B
signs in userspace with bfd_auth_build and verifies with bfd_auth_check;
A's replies are built by the XDP program from the accept set and the
seeded sequence. The session only reaches Up if the two agree, so Up is
the assertion.
"""

import time

import pytest

from conftest import (NS_A, NS_B, STATS, STATS_B, start_engine,
                      wait_both_up, only_session, dump)

KEY = "f4stp4ths3cr3t"


@pytest.mark.parametrize("auth", ["keyed-sha1", "meticulous-sha1"])
def test_authenticated_session_up_over_the_fast_path(rig, binary, bpf_obj,
                                                    auth):
    spec = ("--auth", "%s:5:%s" % (auth, KEY))

    if True:
        start_engine(binary, 4, ns=NS_A, stats=STATS,
                     kernel_tx="rig-a", xdp_mode="generic",
                     extra=("--bpf-obj", bpf_obj) + spec)
        start_engine(binary, 4, ns=NS_B, stats=STATS_B, extra=spec)
        wait_both_up()

        # Up is not enough on its own: a session whose fast path never
        # armed would still come up, answered from userspace the whole
        # time. last_ktx_us is the engine's record of the program having
        # transmitted, so it is what says the digest below was built in
        # the kernel and accepted by a userspace peer.
        end = time.time() + 5
        while time.time() < end:
            if only_session(NS_A, STATS).get("last_ktx_us", 0):
                return
            time.sleep(0.5)
        pytest.fail("the program never answered for an authenticated "
                    "session (last_ktx_us stayed 0)")


def test_fast_path_rejects_a_mismatched_key(rig, binary, bpf_obj):
    """The negative arm: the program must refuse a peer signing with a key
    it does not hold, rather than answering anything that arrives."""
    if True:
        start_engine(binary, 4, ns=NS_A, stats=STATS,
                     kernel_tx="rig-a", xdp_mode="generic",
                     extra=("--bpf-obj", bpf_obj, "--auth",
                            "keyed-sha1:5:%s" % KEY))
        start_engine(binary, 4, ns=NS_B, stats=STATS_B,
                     extra=("--auth", "keyed-sha1:5:a-different-key"))

        end = time.time() + 6
        while time.time() < end:
            if dump(NS_A, STATS)["sessions_up"]:
                pytest.fail("came up against a peer signing with another key")
            time.sleep(0.5)
