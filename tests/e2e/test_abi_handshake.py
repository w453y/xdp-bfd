"""The engine refuses a kernel program built against a different ABI.

tests/unit/abi_check.c pins every shared struct at compile time and cannot
see this failure: bfd_tx and bfd_xdp.o are separate artifacts, built at
separate times, paired at runtime by a path. An engine built against a
newer bfd_shared.h loading an older object gets no complaint from anyone -
the verifier has no opinion, the map accepts the key, and the two halves
then read the same bytes as different structs.

Both directions are asserted. The negative arm alone would pass just as
well against an engine that refuses everything, which is the more likely
way this breaks: the BTF records that make the comparison possible are
emitted only for types reachable from a map definition, so two of the five
are kept alive by a witness in maps.h that is easy to delete by accident.
Refusing the correct object is the worse outcome of the two and gets the
first test.
"""

import os
import shutil
import subprocess

import pytest

from conftest import NS_A, sh, setup, teardown

# One field in tx_cfg, which both halves read out of the config map.
#
# Deliberately not session_state, which was the first choice and is the
# wrong one: growing it by eight bytes pushes the packet path over the
# verifier's 512-byte combined stack budget, so the skewed object fails to
# load whether or not anything checks its ABI, and the test would pass
# against an engine with no check at all. The failure worth pinning is the
# silent one - an object the kernel is perfectly happy with, whose layout
# the engine disagrees about. tx_cfg is reached through a map pointer and
# costs no stack, so a skewed copy loads and runs, and this check is the
# only thing between it and sheared fields.
SKEW = ("	__u32 my_disc;", "	__u32 my_disc;\n	__u32 abi_skew_probe;")


def run_engine(binary, obj, secs=8):
    """Start the engine in the foreground and return what it printed.

    Foreground on purpose: a refusal is a startup-time event and the whole
    point is that it happens before anything is attached, so there is no
    running process to interrogate afterwards. The timeout bounds the
    success case, which does not exit on its own.
    """
    cmd = ("sudo timeout %d ip netns exec %s %s 10.0.0.1 10.0.0.2"
           " --kernel-tx lo --xdp-mode generic --bpf-obj %s"
           % (secs, NS_A, binary, obj))
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (r.stdout or "") + (r.stderr or "")


@pytest.fixture(scope="module")
def rig(request):
    setup()
    try:
        yield request.config.rootpath
    finally:
        if not request.config.getoption("--keep-ns"):
            teardown()


@pytest.fixture(scope="module")
def skewed_obj(rig, tmp_path_factory):
    """A kernel object built from this tree with one struct grown.

    Built from a copy rather than by editing the tree in place: a failure
    part way through would otherwise leave the working tree carrying a
    fake field, and the next `make` would install it in the real object.
    """
    src = tmp_path_factory.mktemp("abi-skew")
    for item in ("Makefile", "include", "src"):
        s = os.path.join(str(rig), item)
        d = os.path.join(str(src), item)
        if os.path.isdir(s):
            shutil.copytree(s, d)
        else:
            shutil.copy(s, d)

    hdr = os.path.join(str(src), "include", "bfd_shared.h")
    with open(hdr) as f:
        text = f.read()
    assert text.count(SKEW[0]) == 1, "session_state anchor moved"
    with open(hdr, "w") as f:
        f.write(text.replace(*SKEW))

    r = subprocess.run("make -C %s bfd_xdp.o" % src, shell=True,
                       capture_output=True, text=True)
    obj = os.path.join(str(src), "bfd_xdp.o")
    if r.returncode or not os.path.exists(obj):
        pytest.skip("cannot build a skewed object here: %s"
                    % (r.stderr or r.stdout))
    # World-readable: the engine runs under sudo out of a pytest tmp dir.
    sh("chmod -R a+rX %s" % src)
    return obj


def test_the_matching_object_is_accepted(rig, skewed_obj):
    """The object this tree just built must load."""
    out = run_engine(str(rig / "bfd_tx"), str(rig / "bfd_xdp.o"))
    assert "refusing to load" not in out, (
        "the engine rejected its own freshly built object:\n%s" % out)
    assert "XDP attached" in out, (
        "engine did not attach with its own object:\n%s" % out)


def test_a_skewed_object_is_refused(rig, skewed_obj):
    out = run_engine(str(rig / "bfd_tx"), skewed_obj)
    assert "refusing to load" in out, (
        "engine accepted an object whose tx_cfg is 4 bytes"
        " longer:\n%s" % out)
    assert "tx_cfg" in out, (
        "refusal did not name the struct that differs:\n%s" % out)
    assert "XDP attached" not in out, (
        "engine attached anyway after refusing:\n%s" % out)
