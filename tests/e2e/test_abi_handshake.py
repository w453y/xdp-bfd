"""The engine refuses a kernel object built against another ABI and accepts its
own; two structs' BTF depends on the witness in maps.h.
"""

import os
import shutil
import subprocess

import pytest

from conftest import NS_A, sh, setup, teardown

# tx_cfg sits behind a map pointer, so a grown one still loads and only the ABI
# check refuses it; growing session_state would fail the verifier.
SKEW = ("	__u32 my_disc;", "	__u32 my_disc;\n	__u32 abi_skew_probe;")


def run_engine(binary, obj, secs=8):
    """A refusal happens at startup; the timeout bounds success."""
    cmd = (
        "sudo timeout %d ip netns exec %s %s 10.0.0.1 10.0.0.2"
        " --kernel-tx lo --xdp-mode generic --bpf-obj %s" % (secs, NS_A, binary, obj)
    )
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
    """Built from a copy of the tree, so a failure cannot leave the fake field
    behind.
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

    r = subprocess.run(
        "make -C %s bfd_xdp.o" % src, shell=True, capture_output=True, text=True
    )
    obj = os.path.join(str(src), "bfd_xdp.o")
    if r.returncode or not os.path.exists(obj):
        pytest.skip("cannot build a skewed object here: %s" % (r.stderr or r.stdout))
    # The engine runs under sudo from a pytest tmp dir.
    sh("chmod -R a+rX %s" % src)
    return obj


def test_the_matching_object_is_accepted(rig, skewed_obj):
    out = run_engine(str(rig / "bfd_tx"), str(rig / "bfd_xdp.o"))
    assert "refusing to load" not in out, (
        "the engine rejected its own freshly built object:\n%s" % out
    )
    assert "XDP attached" in out, "engine did not attach with its own object:\n%s" % out


def test_a_skewed_object_is_refused(rig, skewed_obj):
    out = run_engine(str(rig / "bfd_tx"), skewed_obj)
    assert "refusing to load" in out, (
        "engine accepted an object whose tx_cfg is 4 bytes" " longer:\n%s" % out
    )
    assert "tx_cfg" in out, "refusal did not name the struct that differs:\n%s" % out
    assert "XDP attached" not in out, "engine attached anyway after refusing:\n%s" % out
