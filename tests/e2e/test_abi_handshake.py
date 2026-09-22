"""The engine refuses a kernel object built against a different ABI, and
accepts a matching one. The positive arm matters as much: BTF for two of
the five structs depends on a witness in maps.h.
"""

import os
import shutil
import subprocess

import pytest

from conftest import NS_A, sh, setup, teardown

# Skew tx_cfg: it is reached through a map pointer and costs no stack, so the
# skewed object still loads and only the ABI check stands in the way. Growing
# session_state instead would fail the verifier's stack limit regardless.
SKEW = ("	__u32 my_disc;", "	__u32 my_disc;\n	__u32 abi_skew_probe;")


def run_engine(binary, obj, secs=8):
    """Run the engine in the foreground and return its output; a refusal
    happens at startup. The timeout bounds the success case.
    """
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
    """A kernel object built from a copy of this tree with one struct grown,
    so a failure cannot leave the fake field in the working tree.
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
    # World-readable: the engine runs under sudo out of a pytest tmp dir.
    sh("chmod -R a+rX %s" % src)
    return obj


def test_the_matching_object_is_accepted(rig, skewed_obj):
    """The object this tree just built must load."""
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
