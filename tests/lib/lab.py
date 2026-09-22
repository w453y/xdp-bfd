"""Where the lab is. Read from the environment; the defaults describe the
reference testbed.

    BFD_PEER_HOST   ssh target for the far end of the mesh
    BFD_IFACE       interface the fast path attaches to on the DUT
    BFD_VTYSH       vtysh of the FRR build under test, not the distro one
    BFD_ENGINE      path to bfd_tx
    BFD_STATS       where SIGUSR1 writes its snapshot
    BFD_DPLANE      the engine's --dplane argument
    BFD_FRR_PREFIX  install prefix of that FRR build
    BFD_FRRINIT     frrinit.sh of that FRR build
"""

import os

PEER_HOST = os.environ.get("BFD_PEER_HOST", "w453y@10.66.0.2")
IFACE = os.environ.get("BFD_IFACE", "ens19")
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
ENGINE = os.environ.get("BFD_ENGINE", os.path.join(_ROOT, "bfd_tx"))
STATS = os.environ.get("BFD_STATS", "/tmp/bfd_tx_stats.json")
DPLANE = os.environ.get("BFD_DPLANE", "50700")

FRR_PREFIX = os.environ.get("BFD_FRR_PREFIX", "/opt/frr-master")
VTYSH = os.environ.get("BFD_VTYSH", FRR_PREFIX + "/bin/vtysh")
FRRINIT = os.environ.get("BFD_FRRINIT", FRR_PREFIX + "/sbin/frrinit.sh")
# frrinit.sh needs the stack's own libfrr; sudo drops the ambient
# environment, so it is passed as an assignment instead.
FRR_ENV = "LD_LIBRARY_PATH=" + FRR_PREFIX + "/lib"
