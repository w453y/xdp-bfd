"""Where the lab is, for anything that talks to it.

Every rig hardcoded the same five values, so a second testbed meant editing
each one and a contributor could not run any of them at all. Read from the
environment, defaulting to the testbed these numbers were measured on, so
the defaults stay honest and an override is one variable.

    BFD_PEER_HOST   ssh target for the far end of the mesh
    BFD_IFACE       interface the fast path attaches to on the DUT
    BFD_VTYSH       vtysh of the FRR build under test, not the distro one
    BFD_ENGINE      path to bfd_tx
    BFD_STATS       where SIGUSR1 writes its snapshot
    BFD_FRR_PREFIX  install prefix of that FRR build

The distro vtysh is a trap worth naming: it exists on this box, it answers,
and its daemons are not the ones running, so a rig that picks it up reports
an empty mesh rather than an error. That cost a debugging cycle once.
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
