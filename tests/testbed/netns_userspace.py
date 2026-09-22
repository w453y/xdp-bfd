#!/usr/bin/env python3
"""Userspace parity rig: the socket path, in namespaces. Covers what the
engine does once a packet reaches userspace (acceptance predicate, GTSM,
demux), which inject_matrix.py's BPF counters cannot see. Static mode,
plain UDP sockets, assertions from the SIGUSR1 snapshot. Two namespaces
on a veth pair in 10.77.0.0/24; needs root.
"""

import argparse
import json
import os
import shlex
import struct
import subprocess
import sys
import time

COUNT = 10
SETTLE = 0.6

BFD_PORT = 3784
F_AUTH = 0x04
F_MP = 0x01


# The namespace helpers live in tests/lib, shared with the e2e suite.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib.netns import (
    NS_A,
    NS_B,
    IP_A,
    IP_B,
    IP_A6,
    IP_B6,
    STATS,
    sh,
    setup,
    teardown,
    ns_pids,
    start_engine,
    dump,
    engine_log,
)


def rx_pkts():
    d = dump()
    if not d["sessions"]:
        sys.exit("engine has no session")
    return d["sessions"][0]["rx_pkts"]


def bfd_bytes(
    vers=1,
    diag=0,
    state=1,
    flags=0,
    mult=3,
    length=24,
    my_disc=0xCAFE0001,
    your_disc=0,
    min_tx=300000,
    min_rx=300000,
    min_echo=0,
    trunc=0,
):
    """A control packet, one field wrong at a time."""
    b = struct.pack(
        "!BBBBIIIII",
        ((vers & 7) << 5) | (diag & 0x1F),
        ((state & 3) << 6) | (flags & 0x3F),
        mult,
        length,
        my_disc,
        your_disc,
        min_tx,
        min_rx,
        min_echo,
    )
    return b[: len(b) - trunc] if trunc else b


def inject(payload, ttl, count, fam):
    """Send from the peer namespace over a plain UDP socket; the hop count
    is what exercises GTSM.
    """
    if fam == 6:
        prog = (
            "import socket,sys,base64\n"
            "p=base64.b64decode(sys.argv[1])\n"
            "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)\n"
            "s.setsockopt(socket.IPPROTO_IPV6,"
            "socket.IPV6_UNICAST_HOPS,%d)\n"
            "s.bind(('%s',%d))\n"
            "for _ in range(%d): s.sendto(p,('%s',%d))\n"
        ) % (ttl, IP_B6, BFD_PORT, count, IP_A6, BFD_PORT)
    else:
        prog = (
            "import socket,sys,base64\n"
            "p=base64.b64decode(sys.argv[1])\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            "s.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,%d)\n"
            "s.bind(('%s',%d))\n"
            "for _ in range(%d): s.sendto(p,('%s',%d))\n"
        ) % (ttl, IP_B, BFD_PORT, count, IP_A, BFD_PORT)
    import base64

    # shlex.quote, not json.dumps, so the newlines survive the shell.
    sh(
        "sudo ip netns exec %s python3 -c %s %s"
        % (NS_B, shlex.quote(prog), base64.b64encode(payload).decode())
    )


CASES = (
    # name, description, payload kwargs, ttl, expected rx delta
    ("accepted", "a well-formed packet at TTL 255 reaches the session", {}, 255, COUNT),
    ("gtsm", "a hop count below 255 is refused on a single-hop session", {}, 64, 0),
    ("bad-version", "BFD version other than 1", {"vers": 2}, 255, 0),
    ("zero-my-disc", "my_discriminator of zero is illegal", {"my_disc": 0}, 255, 0),
    ("zero-detect-mult", "detect multiplier of zero is illegal", {"mult": 0}, 255, 0),
    ("short-length", "length field below the 24-byte minimum", {"length": 20}, 255, 0),
    (
        "length-overruns",
        "length field claiming more than the datagram holds",
        {"length": 200},
        255,
        0,
    ),
    ("truncated", "datagram ends before the BFD header does", {"trunc": 6}, 255, 0),
    (
        "auth-bit",
        "the A bit with no authentication configured",
        {"flags": F_AUTH},
        255,
        0,
    ),
    ("mp-bit", "the M bit is reserved for multipoint", {"flags": F_MP}, 255, 0),
    (
        "disc-mismatch",
        "your_disc naming no session of ours",
        {"your_disc": 0x11111111, "state": 3},
        255,
        0,
    ),
    ("accepted-again", "the injector still works after all the drops", {}, 255, COUNT),
)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--binary",
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..", "bfd_tx"
        ),
    )
    p.add_argument("--only")
    p.add_argument(
        "--keep", action="store_true", help="leave the namespaces up for poking at"
    )
    args = p.parse_args()

    binary = os.path.abspath(args.binary)
    if not os.path.exists(binary):
        sys.exit("no engine at %s; run make first" % binary)

    cases = [c for c in CASES if not args.only or c[0] == args.only]
    if not cases:
        sys.exit(
            "no case named %r. Available: %s"
            % (args.only, ", ".join(c[0] for c in CASES))
        )

    failures = 0
    for fam in (4, 6):
        setup()
        try:
            start_engine(binary, fam)
            time.sleep(1)
            for name, desc, kw, ttl, expect in cases:
                before = rx_pkts()
                inject(bfd_bytes(**kw), ttl, COUNT, fam)
                time.sleep(SETTLE)
                got = rx_pkts() - before
                ok = got == expect
                failures += not ok
                print(
                    "%-16s %s  rx %+d (expected %+d)   %s"
                    % (
                        "%s-v%d" % (name, fam),
                        "ok  " if ok else "FAIL",
                        got,
                        expect,
                        desc,
                    )
                )
        finally:
            if not args.keep:
                teardown()
        print()

    print()
    if failures:
        print("%d case(s) failed" % failures)
        return 1
    print("all cases passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
