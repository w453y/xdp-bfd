#!/usr/bin/env python3
"""Userspace parity rig: the socket path, in namespaces, on one machine.

inject_matrix.py asserts on BPF counters, so it can only ever test the XDP
path. Everything the engine does when a packet reaches userspace - the
shared acceptance predicate, GTSM on the sockets, the demux - has no
coverage at all, and two of this branch's fixes live there.

This runs the engine in STATIC mode (no --dplane, no --kernel-tx), so every
packet goes through recvmsg and fsm_rx. Assertions come from the SIGUSR1
stats snapshot, whose per-session rx_pkts only became a real number when
the counter-fidelity fix landed; before that it was structurally zero and
nothing here would have been possible.

No scapy and no raw sockets: the userspace path receives UDP datagrams, so
a plain socket with IP_TTL set reaches every check worth testing. Layer-2
and IP-header cases (fragments, options) are XDP-path concerns and stay in
inject_matrix.py where the counters can see them.

Two namespaces on a veth pair, addresses in 10.77.0.0/24, so nothing here
touches the live mesh on ens19. Needs root.
"""

import argparse
import json
import os
import shlex
import struct
import subprocess
import sys
import time

NS_A = "bfdrig-a"          # engine
NS_B = "bfdrig-b"          # injector
IP_A = "10.77.0.1"
IP_B = "10.77.0.2"
IP_A6 = "fd77::1"
IP_B6 = "fd77::2"
STATS = "/tmp/bfd_rig_stats.json"
COUNT = 10
SETTLE = 0.6

BFD_PORT = 3784
F_AUTH = 0x04
F_MP = 0x01


def sh(cmd, check=True, capture=True):
    """capture=False for anything that leaves a process behind: a captured
    pipe is not closed until every inheritor exits."""
    kw = dict(shell=True, text=True)
    if capture:
        kw["capture_output"] = True
    else:
        kw["stdout"] = subprocess.DEVNULL
        kw["stderr"] = subprocess.DEVNULL
    r = subprocess.run(cmd, **kw)
    if check and r.returncode:
        sys.exit("failed: %s\n%s%s" % (cmd, r.stdout or "", r.stderr or ""))
    return r.stdout or ""


def teardown():
    for ns in (NS_A, NS_B):
        sh("sudo ip netns pids %s 2>/dev/null | xargs -r sudo kill" % ns,
           check=False)
    sh("sudo ip netns del %s" % NS_A, check=False)
    sh("sudo ip netns del %s" % NS_B, check=False)


def setup():
    teardown()
    sh("sudo ip netns add %s" % NS_A)
    sh("sudo ip netns add %s" % NS_B)
    sh("sudo ip link add rig-a netns %s type veth peer name rig-b netns %s"
       % (NS_A, NS_B))
    for ns, dev, ip, ip6 in ((NS_A, "rig-a", IP_A, IP_A6),
                             (NS_B, "rig-b", IP_B, IP_B6)):
        sh("sudo ip netns exec %s ip addr add %s/24 dev %s" % (ns, ip, dev))
        # nodad: a fresh v6 address is tentative for about a second and
        # unusable as a source, so the engine's bind to its local
        # address would fail and fall back to an ephemeral socket - a
        # different path from the one under test.
        sh("sudo ip netns exec %s ip addr add %s/64 dev %s nodad"
           % (ns, ip6, dev))
        sh("sudo ip netns exec %s ip link set %s up" % (ns, dev))
        sh("sudo ip netns exec %s ip link set lo up" % ns)


def engine_pids():
    """Processes actually inside the engine namespace.

    NOT pkill -f on the command line: -f matches the full argv, so the
    sudo and `ip netns exec` wrappers match the same pattern, and
    SIGUSR1 terminates by default - the first dump killed the wrappers
    and the engine went with them. sudo runs before `ip netns exec`, so
    it is never inside the namespace and this cannot pick it up.
    """
    out = sh("sudo ip netns pids %s" % NS_A, check=False)
    return [int(x) for x in out.split()]


def start_engine(binary, fam):
    # The engine runs under sudo, so the snapshot is root-owned and
    # os.unlink from this process cannot touch it. The .tmp sibling
    # goes too, or a stale one could be renamed over a fresh run.
    sh("sudo rm -f %s %s.tmp" % (STATS, STATS))
    la, pa = (IP_A6, IP_B6) if fam == 6 else (IP_A, IP_B)
    sh("sudo ip netns exec %s nohup %s %s %s --stats-dump %s"
       " >>/tmp/bfd_rig_engine.log 2>&1 &" % (NS_A, binary, la, pa, STATS),
       capture=False)
    for _ in range(50):
        time.sleep(0.2)
        if engine_pids():
            return
    sys.exit("engine did not start; see /tmp/bfd_rig_engine.log")


def dump():
    pids = engine_pids()
    if not pids:
        sys.exit("engine is gone; see /tmp/bfd_rig_engine.log")
    sh("sudo kill -USR1 %s" % " ".join(str(x) for x in pids))
    time.sleep(0.3)
    with open(STATS) as f:
        return json.load(f)


def rx_pkts():
    d = dump()
    if not d["sessions"]:
        sys.exit("engine has no session")
    return d["sessions"][0]["rx_pkts"]


def bfd_bytes(vers=1, diag=0, state=1, flags=0, mult=3, length=24,
              my_disc=0xcafe0001, your_disc=0, min_tx=300000,
              min_rx=300000, min_echo=0, trunc=0):
    """A control packet, one field wrong at a time."""
    b = struct.pack("!BBBBIIIII",
                    ((vers & 7) << 5) | (diag & 0x1f),
                    ((state & 3) << 6) | (flags & 0x3f),
                    mult, length,
                    my_disc, your_disc, min_tx, min_rx, min_echo)
    return b[:len(b) - trunc] if trunc else b


def inject(payload, ttl, count, fam):
    """Send from the peer namespace over a plain UDP socket.

    The hop count is the only thing that needs setting - the single-hop
    sockets carry IP_MINTTL / IPV6_MINHOPCOUNT, so this is what exercises
    GTSM, and on v4 it has already shown that option to be inert."""
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
    # shlex.quote, not json.dumps: json double-quotes and escapes the
    # newlines, and the shell passes \n through double quotes
    # literally, so python receives a one-liner full of backslash-n.
    # inject_matrix.py hit this exact thing when it was written.
    sh("sudo ip netns exec %s python3 -c %s %s"
       % (NS_B, shlex.quote(prog), base64.b64encode(payload).decode()))


CASES = (
    # name, description, payload kwargs, ttl, expected rx delta
    ("accepted", "a well-formed packet at TTL 255 reaches the session",
     {}, 255, COUNT),
    ("gtsm", "a hop count below 255 is refused on a single-hop session",
     {}, 64, 0),
    ("bad-version", "BFD version other than 1",
     {"vers": 2}, 255, 0),
    ("zero-my-disc", "my_discriminator of zero is illegal",
     {"my_disc": 0}, 255, 0),
    ("zero-detect-mult", "detect multiplier of zero is illegal",
     {"mult": 0}, 255, 0),
    ("short-length", "length field below the 24-byte minimum",
     {"length": 20}, 255, 0),
    ("length-overruns", "length field claiming more than the datagram holds",
     {"length": 200}, 255, 0),
    ("truncated", "datagram ends before the BFD header does",
     {"trunc": 6}, 255, 0),
    ("auth-bit", "the A bit with no authentication configured",
     {"flags": F_AUTH}, 255, 0),
    ("mp-bit", "the M bit is reserved for multipoint",
     {"flags": F_MP}, 255, 0),
    ("disc-mismatch", "your_disc naming no session of ours",
     {"your_disc": 0x11111111, "state": 3}, 255, 0),
    ("accepted-again", "the injector still works after all the drops",
     {}, 255, COUNT),
)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--binary", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "bfd_tx"))
    p.add_argument("--only")
    p.add_argument("--keep", action="store_true",
                   help="leave the namespaces up for poking at")
    args = p.parse_args()

    binary = os.path.abspath(args.binary)
    if not os.path.exists(binary):
        sys.exit("no engine at %s; run make first" % binary)

    cases = [c for c in CASES if not args.only or c[0] == args.only]
    if not cases:
        sys.exit("no case named %r. Available: %s"
                 % (args.only, ", ".join(c[0] for c in CASES)))

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
                print("%-16s %s  rx %+d (expected %+d)   %s"
                      % ("%s-v%d" % (name, fam), "ok  " if ok else "FAIL",
                         got, expect, desc))
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
