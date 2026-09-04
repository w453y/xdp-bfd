#!/usr/bin/env python3
"""One implementation of the wire arithmetic, shared by every perf script.

The numbers in benchmarks/README.md came from inline awk typed at a
terminal. 03-testing asks for this because two sides computing percentiles
their own way can disagree silently, and because nothing reproduces the
published figures on demand.

Parses `tcpdump -tt -r` rather than the pcap directly: tcpdump captured
them, already decodes BFDv1, and needs no capture library on either side.
-tt gives epoch seconds, which avoids parsing HH:MM:SS and its hour wrap.
"""

import re
import subprocess

HDR = re.compile(r"^(\d+\.\d+) IP (\S+)\.(\d+) > (\S+)\.(\d+):")
HEX = re.compile(r"^\s+0x[0-9a-f]+:\s+(.*)$")
STATE = {0: "AdminDown", 1: "Down", 2: "Init", 3: "Up"}


class Pkt:
    __slots__ = ("t", "src", "dst", "dport", "state")

    def __init__(self, t, src, dst, dport, state):
        self.t, self.src, self.dst = t, src, dst
        self.dport, self.state = dport, state


def read(path):
    """Parse the BFD state out of the HEX, not out of tcpdump's decode.

    Ubuntu's tcpdump 4.99.4 renders UDP/3784 as BCM-LI-SHIM (a Broadcom
    lawful-intercept shim that claims the same port) while 4.99.6 renders
    it as BFDv1. Depending on the dissector meant the harness worked on the
    machine it was written on and produced zero packets in CI. -x gives the
    L3 payload and the header layout is fixed: 20 bytes IP (ihl 5, which a
    BFD control packet always is - the engine drops options), 8 UDP, then
    BFD, whose second byte carries the state in its top two bits.
    """
    r = subprocess.run(["tcpdump", "-n", "-tt", "-x", "-r", path],
                       capture_output=True, text=True)
    pkts, pend, blob = [], None, ""

    def flush():
        if pend is None:
            return
        b = bytes.fromhex(blob)
        if len(b) < 30 or (b[0] >> 4) != 4 or (b[0] & 0x0f) != 5:
            return
        if int.from_bytes(b[22:24], "big") not in (3784, 4784):
            return
        pkts.append(Pkt(pend[0], pend[1], pend[2], pend[3],
                        STATE.get(b[29] >> 6, "?")))

    for line in r.stdout.splitlines():
        m = HDR.match(line)
        if m:
            flush()
            pend = (float(m.group(1)), m.group(2), m.group(4), int(m.group(5)))
            blob = ""
            continue
        h = HEX.match(line)
        if h and pend is not None:
            blob += h.group(1).replace(" ", "")
    flush()

    if not pkts:
        raise SystemExit(
            "no BFD control packets in %s\ntcpdump rc=%d, %d lines\n%s"
            % (path, r.returncode, len(r.stdout.splitlines()),
               "\n".join(r.stdout.splitlines()[:3])))
    return pkts


def gaps_ms(pkts, src):
    """Inter-departure gaps for one sender, in milliseconds."""
    ts = [p.t for p in pkts if p.src == src]
    return [(b - a) * 1000.0 for a, b in zip(ts, ts[1:])]


def flaps(pkts, src):
    """Flaps as the README counts them: CHANGES in the sender\'s state field,
    divided by two, because one flap is Up->Down plus Down->Up.

    Not a count of Down packets - a session sits in Down for many packets
    while it recovers. bench1-bfdd has 331 Down packets and 107 flaps."""
    states = [p.state for p in pkts if p.src == src]
    changes = sum(1 for a, b in zip(states, states[1:]) if a != b)
    return changes // 2, changes


def pct(vals, q):
    """Linear-interpolated percentile, the definition the published numbers
    used.

    Found by reproducing them rather than by assuming: nearest-rank agrees
    with the README on results 1 and 3, where n is in the thousands and the
    two definitions converge, but disagrees on result 2 at n=20 - nearest
    rank makes p99 equal max (32.63), while the README has p99 32.4 against
    max 32.6. That is exactly the silent disagreement 03-testing wanted one
    shared implementation to prevent."""
    if not vals:
        return float("nan")
    s = sorted(vals)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * q
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def summary(vals):
    if not vals:
        return {}
    return {"n": len(vals), "min": min(vals), "mean": sum(vals) / len(vals),
            "p50": pct(vals, 0.50), "p99": pct(vals, 0.99),
            "p999": pct(vals, 0.999), "max": max(vals)}


def detect_ms(pkts, dut, peer):
    """Detection latency: the peer's last packet before each DUT Down, to
    that Down. One sample per detection EVENT, taking the first Down of
    each run - the DUT sends several while it waits to recover, and
    counting all of them would inflate n fourfold.

    bench2-detect-dist has 80 DUT Down packets across 20 kills."""
    out, in_down, last_peer = [], False, None
    for p in pkts:
        if p.src == peer:
            last_peer = p.t
        if p.src != dut:
            continue
        if p.state == "Down":
            if not in_down and last_peer is not None:
                out.append((p.t - last_peer) * 1000.0)
            in_down = True
        else:
            in_down = False
    return out
