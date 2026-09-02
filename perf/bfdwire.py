#!/usr/bin/env python3
"""One implementation of the wire arithmetic, shared by every perf script.

The numbers in docs/benchmarks/README.md came from inline awk typed at a
terminal. 03-testing asks for this because two sides computing percentiles
their own way can disagree silently, and because nothing reproduces the
published figures on demand.

Parses `tcpdump -tt -r` rather than the pcap directly: tcpdump captured
them, already decodes BFDv1, and needs no capture library on either side.
-tt gives epoch seconds, which avoids parsing HH:MM:SS and its hour wrap.
"""

import re
import subprocess

LINE = re.compile(
    r"^(\d+\.\d+) IP (\S+)\.(\d+) > (\S+)\.(\d+): BFDv1, Control, State (\w+)")


class Pkt:
    __slots__ = ("t", "src", "dst", "dport", "state")

    def __init__(self, t, src, dst, dport, state):
        self.t, self.src, self.dst = t, src, dst
        self.dport, self.state = dport, state


def read(path):
    # -n: no name resolution. Without it tcpdump renders 10.66.0.1 as
    # "bfd-dut" on a host whose /etc/hosts says so and numerically
    # everywhere else, so the parsed addresses depend on which
    # machine runs the harness. That broke CI on the first run.
    r = subprocess.run(["tcpdump", "-n", "-tt", "-r", path],
                       capture_output=True, text=True)
    pkts = []
    for line in r.stdout.splitlines():
        m = LINE.match(line)
        if m:
            pkts.append(Pkt(float(m.group(1)), m.group(2), m.group(4),
                            int(m.group(5)), m.group(6)))
    if not pkts:
        raise SystemExit(
            "no BFD control packets in %s\n"
            "tcpdump rc=%d, %d stdout lines. First three:\n%s\n"
            "stderr: %s"
            % (path, r.returncode, len(r.stdout.splitlines()),
               "\n".join(r.stdout.splitlines()[:3]) or "(none)",
               r.stderr.strip()[:200]))
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
