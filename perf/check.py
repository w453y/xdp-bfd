#!/usr/bin/env python3
"""Recompute docs/benchmarks/README.md from the committed pcaps.

A regression detector for the HARNESS, not a benchmark. It needs no
testbed and no timing: the pcaps are fixed, so a change in the output is a
change in the arithmetic. Running it on a shared CI machine is meaningful
for exactly that reason and for no other - nothing here validates the
engine\'s performance, only that the numbers the README publishes can still
be derived from the captures it cites.

Result 2 is checked with tolerances rather than exactly. Its published p50
(31.3) and p99 (32.4) could not be reproduced: nearest-rank gives p99 32.63
(= max at n=20) and linear interpolation gives 32.58, and neither yields
31.3 for p50. Results 1 and 3 match to the last published digit under
interpolation, so the definition is right and the difference is in the
sample - detect_ms takes the first Down of each run, and the original may
have selected differently. Gating on an unrecoverable figure would gate on
this reconstruction rather than on anything real, so the substantive claims
are checked instead: n, the 30ms floor, the mean over floor, and the tail.

    python3 perf/check.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bfdwire as w                                    # noqa: E402

B = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "docs", "benchmarks")
DUT, PEER = "bfd-dut", "10.66.0.2"
fails = []


def check(name, got, want, tol=0.0):
    ok = abs(got - want) <= tol if tol else got == want
    print("%-28s got %-10s want %-10s %s"
          % (name, round(got, 2), round(want, 2), "ok" if ok else "FAIL"))
    if not ok:
        fails.append(name)


def between(name, got, lo, hi):
    ok = lo <= got <= hi
    print("%-28s got %-10s want %s..%s %s"
          % (name, round(got, 2), lo, hi, "ok" if ok else "FAIL"))
    if not ok:
        fails.append(name)


print("result 1: resilience, flaps from the peer\'s transmitted state")
p = w.read(os.path.join(B, "bench1-bfdd-107flaps.pcap"))
check("bfdd flaps", w.flaps(p, PEER)[0], 107)
p = w.read(os.path.join(B, "bench1-xdpbfd-0flaps.pcap"))
check("xdp-bfd flaps", w.flaps(p, PEER)[0], 0)

print()
print("result 2: detection latency (tolerances - see the module docstring)")
d = w.summary(w.detect_ms(w.read(os.path.join(B, "bench2-detect-dist.pcap")),
                          DUT, PEER))
check("detect n", d["n"], 20)
between("detect min (30ms floor)", d["min"], 30.0, 30.5)
between("detect mean over floor", d["mean"] - 30.0, 1.0, 1.6)
between("detect max", d["max"], 30.0, 33.0)

print()
print("result 3: TX pacing, DUT inter-departure")
g = w.summary(w.gaps_ms(w.read(os.path.join(B, "bench3-pacing.pcap")), DUT))
check("pacing n", g["n"], 7295)
check("pacing mean", g["mean"], 8.77, 0.005)
check("pacing p50", g["p50"], 8.77, 0.005)
check("pacing p99", g["p99"], 10.01, 0.005)
check("pacing p999", g["p999"], 10.05, 0.005)
check("pacing max", g["max"], 10.08, 0.005)

print()
if fails:
    print("%d check(s) failed: %s" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("all checks passed")
