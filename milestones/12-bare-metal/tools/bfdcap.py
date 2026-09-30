#!/usr/bin/env python3
"""bfdcap.py PCAP CLASSMAP [--from S] [--to S] [--json OUT]

Wire analysis of the hardware testbed mirror capture (m4, eno3).

Per BFD control flow (sender -> receiver):
  - gaps between the sender's packets, each against the receiver's
    detection time for that sender (RFC 5880 s6.8.4, from the timers both
    sides carry in their packets): a gap over it is a detection the
    receiver would make
  - state transitions out of Up in the sender's packets (flaps)
  - reply latency: the DUT's first packet on a session within 2 ms of the
    peer's packet on it (the program answers in XDP)

Flows whose receiver sends D (demand, s6.6) are left out of the gap count.
CLASSMAP is JSON {"dut|peer": class}. The DUT is the sender with DUT_MAC.
"""

import json
import struct
import sys
from collections import defaultdict

DUT_MAC = bytes.fromhex("6805cae79564")
CTRL = (3784, 4784)


def pcap(path):
    f = open(path, "rb")
    gh = f.read(24)
    magic = struct.unpack("<I", gh[:4])[0]
    if magic == 0xA1B23C4D:
        div, e = 1e9, "<"
    elif magic == 0xA1B2C3D4:
        div, e = 1e6, "<"
    else:
        raise SystemExit("not a little-endian pcap: %x" % magic)
    rh = struct.Struct(e + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        s, frac, incl, _ = rh.unpack(h)
        yield s + frac / div, f.read(incl)


def ip6s(b):
    import ipaddress

    return str(ipaddress.IPv6Address(b))


def parse(pkt):
    if len(pkt) < 14:
        return None
    et = pkt[12:14]
    if et == b"\x08\x00":
        ihl = (pkt[14] & 0x0F) * 4
        if pkt[23] != 17:
            return None
        src = "%d.%d.%d.%d" % tuple(pkt[26:30])
        dst = "%d.%d.%d.%d" % tuple(pkt[30:34])
        u = 14 + ihl
    elif et == b"\x86\xdd":
        if pkt[20] != 17:
            return None
        src, dst = ip6s(pkt[22:38]), ip6s(pkt[38:54])
        u = 54
    else:
        return None
    if len(pkt) < u + 8 + 24:
        return None
    dport = struct.unpack(">H", pkt[u + 2 : u + 4])[0]
    if dport not in CTRL:
        return None
    b = pkt[u + 8 : u + 32]
    state = b[1] >> 6
    flags = b[1] & 0x3F
    mult = b[2]
    tx, rx = struct.unpack(">II", b[12:20])
    return pkt[6:12] == DUT_MAC, src, dst, state, flags, mult, tx, rx


def pct(v, q):
    if not v:
        return None
    v = sorted(v)
    return v[min(len(v) - 1, int(q * len(v)))]


def main():
    args = sys.argv[1:]
    path, cmap = args[0], json.load(open(args[1]))
    t_from = float(args[args.index("--from") + 1]) if "--from" in args else 0
    t_to = float(args[args.index("--to") + 1]) if "--to" in args else 1e18
    jout = args[args.index("--json") + 1] if "--json" in args else None

    last = {}  # (src,dst) -> (t, state, flags, mult, tx, rx)
    flaps = defaultdict(int)  # (src,dst) -> Up -> not Up
    over = defaultdict(list)  # (src,dst) -> [(t, gap_ms, budget_ms)]
    ratio = defaultdict(list)  # class/side -> gap / budget
    gapms = defaultdict(list)  # class/side -> gap ms
    lat = defaultdict(list)  # class -> reply latency us
    pending = {}  # (peer,dut) -> t of the peer's packet awaiting a reply
    npk = 0
    t0 = t1 = None
    for t, pkt in pcap(path):
        if t < t_from or t > t_to:
            continue
        p = parse(pkt)
        if not p:
            continue
        dut, src, dst, st, fl, mult, tx, rx = p
        npk += 1
        t0 = t if t0 is None else t0
        t1 = t
        key = (src, dst)
        sess = (src, dst) if dut else (dst, src)  # (dut addr, peer addr)
        cls = cmap.get("%s|%s" % sess, "?")
        side = "dut" if dut else "peer"
        prev = last.get(key)
        back = last.get((dst, src))
        if prev:
            if prev[1] == 3 and st != 3:
                flaps[key] += 1
            demand = back and back[2] & 0x02 and back[1] == 3
            if back and not demand and prev[1] == 3 and st == 3:
                gap = (t - prev[0]) * 1e3
                budget = prev[3] * max(back[5], prev[4]) / 1e3
                if budget > 0:
                    ratio[(cls, side)].append(gap / budget)
                    gapms[(cls, side)].append(gap)
                    if gap > budget:
                        over[key].append((round(t, 6), round(gap, 3), round(budget, 3)))
        last[key] = (t, st, fl, mult, tx, rx)
        if dut:
            pt = pending.pop((dst, src), None)
            if pt is not None and t - pt < 0.002:
                lat[cls].append((t - pt) * 1e6)
        else:
            pending[key] = t

    dur = (t1 - t0) if t0 is not None else 0
    print("%s: %d control packets over %.1f s" % (path, npk, dur))
    print("\nflaps (sender's state left Up): %d from the DUT, %d from the peer"
          % (sum(v for k, v in flaps.items() if cmap.get("%s|%s" % k) is not None),
             sum(v for k, v in flaps.items() if cmap.get("%s|%s" % k) is None)))
    print("\n%-16s %-4s %8s %8s %8s %8s %9s %6s" % (
        "class", "side", "gaps", "p50ms", "p99ms", "maxms", "max/budg", "over"))
    res = {"packets": npk, "seconds": dur, "classes": {}, "over": {}, "flaps": {}}
    for (cls, side) in sorted(ratio):
        r, g = ratio[(cls, side)], gapms[(cls, side)]
        n_over = sum(1 for x in r if x > 1)
        print("%-16s %-4s %8d %8.2f %8.2f %8.2f %9.3f %6d" % (
            cls, side, len(g), pct(g, .5), pct(g, .99), max(g), max(r), n_over))
        res["classes"]["%s/%s" % (cls, side)] = {
            "gaps": len(g), "p50": pct(g, .5), "p99": pct(g, .99), "p999": pct(g, .999),
            "max": max(g), "max_ratio": max(r), "over": n_over}
    print("\nreply latency, peer packet -> DUT packet on the session within 2 ms (us)")
    print("%-16s %8s %8s %8s %8s %8s" % ("class", "n", "p50", "p99", "p999", "max"))
    allv = []
    for cls in sorted(lat):
        v = lat[cls]
        allv += v
        print("%-16s %8d %8.1f %8.1f %8.1f %8.1f" % (cls, len(v), pct(v, .5), pct(v, .99), pct(v, .999), max(v)))
        res.setdefault("latency", {})[cls] = {"n": len(v), "p50": pct(v, .5), "p99": pct(v, .99),
                                              "p999": pct(v, .999), "max": max(v)}
    if allv:
        print("%-16s %8d %8.1f %8.1f %8.1f %8.1f" % ("ALL", len(allv), pct(allv, .5), pct(allv, .99),
                                                     pct(allv, .999), max(allv)))
    worst = sorted(((len(v), k) for k, v in over.items()), reverse=True)[:10]
    if worst:
        print("\nflows with gaps over the receiver's detection time (first 10):")
        for n, k in worst:
            print("  %s -> %s  %s: %d, first %s" % (k[0], k[1], cmap.get("%s|%s" % k) or cmap.get("%s|%s" % (k[1], k[0])), n, over[k][0]))
    res["over"] = {"%s>%s" % k: v for k, v in over.items()}
    res["flaps"] = {"%s>%s" % k: v for k, v in flaps.items()}
    if jout:
        json.dump(res, open(jout, "w"), indent=1)


if __name__ == "__main__":
    main()
