#!/usr/bin/env python3
"""flaps.py PCAP CLASSMAP T_START: every Up -> not-Up on the wire, with who
left Up first, its diag, time since T_START, and the gap before it on both
directions."""
import collections
import json
import sys

sys.path.insert(0, ".")
from bfdcap import pcap, DUT_MAC  # noqa: E402
import struct  # noqa: E402

DIAG = {0: "none", 1: "detect", 2: "echo", 3: "nbr-down", 4: "fwd-reset", 5: "path-down",
        7: "admin-down"}


def parse(pkt):
    et = pkt[12:14]
    if et == b"\x08\x00":
        ihl = (pkt[14] & 0x0F) * 4
        src = "%d.%d.%d.%d" % tuple(pkt[26:30])
        dst = "%d.%d.%d.%d" % tuple(pkt[30:34])
        u = 14 + ihl
    elif et == b"\x86\xdd":
        import ipaddress
        src, dst = str(ipaddress.IPv6Address(pkt[22:38])), str(ipaddress.IPv6Address(pkt[38:54]))
        u = 54
    else:
        return None
    dport = struct.unpack(">H", pkt[u + 2:u + 4])[0]
    if dport not in (3784, 4784) or len(pkt) < u + 32:
        return None
    b = pkt[u + 8:u + 32]
    return pkt[6:12] == DUT_MAC, src, dst, b[1] >> 6, b[0] & 0x1F


path, cmap, t0 = sys.argv[1], json.load(open(sys.argv[2])), float(sys.argv[3])
last = {}      # (src,dst) -> (t, state)
first = {}     # session -> open flap: {side: (t, diag, gap)}
events = []
for t, pkt in pcap(path):
    if not t0:
        t0 = t
    p = parse(pkt)
    if not p:
        continue
    dut, src, dst, st, diag = p
    sess = (src, dst) if dut else (dst, src)
    prev = last.get((src, dst))
    if prev and prev[1] == 3 and st != 3:
        gap = (t - prev[0]) * 1e3
        f = first.setdefault(sess, {})
        f["dut" if dut else "peer"] = (t, DIAG.get(diag, diag), gap)
        if len(f) == 2 or True:
            pass
    if prev and prev[1] != 3 and st == 3 and sess in first:
        f = first.pop(sess)
        side = min(f, key=lambda k: f[k][0])
        events.append((f[side][0] - t0, cmap.get("%s|%s" % sess, "?"), side, f[side][1], f[side][2], sess))
    last[(src, dst)] = (t, st)
for sess, f in first.items():
    side = min(f, key=lambda k: f[k][0])
    events.append((f[side][0] - t0, cmap.get("%s|%s" % sess, "?"), side, f[side][1], f[side][2], sess))

print(len(events), "flaps")
print("\nby phase, first to leave Up, diag:")
ph = collections.Counter()
for e in events:
    phase = "idle-pre" if e[0] < 30 else "L3" if e[0] < 151.6 else "L4" if e[0] < 214 else "idle-post"
    ph[(phase, e[2], e[3])] += 1
for k, v in sorted(ph.items()):
    print("  %-10s %-5s %-10s %d" % (k + (v,)))
print("\nby class:")
for k, v in sorted(collections.Counter(e[1] for e in events).items()):
    print("  %-16s %d" % (k, v))
print("\nclass x side x diag:"); [print("  ", k, v) for k, v in sorted(collections.Counter((e[1], e[2], e[3]) for e in events).items())]
print("\nfirst 15 in time:")
for e in sorted(events)[:15]:
    print("  +%8.3fs %-14s %-5s %-9s gap-before %8.1f ms  %s" % (e[0], e[1], e[2], e[3], e[4], e[5]))
tl = collections.Counter(int(e[0]) for e in events)
print("\nper second (flaps started):", sorted(tl.items()))
