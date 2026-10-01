import struct, sys
# icmplat.py PCAP: echo request -> reply latency per replier, from the mirror.
f = open(sys.argv[1], "rb"); gh = f.read(24)
nano = struct.unpack("<I", gh[:4])[0] == 0xa1b23c4d
req = {}; lat = {}
while True:
    h = f.read(16)
    if len(h) < 16: break
    s, frac, incl, _ = struct.unpack("<IIII", h); p = f.read(incl)
    t = s + frac / (1e9 if nano else 1e6)
    if len(p) < 42 or p[12:14] != b"\x08\x00" or p[23] != 1: continue
    ihl = (p[14] & 0xf) * 4; ic = 14 + ihl
    typ = p[ic]; idseq = p[ic+4:ic+8]; src = ".".join(map(str, p[26:30]))
    if typ == 8: req[idseq] = t
    elif typ == 0 and idseq in req:
        lat.setdefault(src, []).append((t - req.pop(idseq)) * 1e6)
for k, v in lat.items():
    v.sort(); n = len(v); q = lambda x: v[min(n - 1, int(x * n))]
    print("replies from %-12s n %5d  min %6.1f p50 %6.1f p99 %6.1f max %7.1f us" % (k, n, v[0], q(.5), q(.99), v[-1]))
