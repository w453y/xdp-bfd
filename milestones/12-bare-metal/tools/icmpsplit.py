import struct, sys
# icmpsplit.py PCAP: m2 -> m1 echo with gi1 mirrored both ways. Request seen
# at gi2 ingress then gi1 egress; reply at gi1 ingress.
f = open(sys.argv[1], "rb"); f.read(24)
req = {}; sw = []; host = []
while True:
    h = f.read(16)
    if len(h) < 16: break
    s, ns, incl, _ = struct.unpack("<IIII", h); p = f.read(incl); t = s + ns / 1e9
    if len(p) < 42 or p[12:14] != b"\x08\x00" or p[23] != 1: continue
    ic = 14 + (p[14] & 0xf) * 4; typ = p[ic]; k = p[ic+4:ic+8]
    if typ == 8 and p[26:30] == bytes([10,66,0,2]): req.setdefault(k, []).append(t)
    elif typ == 0 and p[26:30] == bytes([10,66,0,1]) and len(req.get(k, [])) == 2:
        a, b = req.pop(k); sw.append((b - a) * 1e6); host.append((t - b) * 1e6)
def st(n, v):
    v.sort(); q = lambda x: v[min(len(v) - 1, int(x * len(v)))]
    print("%-28s n %5d min %6.1f p50 %6.1f p99 %6.1f max %6.1f us" % (n, len(v), v[0], q(.5), q(.99), v[-1]))
st("switch gi2 in -> gi1 out", sw); st("m1 wire in -> reply on wire", host)
