# rxts.py IFACE SECS: per received ICMP echo request, kernel software receive
# time minus I210 raw hardware time; clocks differ, so report each 1 s
# window against that window's minimum (drift within 1 s is ~50 ns).
import socket, struct, sys, time
SOL_SOCKET, SO_TIMESTAMPING, SCM_TIMESTAMPING = 1, 37, 37
F = (1 << 2) | (1 << 3) | (1 << 4) | (1 << 6)  # RX_HW, RX_SW, SOFTWARE, RAW_HW
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
s.bind((sys.argv[1], 0)); s.setsockopt(SOL_SOCKET, SO_TIMESTAMPING, F)
import fcntl, array
ifr = struct.pack("16sP", sys.argv[1].encode(), 0)
cfg = struct.pack("iii", 0, 0, 1)  # HWTSTAMP_FILTER_ALL
buf = array.array("b", cfg)
ifr = struct.pack("16sQ", sys.argv[1].encode(), buf.buffer_info()[0])
fcntl.ioctl(s, 0x89b0, ifr)  # SIOCSHWTSTAMP
end = time.time() + float(sys.argv[2]); win = {}
while time.time() < end:
    d, anc, _, _ = s.recvmsg(256, 256)
    if len(d) < 34 or d[23] != 1 or d[34] != 8: continue
    for lvl, typ, data in anc:
        if lvl == SOL_SOCKET and typ == SCM_TIMESTAMPING:
            t = struct.unpack("qqqqqq", data[:48])
            sw, hw = t[0] + t[1] / 1e9, t[4] + t[5] / 1e9
            if hw: win.setdefault(int(sw), []).append((sw - hw) * 1e6)
v = []
for k, w in win.items():
    m = min(w); v += [x - m for x in w]
v.sort(); q = lambda x: v[min(len(v) - 1, int(x * len(v)))]
print("NIC hw rx -> kernel sw rx (above per-second min): n %d p50 %.1f p99 %.1f max %.1f us" % (len(v), q(.5), q(.99), v[-1]))
