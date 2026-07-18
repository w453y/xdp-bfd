#!/usr/bin/env python3
# bfddp message counter + counters responder. Listens on 127.0.0.1:50700,
# parses the message stream, counts per type, and answers
# DP_REQUEST_SESSION_COUNTERS with a valid 80-byte BFD_SESSION_COUNTERS
# reply (echoed id, requested lid, zeroed counters). Prints a per-type
# summary when the connection closes. No dataplane implementation needed.
import socket, struct, sys

TYPES = {0:"ECHO_REQUEST",1:"ECHO_REPLY",2:"DP_ADD_SESSION",
         3:"DP_DELETE_SESSION",4:"BFD_STATE_CHANGE",
         5:"DP_REQUEST_SESSION_COUNTERS",6:"BFD_SESSION_COUNTERS"}

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 50700))
srv.listen(1)
print("listening on 127.0.0.1:50700 (counters responder enabled)", flush=True)

conn_n = 0
while True:
    c, addr = srv.accept()
    conn_n += 1
    print(f"--- connection {conn_n} from {addr} ---", flush=True)
    buf = b""
    counts = {}
    total = 0
    replies = 0
    while True:
        try:
            d = c.recv(65536)
        except ConnectionResetError:
            print("    (connection reset by peer)", flush=True)
            break
        if not d:
            break
        buf += d
        total += len(d)
        while len(buf) >= 8:
            ver, zero, mtype, mid, mlen = struct.unpack("!BBHHH", buf[:8])
            if mlen < 8 or ver != 1:
                print(f"FRAMING ERROR ver={ver} len={mlen}", flush=True)
                sys.exit(1)
            if len(buf) < mlen:
                break
            counts[mtype] = counts.get(mtype, 0) + 1
            if mtype == 5:  # DP_REQUEST_SESSION_COUNTERS
                lid = buf[8:12]  # network-order lid, echoed back
                reply = (struct.pack("!BBHHH", 1, 0, 6, mid, 80)
                         + lid + b"\x00" * 68)
                try:
                    c.sendall(reply)
                    replies += 1
                except BrokenPipeError:
                    print("    (broken pipe on reply)", flush=True)
                    break
            buf = buf[mlen:]
    c.close()
    print(f"--- connection {conn_n} closed: {total} bytes in, "
          f"{replies} counters replies sent, {len(buf)} residual ---",
          flush=True)
    for t in sorted(counts):
        print(f"    {TYPES.get(t, t)}: {counts[t]}", flush=True)

