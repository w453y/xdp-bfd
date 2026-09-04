#!/usr/bin/env python3
# Connect to the xdp-bfd engine's dplane listener as a fake bfdd and
# send one message header with an oversized length field, to exercise
# the bad-frame-length branch. Expected: engine logs "bad frame length
# ... dropping connection" and closes us. With --dp-hold, sessions
# orphan and survive; real bfdd then reconnects and re-adds them.
import socket, struct, sys, time

# bfddp_message_header: version(1) type(1) length(2 BE) ... we only need
# the first 4 bytes for the length check to fire. Send a plausible
# header start with length = 0xFFFF (> dp_buf 4096).
hdr = struct.pack("!BBH", 1, 1, 0xFFFF)  # version, type, length=65535
s = socket.create_connection(("127.0.0.1", 50700), timeout=3)
print("connected to dplane, sending bogus-length header")
s.sendall(hdr + b"\x00" * 4)  # a few extra bytes so recv has >= header
time.sleep(1)
# read to see if the engine dropped us (recv returns b'' on close)
s.setblocking(False)
try:
    data = s.recv(64)
    print("still open, recv:", data)
except BlockingIOError:
    print("still open (no data), connection not dropped yet")
except (ConnectionResetError, OSError) as e:
    print("connection dropped by engine:", e)
s.close()
