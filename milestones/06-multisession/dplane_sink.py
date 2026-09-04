#!/usr/bin/env python3
# Minimal distributed-BFD dataplane sink: accepts bfdd's dplane
# connection, reads everything immediately, counts bytes and
# 203-byte SESSION messages. No BFD logic; proves the loss is in
# bfdd's buffering, not the dataplane.
import socket, struct, sys

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 50700))
s.listen(1)
print("sink: listening on 127.0.0.1:50700")
c, a = s.accept()
print("sink: bfdd connected from", a)
total = b""
try:
    while True:
        d = c.recv(65536)
        if not d:
            print("sink: bfdd disconnected, waiting for reconnect")
            c.close(); c, a = s.accept()
            print("sink: bfdd connected from", a); continue
        total += d
        n = 0; off = 0
        while off + 8 <= len(total):
            length = struct.unpack_from("!H", total, off + 6)[0]
            if length < 8: break
            n += 1; off += length
        print("sink: %d bytes, %d messages so far" % (len(total), n))
except KeyboardInterrupt:
    pass
n = 0
off = 0
# bfddp_message_header: version u8, zero u8, type u16, id u16,
# length u16 (network order) -- length at offset 6, includes header.
while off + 8 <= len(total):
    length = struct.unpack_from("!H", total, off + 6)[0]
    if length < 8:
        break
    typ = struct.unpack_from("!H", total, off + 2)[0]
    n += 1
    off += length
print("sink: %d bytes, %d messages" % (len(total), n))
