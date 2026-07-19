#!/usr/bin/env python3
# echo_inject.py — send self-addressed BFD echoes to the DUT for XDP reflection.
# Run on bfd-chaos. If the DUT reflects, they return with TTL 254, payload intact.
from scapy.all import Ether, IP, UDP, Raw, sendp, AsyncSniffer
import struct, time

DUT_MAC = "bc:24:11:60:0e:53"
SELF_IP = "10.66.0.3"
IFACE   = "ens19"

nonce = 0xDEADBEEF
bfd  = struct.pack("!BBBB", 0x20, 0x00, 0x03, 0x18)   # v1, flags 0, mult 3, len 24
bfd += struct.pack("!I", 0x11223344)                  # my_disc
bfd += struct.pack("!I", 0)                           # your_disc = 0
bfd += struct.pack("!I", 50000)                       # min_tx
bfd += struct.pack("!I", 50000)                       # min_rx
bfd += struct.pack("!I", nonce)                       # last 4 bytes = nonce

pkt = (Ether(dst=DUT_MAC) /
       IP(src=SELF_IP, dst=SELF_IP, ttl=255) /
       UDP(sport=3785, dport=3785) /
       Raw(bfd))

# capture the reflection: our own self-addressed IP coming back
s = AsyncSniffer(iface=IFACE, filter=f"udp port 3785 and ip src {SELF_IP}", store=True)
s.start(); time.sleep(0.3)
sendp(pkt, iface=IFACE, count=5, inter=0.1, verbose=False)
time.sleep(1)
res = s.stop()

sent_ttl = 255
reflected = [p for p in res if p.haslayer(IP) and p[IP].ttl == 254]
print(f"sent 5 echoes (ttl 255), captured {len(res)} frames on 3785, "
      f"{len(reflected)} reflected (ttl 254)")
for p in res:
    if not p.haslayer(IP): continue
    pl = bytes(p[UDP].payload) if p.haslayer(UDP) else b""
    n = struct.unpack("!I", pl[20:24])[0] if len(pl) >= 24 else None
    tag = " <-- REFLECTED" if p[IP].ttl == 254 else " (outbound)"
    print(f"  ttl={p[IP].ttl} smac={p[Ether].src} nonce={hex(n) if n else None}{tag}")
