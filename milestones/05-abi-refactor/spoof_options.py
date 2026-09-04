#!/usr/bin/env python3
# Inject a BFD control packet carrying an IP option (ihl=6) to the DUT.
# Correct TTL 255 and your_disc, so pre-fix it would bypass the ihl==5
# gate, skip GTSM/demux, and leak to the userspace socket. Post-fix the
# kernel must XDP_DROP it (stats idx 3) and the session must not flap.
# Usage: sudo python3 spoof_options.py <my_disc> <your_disc> [count]
import sys, struct
from scapy.all import IP, UDP, Raw, IPOption, send

my_disc, your_disc = int(sys.argv[1]), int(sys.argv[2])
count = int(sys.argv[3]) if len(sys.argv) > 3 else 200
bfd = struct.pack("!BBBBIIIII",
                  (1 << 5), 0xc0, 3, 24,
                  my_disc, your_disc, 10000, 10000, 0)
# IPOption_NOP-based padding forces ihl > 5 (4 option bytes -> ihl=6)
pkt = (IP(src="10.66.0.2", dst="10.66.0.1", ttl=255,
          options=[IPOption(b"\x01\x01\x01\x01")]) /
       UDP(sport=49200, dport=3784) / Raw(bfd))
send(pkt, iface="ens19", count=count, inter=0.005, verbose=False)
print(f"sent {count} optioned packets (ihl=6)")
