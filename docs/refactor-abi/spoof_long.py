#!/usr/bin/env python3
# Inject one valid-but-oversized BFD control packet (24 BFD bytes + 10
# pad) at the DUT from the peer. Passes GTSM (TTL 255) and demux
# (correct your_disc), so the kernel echoes it; the echo must come back
# trimmed to 66 bytes on the wire.
#
# Usage (on bfd-peer): sudo python3 spoof_long.py <my_disc> <your_disc>
#   my_disc   = peer's discriminator (DUT's "Remote ID" in show bfd peers)
#   your_disc = DUT's discriminator  (DUT's "ID" in show bfd peers)
import sys, struct
from scapy.all import IP, UDP, Raw, send

my_disc, your_disc = int(sys.argv[1]), int(sys.argv[2])
bfd = struct.pack("!BBBBIIIII",
                  (1 << 5),        # vers 1, diag 0
                  0xc0,            # state Up, no P/F
                  3, 24,           # mult, len
                  my_disc, your_disc,
                  10000, 10000, 0) # min_tx, min_rx, echo
pkt = (IP(src="10.66.0.2", dst="10.66.0.1", ttl=255) /
       UDP(sport=49200, dport=3784) /
       Raw(bfd + b"\x00" * 10))    # 10 trailing bytes past bfd.len
send(pkt, iface="ens19", verbose=True)
