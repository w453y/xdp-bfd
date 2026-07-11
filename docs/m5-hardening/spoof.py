# BFD spoof/injection harness for the m5h test (see README m5h).
# Run from a third host on the same L2 segment as DUT and peer.
# Forges source = peer IP; broadcast-dst Ether so the bridge floods
# the frame to the DUT NIC. Confirm delivery on the DUT NIC before
# trusting counters (tcpdump -i <if> "udp port 3784 and udp[12:4]=0xdeadbeef").
# Usage: sudo python3 spoof.py 0x<DUT_wire_disc>
#   DUT_wire_disc = bpftool map dump name tx_config | grep my_disc
# Cases: wrong your_disc (demux reject), low TTL (GTSM reject),
#        correct your_disc from forged host (must not flap the session).

import sys, time
from scapy.all import Ether, IP, UDP, sendp, sniff

IFACE   = "ens19"
PEER_IP = "10.66.0.2"   # source we forge (the real peer)
DUT_IP  = "10.66.0.1"

def bfd(my_disc, your_disc, state=3):
    # BFD control packet, 24 bytes, no auth
    vers_diag = (1 << 5)
    flags     = (state & 3) << 6
    return bytes([
        vers_diag, flags, 3, 24,
        (my_disc>>24)&0xff,(my_disc>>16)&0xff,(my_disc>>8)&0xff,my_disc&0xff,
        (your_disc>>24)&0xff,(your_disc>>16)&0xff,(your_disc>>8)&0xff,your_disc&0xff,
        0,0,0x27,0x10,   # min_tx 10000us
        0,0,0x27,0x10,   # min_rx 10000us
        0,0,0,0,         # echo rx 0
    ])

def send_case(name, your_disc, ttl, count=200):
    pkt = (Ether()/IP(src=PEER_IP, dst=DUT_IP, ttl=ttl)/
           UDP(sport=49152, dport=3784)/bfd(0xdeadbeef, your_disc))
    print(f"[{name}] your_disc=0x{your_disc:08x} ttl={ttl} x{count}")
    sendp(pkt, iface=IFACE, count=count, inter=0.005, verbose=0)

if __name__ == "__main__":
    real = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0
    # case 1: wrong your_disc, ttl 255  -> demux reject
    send_case("wrong-disc", 0x11111111, 255)
    time.sleep(1)
    # case 2: correct-ish disc but ttl 64 -> GTSM reject
    send_case("low-ttl", real, 64)
    time.sleep(1)
    # case 3 (control): correct your_disc, ttl 255, forged host
    #   -> passes validation (proves guard, not dead injector)
    send_case("correct-disc", real, 255)
