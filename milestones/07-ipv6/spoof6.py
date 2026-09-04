#!/usr/bin/env python3
# v6 BFD spoof/injection harness. Mirror of milestones/04-hardening/spoof.py.
# Forges source = peer (fd66::2); explicit DUT dest MAC so the frame
# lands on the DUT NIC (v6 has no broadcast). Confirm delivery with
# tcpdump on the DUT before trusting counters.
# Usage: sudo python3 spoof6.py <DUT_MAC> 0x<DUT_wire_disc>
#   wire_disc = bpftool map dump name tx_config | grep -A1 fd66 ... my_disc
import sys, time
from scapy.all import Ether, IPv6, UDP, sendp

IFACE = "ens19"
PEER  = "fd66::2"    # forged source (real peer)
DUT   = "fd66::1"

def bfd(my_disc, your_disc, state=3):
    vers_diag = (1 << 5)
    flags = (state & 3) << 6
    return bytes([
        vers_diag, flags, 3, 24,
        (my_disc>>24)&0xff,(my_disc>>16)&0xff,(my_disc>>8)&0xff,my_disc&0xff,
        (your_disc>>24)&0xff,(your_disc>>16)&0xff,(your_disc>>8)&0xff,your_disc&0xff,
        0,0,0x27,0x10,
        0,0,0x27,0x10,
        0,0,0,0,
    ])

def send_case(name, mac, your_disc, hlim, count=200):
    pkt = (Ether(dst=mac)/IPv6(src=PEER, dst=DUT, hlim=hlim)/
           UDP(sport=49152, dport=3784)/bfd(0xdeadbeef, your_disc))
    print(f"[{name}] your_disc=0x{your_disc:08x} hlim={hlim} x{count}")
    sendp(pkt, iface=IFACE, count=count, inter=0.005, verbose=0)

if __name__ == "__main__":
    mac  = sys.argv[1]
    real = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
    send_case("wrong-disc", mac, 0x11111111, 255)   # demux reject -> stats[3]
    time.sleep(1)
    send_case("low-hlim", mac, real, 64)            # GTSM reject -> stats[3]
    time.sleep(1)
    send_case("correct-disc", mac, real, 255)       # control: passes guard, must NOT flap
