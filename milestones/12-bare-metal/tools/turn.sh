#!/bin/bash
# turn.sh LABEL: m1 wire-in -> reply wire-out for 2500 pings from m2, timed by m4 (gi1 mirrored rx+tx).
J="-o LogLevel=ERROR -J w453y@10.100.15.152 w453y@fe80::eab5:d0ff:fe8b:726d%enp0s31f6"
ssh $J "sudo rm -f /tmp/icmp.pcap; sudo nohup timeout 34 tcpdump -i eno3 -s 96 -j adapter_unsynced --time-stamp-precision=nano -w /tmp/icmp.pcap icmp >/tmp/icmp.log 2>&1 &"; sleep 2
ssh -o LogLevel=ERROR 10.100.15.146 'sudo ping -q -i 0.01 -c 2500 10.66.0.1 >/dev/null'; sleep 7
echo -n "$1: "; ssh $J "sudo chmod a+r /tmp/icmp.pcap; python3 /tmp/icmpsplit.py /tmp/icmp.pcap | tail -1"
