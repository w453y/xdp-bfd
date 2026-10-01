#!/bin/bash
# iso.sh LABEL ARM|- "STRESS"|- SECS: one isolated case, peer down events and m1's drop counters.
L=$1 ARM=$2 ST=$3 T=${4:-60}
S="ssh -o BatchMode=yes -o LogLevel=ERROR -o ConnectTimeout=10"
pd() { $S w453y@10.100.15.146 'sudo /opt/frr-master/bin/vtysh -c "show bfd peers counters"' | awk '/Session down events/{s+=$NF} END{print s+0}'; }
ctr() { $S w453y@10.100.15.145 'ethtool -S enp1s0 | grep -E "rx_missed_errors|rx_no_buffer_count|alloc_rx|rx_fifo_errors|rx_dropped" | tr -s " " | tr "\n" " ";
	awk "{d+=strtonum(\"0x\"\$2); q+=strtonum(\"0x\"\$3)} END{printf \"softnet_drop %d squeeze %d\", d, q}" /proc/net/softnet_stat'; }
a=$(pd); c0=$(ctr)
[ "$ARM" != - ] && $S w453y@10.100.15.152 "sudo timeout $T trafgen -i /tmp/f$ARM.cfg -o enp1s0 -n 0 --gap 0us >/dev/null 2>&1" &
[ "$ST" != - ] && $S w453y@10.100.15.145 "$ST --timeout ${T}s >/dev/null 2>&1" &
[ "$ARM" = - ] && [ "$ST" = - ] && sleep "$T"
wait; sleep 8
echo "$L: peer downs +$(( $(pd) - a ))"
echo "  before: $c0"; echo "  after:  $(ctr)"
