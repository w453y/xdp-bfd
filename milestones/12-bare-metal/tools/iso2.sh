#!/bin/bash
# iso2.sh LABEL ARM|- "STRESS"|- SECS: iso.sh plus XDP ns/frame and frames/s.
L=$1 ARM=$2 ST=$3 T=${4:-60}
S="ssh -o BatchMode=yes -o LogLevel=ERROR -o ConnectTimeout=10"
pd() { $S w453y@10.100.15.146 'sudo /opt/frr-master/bin/vtysh -c "show bfd peers counters"' | awk '/Session down events/{s+=$NF} END{print s+0}'; }
ctr() { $S w453y@10.100.15.145 'sudo sysctl -qw kernel.bpf_stats_enabled=1; echo $(sudo bpftool prog show name bfd_observer | grep -o "run_time_ns [0-9]* run_cnt [0-9]*" | awk "{print \$2, \$4}") $(ethtool -S enp1s0 | awk "/rx_no_buffer_count|rx_missed_errors/{print \$2}" | tr "\n" " ")'; }
a=$(pd); read t0 c0 nb0 ms0 <<<"$(ctr)"
[ "$ARM" != - ] && $S w453y@10.100.15.152 "sudo timeout $T trafgen -i /tmp/f$ARM.cfg -o enp1s0 -n 0 --gap 0us >/dev/null 2>&1" &
[ "$ST" != - ] && $S w453y@10.100.15.145 "$ST --timeout ${T}s >/dev/null 2>&1" &
[ "$ARM" = - ] && [ "$ST" = - ] && sleep "$T"
wait; sleep 8
read t1 c1 nb1 ms1 <<<"$(ctr)"
awk -v L="$L" -v d=$(( $(pd) - a )) -v dt=$((t1-t0)) -v dc=$((c1-c0)) -v nb=$((nb1-nb0)) -v ms=$((ms1-ms0)) -v T=$T \
	'BEGIN{printf "%s: peer downs +%d | xdp %.0f frames/s %.0f ns/frame | rx_no_buffer +%d rx_missed +%d\n", L, d, dc/T, (dc?dt/dc:0), nb, ms}'
