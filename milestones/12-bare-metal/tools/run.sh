#!/bin/bash
# run.sh NAME idle SECS | run.sh NAME ladder
# One benchmark run on the hardware testbed: mirror capture on m4, peer and
# DUT counters before and after, and for "ladder" the stress ladder on m1
# (30 s idle, L3 120 s, L4 60 s, 30 s idle).
set -u
NAME=$1 MODE=$2 SECS=${3:-0}
# L4PRIO: the hogs' SCHED_FIFO priority (50). NOL3=1: skip L3.
L4PRIO=${L4PRIO:-50} NOL3=${NOL3:-0}
M1=w453y@10.100.15.145 M2=w453y@10.100.15.146
# m4 by link-local through m3: another host took 10.100.15.154 on 2026-10-01.
M4="-J w453y@10.100.15.152 w453y@fe80::eab5:d0ff:fe8b:726d%enp0s31f6"
OUT=$(dirname "$0")/runs/$NAME
mkdir -p "$OUT"
S="ssh -o BatchMode=yes -o LogLevel=ERROR"

peerdown() { $S $M2 'sudo /opt/frr-master/bin/vtysh -c "show bfd peers counters"' |
	awk '/Session down events/{s+=$NF} END{print s+0}'; }
dutdown() { $S $M1 'sudo /opt/frr-master/bin/vtysh -c "show bfd peers counters"' |
	awk '/Session down events/{s+=$NF} END{print s+0}'; }
peerup() { $S $M2 'sudo /opt/frr-master/bin/vtysh -c "show bfd peers brief"' | grep -cw up; }
now() { date +%s.%N; }

[ "$MODE" = ladder ] && SECS=240
[ "$MODE" = ladder ] && [ "$NOL3" = 1 ] && SECS=120
echo "run $NAME mode $MODE capture ${SECS}s" | tee "$OUT/log"
echo "before: peer-down $(peerdown) dut-down $(dutdown) peer-up $(peerup)" | tee -a "$OUT/log"
$S $M1 'uname -r; pgrep -a -x xdp-bfd || pgrep -a -x bfd_tx || echo "no engine"; ps -o cls,rtprio,comm -C xdp-bfd; grep bfdd_options /opt/frr-master/etc/frr/daemons' >>"$OUT/log"

$S $M4 "sudo rm -f ~/cap/$NAME.pcap; sudo nohup timeout $((SECS + 5)) tcpdump -i eno3 -s 128 -B 262144 \
	-j adapter_unsynced --time-stamp-precision=nano -Z w453y -w ~/cap/$NAME.pcap \
	'udp and (port 3784 or port 3785 or port 4784)' >~/cap/$NAME.tcpdump.log 2>&1 &"
sleep 3
echo "capture start $(now)" | tee -a "$OUT/log"

if [ "$MODE" = ladder ]; then
	sleep 30
	if [ "$NOL3" != 1 ]; then
		echo "L3 start $(now)" | tee -a "$OUT/log"
		$S $M1 'stress-ng --cpu 12 --timer 24 --timerfd 12 --hrtimers 6 --timeout 120s --metrics-brief 2>&1 | tail -8' >>"$OUT/stress-L3.txt"
		echo "L3 end $(now)" | tee -a "$OUT/log"
	fi
	echo "L4 start $(now) prio $L4PRIO" | tee -a "$OUT/log"
	$S $M1 "sudo stress-ng --cpu 12 --sched fifo --sched-prio $L4PRIO --timeout 60s --metrics-brief 2>&1 | tail -8" >>"$OUT/stress-L4.txt"
	echo "L4 end $(now)" | tee -a "$OUT/log"
	sleep 30
else
	sleep "$SECS"
fi
sleep 5
echo "capture end $(now)" | tee -a "$OUT/log"
$S $M4 "cat ~/cap/$NAME.tcpdump.log | tail -3" | tee -a "$OUT/log"
sleep 5
echo "after: peer-down $(peerdown) dut-down $(dutdown) peer-up $(peerup)" | tee -a "$OUT/log"
