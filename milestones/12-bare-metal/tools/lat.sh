#!/bin/bash
# lat.sh NAME RXUSECS CSTATE [SECS]
# One reply-latency arm at idle: set the DUT's igb interrupt throttling and
# deepest C-state, capture the mirror on m4, and report the wire reply
# latency with the interrupt rate and package power over the same window.
# CSTATE: all (every state), c1e (cpupower idle-set -D 2), poll (-D 0).
set -u
NAME=$1 RX=$2 CS=$3 SECS=${4:-60}
M1=w453y@10.100.15.145 M3=w453y@10.100.15.152
M4LL=w453y@fe80::eab5:d0ff:fe8b:726d%enp0s31f6
M4="-J $M3 $M4LL"
OUT=$(dirname "$0")/runs/lat-$NAME
mkdir -p "$OUT"
S="ssh -o BatchMode=yes -o LogLevel=ERROR"

case $CS in
all) CSCMD="cpupower idle-set -E" ;;
c1e) CSCMD="cpupower idle-set -E && cpupower idle-set -D 2" ;;
poll) CSCMD="cpupower idle-set -E && cpupower idle-set -D 0" ;;
*) echo "bad CSTATE $CS"; exit 1 ;;
esac

$S $M1 "sudo ethtool -C enp1s0 rx-usecs $RX && sudo sh -c '$CSCMD' >/dev/null" || exit 1
sleep 10

snap() { $S $M1 'echo $(grep enp1s0 /proc/interrupts | awk "{for(i=2;i<=13;i++)s+=\$i} END{print s}") \
	$(sudo cat /sys/class/powercap/intel-rapl:0/energy_uj) \
	$(awk "/^cpu /{print \$2+\$3+\$4+\$6+\$7+\$8, \$5}" /proc/stat)'; }

$S $M4 "sudo rm -f ~/cap/lat-$NAME.pcap; sudo nohup timeout $((SECS + 4)) tcpdump -i eno3 -s 128 -B 262144 \
	-j adapter_unsynced --time-stamp-precision=nano -Z w453y -w ~/cap/lat-$NAME.pcap \
	'udp and (port 3784 or port 3785 or port 4784)' >~/cap/lat-$NAME.log 2>&1 &"
sleep 2
A=$(snap)
sleep "$SECS"
B=$(snap)
sleep 4

read -r ia ea ba ia2 <<<"$A"
read -r ib eb bb ib2 <<<"$B"
{
	echo "arm $NAME rx-usecs $RX cstate $CS ${SECS}s"
	$S $M1 'ethtool -c enp1s0 | grep "^rx-usecs:"; cpupower idle-info | grep -A1 "Available idle states"'
	awk -v i=$((ib - ia)) -v e=$((eb - ea)) -v b=$((bb - ba)) -v d=$((ib2 - ia2)) -v s="$SECS" \
		'BEGIN{printf "irq/s %.0f  pkg W %.2f  cpu busy %.2f%%\n", i/s, e/s/1e6, 100*b/(b+d)}'
	$S $M4 "tail -2 ~/cap/lat-$NAME.log"
} | tee "$OUT/log"

$S $M3 "scp -q -o BatchMode=yes '[${M4LL#w453y@}]:cap/lat-$NAME.pcap' ~/ana/ 2>&1 ||
	scp -q -o BatchMode=yes 'w453y@[${M4LL#w453y@}]:cap/lat-$NAME.pcap' ~/ana/;
	cd ~/ana && python3 bfdcap.py lat-$NAME.pcap classmap.json --json lat-$NAME.json |
	sed -n '/reply latency/,/^ALL/p'" | tee -a "$OUT/log" | grep -E "class|^ALL"
