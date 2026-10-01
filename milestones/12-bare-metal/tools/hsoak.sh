#!/bin/bash
# hsoak.sh NAME: an hour with the DUT under attack. m3 floods m1's port at
# line rate the whole time, rotating arms A-E every minute; m1 runs a
# different stress-ng phase every 5 minutes (CPU, real-time, timers, memory
# into swap). Sampled every 30 s from the peer, which is not under attack,
# and from m1 when it answers.
set -u
NAME=$1
OUT=$(dirname "$0")/runs/$NAME
mkdir -p "$OUT"
S="ssh -o BatchMode=yes -o LogLevel=ERROR -o ConnectTimeout=10"
M1=w453y@10.100.15.145 M2=w453y@10.100.15.146 M3=w453y@10.100.15.152

PHASES=(
	"sudo stress-ng --cpu 12 --sched fifo --sched-prio 99"
	"stress-ng --cpu 12 --timer 24 --timerfd 12 --hrtimers 6"
	"stress-ng --vm 8 --vm-bytes 95% --vm-keep"
	"sudo stress-ng --cpu 12 --sched fifo --sched-prio 50 --vm 4 --vm-bytes 90% --vm-keep"
	"stress-ng --vm 12 --vm-bytes 110% --vm-keep --page-in"
	"stress-ng --cpu 12 --timer 24 --vm 6 --vm-bytes 85% --vm-keep"
)
ORDER=(0 1 2 3 4 5 0 2 3 4 5 1)

peer() {
	$S $M2 'v=/opt/frr-master/bin/vtysh; echo "peer-down $(sudo $v -c "show bfd peers counters" |
		awk "/Session down events/{s+=\$NF} END{print s+0}") peer-up $(sudo $v -c "show bfd peers brief" | grep -cw up)"'
}
dut() {
	timeout 25 $S $M1 'P=$(pgrep -x xdp-bfd); C=/sys/fs/cgroup/system.slice/xdp-bfd.service;
		echo "eng-rss $(awk "/VmRSS/{print \$2}" /proc/$P/status) eng-swap $(awk "/VmSwap/{print \$2}" /proc/$P/status)" \
		"cg $(($(cat $C/memory.current) / 1024)) swap-used $(free -m | awk "/Swap/{print \$3}")" \
		"cls $(ps -o cls= -p $P) cpu_s $(awk "{print (\$14+\$15)/100}" /proc/$P/stat)"' 2>/dev/null || echo "dut n/a"
}

{
	echo "start $(date +%T) $(peer)"
	$S $M1 'uname -r; pgrep -a -x xdp-bfd; systemctl show -p MemoryMin,OOMScoreAdjust xdp-bfd | tr "\n" " "'
} | tee "$OUT/log"

# Rotating flood, 60 one-minute arms.
$S $M3 'cat > /tmp/hflood.sh <<"EOF"
for i in $(seq 0 59); do
	a=$(echo A B C D E | cut -d" " -f$((i % 5 + 1)))
	echo "$(date +%T) arm $a $(sudo timeout 60 trafgen -i /tmp/f$a.cfg -o enp1s0 -n 0 --gap 0us 2>&1 | grep -m1 "packets outgoing")"
done
EOF
nohup bash /tmp/hflood.sh >/tmp/hflood.log 2>&1 &'

# Sampler, every 30 s for 62 minutes.
(
	for i in $(seq 0 124); do
		echo "$(date +%T) $(peer) $(dut)"
		sleep 30
	done
) >>"$OUT/samples" 2>&1 &
SAMPLER=$!

for p in "${ORDER[@]}"; do
	echo "$(date +%T) phase $p: ${PHASES[$p]}" | tee -a "$OUT/log"
	timeout 330 $S $M1 "${PHASES[$p]} --timeout 300s --metrics-brief 2>&1 | tail -4" >>"$OUT/stress.txt" 2>&1
done
echo "stress done $(date +%T)" | tee -a "$OUT/log"

wait $SAMPLER
$S $M3 'cat /tmp/hflood.log' >"$OUT/flood.txt"
{
	echo "end $(date +%T) $(peer)"
	$S $M1 'sudo journalctl -k --since "-70min" | grep -iE "out of memory|oom-kill|killed process" | tail -20;
		sudo journalctl -u xdp-bfd --since "-70min" -o cat | grep -vE "stats: wrote|authentication key" | tail -20'
} | tee -a "$OUT/log"
