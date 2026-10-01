#!/bin/bash
# soak.sh MINUTES: one line a minute of both ends' down counters, Up count,
# the engine's RSS and CPU seconds, and deadman-hold.
S="ssh -o BatchMode=yes -o LogLevel=ERROR"
M1=w453y@10.100.15.145 M2=w453y@10.100.15.146
for i in $(seq 0 "$1"); do
	p=$($S $M2 'sudo /opt/frr-master/bin/vtysh -c "show bfd peers counters"' | awk '/Session down events/{s+=$NF} END{print s+0}')
	u=$($S $M2 'sudo /opt/frr-master/bin/vtysh -c "show bfd peers brief"' | grep -cw up)
	e=$($S $M1 'P=$(pgrep -x xdp-bfd); d=$(sudo /opt/frr-master/bin/vtysh -c "show bfd peers counters" | awk "/Session down events/{s+=\$NF} END{print s+0}");
		rss=$(awk "/VmRSS/{print \$2}" /proc/$P/status); cpu=$(awk "{print (\$14+\$15)/100}" /proc/$P/stat);
		sudo kill -USR1 $P; sleep 1; dh=$(python3 -c "import json;print(json.load(open(\"/tmp/bfd_tx_stats.json\"))[\"stats\"].get(\"deadman-hold\"))");
		echo "dut-down $d rss_kb $rss cpu_s $cpu deadman-hold $dh"')
	echo "$(date +%H:%M:%S) min $i peer-down $p peer-up $u $e"
	if [ "$i" -lt "$1" ]; then sleep 59; fi
done
