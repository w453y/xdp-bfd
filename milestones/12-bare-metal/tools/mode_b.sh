#!/bin/bash
# mode_b.sh [EXTRA ENGINE ARGS...]: xdp-bfd engine (from $D, default ~/xdp-bfd-dscp)
# with bfdd as its control plane. Stops FRR on both ends and starts both
# together, so neither keeps a stale remote discriminator (FRR #23464).
D=${D:-$HOME/xdp-bfd-dscp}
ssh w453y@10.66.0.2 "sudo systemctl stop frr" & sudo systemctl stop frr; wait
sudo pkill -x bfd_tx
for i in $(seq 1 40); do pgrep -x bfd_tx >/dev/null || break; sleep 0.25; done
sudo rm -rf /sys/fs/bpf/xdp-bfd
sudo ip link set dev enp1s0 xdp off 2>/dev/null
sudo sed -i 's|^bfdd_options=.*|bfdd_options="  --daemon -A 127.0.0.1 --dplaneaddr ipv4c:127.0.0.1:50700"|' /opt/frr-master/etc/frr/daemons
cd "$D" && sudo sh -c "nohup ${PRIO:+chrt -f $PRIO} ./bfd_tx --dplane 50700 --kernel-tx enp1s0 --dp-hold 60 --sweep-us 5000 --bpf-obj $D/bfd_xdp.o --stats-dump /tmp/bfd_tx_stats.json --pin /sys/fs/bpf/xdp-bfd $* >/tmp/bfd_tx_mesh.log 2>&1 &"
sleep 2
ssh w453y@10.66.0.2 "sudo systemctl start frr" & sudo systemctl start frr; wait
ip -d link show enp1s0 | grep -oE "prog/xdp id [0-9]+"
grep -E "dead-man" /tmp/bfd_tx_mesh.log
echo "mode B: xdp-bfd from $D, extra args: $*"
