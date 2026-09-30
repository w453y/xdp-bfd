#!/bin/bash
# mode_a.sh: stock bfdd on m1, no data plane. Stops the engine and drops its
# pinned XDP link and maps, so nothing of it stays attached.
sudo systemctl stop frr
sudo pkill -x bfd_tx
for i in $(seq 1 40); do pgrep -x bfd_tx >/dev/null || break; sleep 0.25; done
sudo rm -rf /sys/fs/bpf/xdp-bfd
sudo ip link set dev enp1s0 xdp off 2>/dev/null
sudo sed -i 's|^bfdd_options=.*|bfdd_options="  --daemon -A 127.0.0.1"|' /opt/frr-master/etc/frr/daemons
sudo systemctl start frr
ip -d link show enp1s0 | grep -c prog/xdp
echo "mode A: stock bfdd, no data plane"
