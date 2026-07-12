#!/bin/sh
# xdp-bfd engine + XDP, FRR as control plane
sudo systemctl stop frr
sudo pkill -x bfd_tx 2>/dev/null
sleep 1
sudo ip link set dev ens19 xdpdrv off 2>/dev/null
sudo sed -i 's|^bfdd_options=.*|bfdd_options="  --daemon -A 127.0.0.1 --dplaneaddr ipv4c:127.0.0.1:50700"|' /etc/frr/daemons
cd ~/xdp-bfd
sudo ./bfd_tx --dplane 50700 --kernel-tx ens19 --dp-hold 60 &
sleep 2
sudo systemctl start frr
sleep 3
echo "mode B: xdp-bfd dplane"
