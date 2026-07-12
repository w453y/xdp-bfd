#!/bin/sh
# stock bfdd on the DUT
sudo pkill -x bfd_tx 2>/dev/null
sudo ip link set dev ens19 xdpdrv off 2>/dev/null
sudo sed -i 's|^bfdd_options=.*|bfdd_options="  --daemon -A 127.0.0.1"|' /etc/frr/daemons
sudo systemctl restart frr
sleep 3
echo "mode A: stock bfdd, no dplane"
