#!/bin/bash
# Event B: restart the engine; the peer's bfdd is the surviving end.
# Set these for your lab before running; there are no useful defaults.
DUT=${DUT:-user@dut}                       # host running bfd_tx
PVE=${PVE:-root@hypervisor}                # host that can capture the bridge
PEER_HOST=${PEER_HOST:-user@10.66.0.24}    # host running the peer bfdd
BRIDGE=${BRIDGE:-vmbr3}                    # bridge the two guests share
PEER="timeout 90 ssh -o BatchMode=yes -n $PEER_HOST"
FILT='(udp port 3784 or udp port 4784 or udp port 3785) and (host 10.66.0.24 or host 10.66.0.25 or host 10.66.0.22 or host 10.66.0.10 or host 10.66.0.18 or host 10.66.0.11)'

ssh -o BatchMode=yes -n $PVE "rm -f /tmp/eventB.pcap; nohup tcpdump -i $BRIDGE -s 200 -w /tmp/eventB.pcap '$FILT' >/tmp/eventB.tcpdump.log 2>&1 & echo capture started"
sleep 3

echo "=================== T0 ==================="
ssh -n $DUT "$PEER 'bash /tmp/snap_peer.sh'"

echo "=================== RESTART engine ==================="
date -u +'wall %H:%M:%S'
ssh -n $DUT "sudo pkill -x bfd_tx; sleep 3; cd ${ENGINE_DIR:-/opt/xdp-bfd} && sudo sh -c 'nohup ./bfd_tx --dplane 50700 --kernel-tx ${KTX_IF:-ens19} --dp-hold 60 >/tmp/engine.out 2>&1 &'; sleep 3; pgrep -a bfd_tx"
sleep 80

echo "=================== T1 (80s later) ==================="
ssh -n $DUT "$PEER 'bash /tmp/snap_peer.sh'"
ssh -n $DUT "sudo kill -USR1 \$(pgrep -x bfd_tx); sleep 1; sudo python3 /tmp/snap_engine.py" > /tmp/B_engine_t1.json
python3 -c "
import json;d=json.load(open('/tmp/B_engine_t1.json'))
print('engine up %d/%d  auth-bad=%d rejected=%d'%(d['up'],d['total'],d['stats']['auth-bad'],d['stats']['rejected']))
for k,v in sorted(d['watched'].items()): print(' %-12s %-5s my=%-11d rem=%-11d up_ev=%d down_ev=%d reason=%s'%(k,v['state'],v['my_disc'],v['remote_disc'],v['up_events'],v['down_events'],v['last_reason']))
"
ssh -o BatchMode=yes -n $PVE "pkill -x tcpdump; sleep 2; capinfos -c /tmp/eventB.pcap 2>/dev/null | tail -1"
echo DONE
