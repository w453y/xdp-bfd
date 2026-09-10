#!/bin/bash
# Event A: restart the peer's bfdd; the engine is the surviving end.
# Set these for your lab before running; there are no useful defaults.
DUT=${DUT:-user@dut}                       # host running bfd_tx
PVE=${PVE:-root@hypervisor}                # host that can capture the bridge
PEER_HOST=${PEER_HOST:-user@10.66.0.24}    # host running the peer bfdd
BRIDGE=${BRIDGE:-vmbr3}                    # bridge the two guests share
PEER="timeout 90 ssh -o BatchMode=yes -n $PEER_HOST"
FILT='(udp port 3784 or udp port 4784 or udp port 3785) and (host 10.66.0.24 or host 10.66.0.25 or host 10.66.0.22 or host 10.66.0.10 or host 10.66.0.18 or host 10.66.0.11)'

ssh -o BatchMode=yes -n $PVE "rm -f /tmp/eventA.pcap; nohup tcpdump -i $BRIDGE -s 200 -w /tmp/eventA.pcap '$FILT' >/tmp/eventA.tcpdump.log 2>&1 & echo started"
sleep 3

echo "=================== T0 (before restart) ==================="
date -u +'wall %H:%M:%S'
ssh -n $DUT "sudo kill -USR1 \$(pgrep -x bfd_tx); sleep 1; sudo python3 /tmp/snap_engine.py" > /tmp/A_engine_t0.json
ssh -n $DUT "$PEER 'bash /tmp/snap_peer.sh'" > /tmp/A_peer_t0.txt
cat /tmp/A_peer_t0.txt
python3 -c "
import json;d=json.load(open('/tmp/A_engine_t0.json'))
print('engine up %d/%d  auth-bad=%d rejected=%d'%(d['up'],d['total'],d['stats']['auth-bad'],d['stats']['rejected']))
for k,v in sorted(d['watched'].items()): print(' %-12s %-5s my=%-11d rem=%-11d up_ev=%d down_ev=%d demand_on=%s peer=%s'%(k,v['state'],v['my_disc'],v['remote_disc'],v['up_events'],v['down_events'],v['demand']['on'],v['demand']['peer']))
"

echo "=================== RESTART peer bfdd ==================="
date -u +'wall %H:%M:%S'
ssh -n $DUT "$PEER 'sudo pkill -x bfdd; echo killed'"
sleep 75

echo "=================== T1 (75s after restart) ==================="
date -u +'wall %H:%M:%S'
ssh -n $DUT "sudo kill -USR1 \$(pgrep -x bfd_tx); sleep 1; sudo python3 /tmp/snap_engine.py" > /tmp/A_engine_t1.json
ssh -n $DUT "$PEER 'bash /tmp/snap_peer.sh'" > /tmp/A_peer_t1.txt
cat /tmp/A_peer_t1.txt
python3 -c "
import json;d=json.load(open('/tmp/A_engine_t1.json'))
print('engine up %d/%d  auth-bad=%d rejected=%d'%(d['up'],d['total'],d['stats']['auth-bad'],d['stats']['rejected']))
for k,v in sorted(d['watched'].items()): print(' %-12s %-5s my=%-11d rem=%-11d up_ev=%d down_ev=%d reason=%s'%(k,v['state'],v['my_disc'],v['remote_disc'],v['up_events'],v['down_events'],v['last_reason']))
"

ssh -o BatchMode=yes -n $PVE "pkill -x tcpdump; sleep 2; ls -l /tmp/eventA.pcap; capinfos -c /tmp/eventA.pcap 2>/dev/null | tail -2"
echo DONE
