# Reproducing the 64-session scale test

Assumes the base testbed from docs/reproduction.md: dut (10.66.0.1),
peer (10.66.0.2), chaos (10.66.0.3) on an isolated bridge, FRR 10.5.1,
engine built from main. All BFD timers 10ms/10ms/mult 3.

## 1. Addressing

64 sessions between three hosts need 64 distinct address pairs,
because bfdd's peer identity is (peer addr, ifname, vrf) only -
local-address is an attribute, not part of the key. Same-peer-addr
stanzas differing only in local-address silently edit one node.

dut:
    for i in $(seq 0 31); do
      sudo ip addr add 10.66.0.$((110+i))/24 dev ens19 2>/dev/null
      sudo ip addr add 10.66.0.$((160+i))/24 dev ens19 2>/dev/null
    done
peer:  10.66.0.10-41  (sudo ip addr add 10.66.0.$((10+i))/24 ...)
chaos: 10.66.0.60-91  (sudo ip addr add 10.66.0.$((60+i))/24 ...)

Pairs: dut .110+i <-> peer .10+i, dut .160+i <-> chaos .60+i.

## 2. Peer-side FRR config (peer and chaos)

Config-file bring-up is fine on the peers (stock bfdd, no dplane).
Remove any old bfd block first; sed keeps vtysh's broken `no peer`
out of the loop entirely:

    sudo sed -i '/^bfd$/,/^exit$/d' /etc/frr/frr.conf
    { echo bfd; for i in $(seq 0 31); do printf ' peer 10.66.0.%d local-address 10.66.0.%d interface ens19\n  transmit-interval 10\n  receive-interval 10\n exit\n !\n' $((110+i)) $((10+i)); done; echo exit; } | sudo tee -a /etc/frr/frr.conf > /dev/null
    sudo systemctl restart frr

(chaos: peer $((160+i)) local-address $((60+i)).)

## 3. DUT bring-up - MUST be incremental

Do NOT put the 64 peers in the dut's frr.conf. bfdd's dplane client
truncates the reconnect burst at 8KB (~20 sessions) and never
resends the rest (scale-64.txt bug 2). Keep the dut's frr.conf bfd
block EMPTY, start the engine + frr, then add peers one at a time
over the live dplane connection:

    sudo sed -i '/^bfd$/,/^exit$/d' /etc/frr/frr.conf
    sh mode_b.sh          # engine first, frr second (docs/benchmarks)
    sleep 10
    for i in $(seq 0 31); do
      sudo vtysh -c "conf t" -c "bfd" -c "peer 10.66.0.$((10+i)) local-address 10.66.0.$((110+i)) interface ens19" -c "receive-interval 10" -c "transmit-interval 10" -c "no shutdown"
      sudo vtysh -c "conf t" -c "bfd" -c "peer 10.66.0.$((60+i)) local-address 10.66.0.$((160+i)) interface ens19" -c "receive-interval 10" -c "transmit-interval 10" -c "no shutdown"
    done
    sleep 15
    sudo vtysh -c "show bfd peers brief" | grep -c up     # expect 64
    sudo ss -ulpn 'sport >= 65472' | grep -c bfd_tx       # expect 64

Never `write memory` on the dut: a persisted 64-peer config makes
every frr restart re-trigger the truncation.

## 4. Capture (hypervisor)

    tcpdump -i vmbr3 -w /tmp/bfd-64.pcap udp port 3784 &

## 5. Stress

    sudo vtysh -c "show bfd peers counters" | grep -c "down events: 0"
    stress-ng --cpu 4 --timer 8 --timerfd 4 --hrtimers 2 --timeout 120 &
    sleep 125
    sudo vtysh -c "show bfd peers brief" | grep -c up
    sudo vtysh -c "show bfd peers counters" | grep -c "down events: 0"

At this N expect the possibility of a correlated multi-session flap
from a single RX-softirq stall (scale-64.txt results); the engine
log timestamps every DETECT TIMEOUT with its silent gap.

## 6. Mass kill

chaos:  sudo pkill -9 -x bfdd; date +%s.%N
dut:    collect the 32 DETECT TIMEOUT lines; then
        sudo vtysh -c "show bfd peers brief" | grep -c up   # expect 32
chaos:  watchfrr respawns bfdd from the saved config; dut returns
        to 64 unattended.

## 7. Analysis

Per-slot max TX gap, windowed to the stress period (whole-capture
max is dominated by 1s slow-rate bring-up TX, not by stress):

    tshark -r /tmp/bfd-64.pcap -Y "udp.srcport >= 65472 && frame.time_epoch >= T0 && frame.time_epoch <= T1" -T fields -e frame.time_epoch -e udp.srcport 2>/dev/null |
    sort -k2,2n -k1,1n |
    awk '{if($2==p){g=($1-t)*1000; if(g>m[$2])m[$2]=g} p=$2; t=$1} END{for(q in m) print q, m[q]}' | sort -k2 -rn

Windowed evidence pcaps via editcap with LOCAL wall-clock times
(`date -d @<epoch>`), then gzip -9 (66-byte packets, snaplen
truncation gains nothing; tshark reads .pcap.gz directly).

## 8. Pitfalls hit while developing this test, so you skip them

- vtysh `no peer` fails validation in FRR 10.5.1 regardless of
  form; delete peers by sed on frr.conf + restart.
- Changing local-address on an existing peer node does not reach
  the dataplane; recreate the session.
- ifconfig hides secondary addresses; use `ip -br addr`.
- A leftover session on the peer holding a stale remote disc can
  deadlock against the engine's your_disc drop if the engine's TX
  sources from the wrong address; fixed in the engine (slot sockets
  bind the session's local address) but the symptom - one session
  down forever while 63 run - is worth recognizing.
