# TX bake-off

Five transmit architectures under identical conditions: 4x SCHED_FIFO
prio-50 hogs, 60 seconds, a 3x10ms session, measured from a wire-truth
capture taken off the hypervisor bridge rather than on the host under
test.

The result and the analysis are in [writeup.md](../../writeup.md) section
4. The charts drawn from these captures are in
[benchmarks/charts/](../../benchmarks/charts/).

| file | backend |
|---|---|
| `bfd-m3-naive.pcap` | naive userspace loop, unstressed |
| `bfd-m3-naive-L4.pcap` | naive userspace loop, RT starvation |
| `bfd-m3-rt.pcap` | userspace at `chrt -f 90` on a pinned core |
| `bfd-m3-txtime-L4.pcap` | `SO_TXTIME` + etf qdisc, one packet in flight |
| `bfd-m3-txtime-pipe-L4.pcap` | `SO_TXTIME` + etf qdisc, pipelined five deep |
| `bfd-m3-ktx-L4.pcap` | XDP RX-clocked TX |

`*-log.txt` is the engine's own output for each run. `*-window.txt`
holds the extracted inter-packet gap windows the tables were computed
from.
