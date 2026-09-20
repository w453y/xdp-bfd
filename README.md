# xdp-bfd

BFD (RFC 5880, 5881, 5883) with the fast path in XDP. Detection and
transmission run in the driver path and in softirq, so sub-second timers
hold under load that makes a userspace BFD daemon flap.

It runs standalone, or as a data plane for an unmodified FRR bfdd over
FRR's distributed-BFD protocol. Asynchronous mode with the full state
machine, single-hop and multihop, IPv4 and IPv6, echo, poll sequences and
demand mode. 64 sessions per host.

## Build

```
make          # bfd_xdp.o, bfd_tx, bfd_loader
make check    # unit suites; no root, no NIC, no testbed
```

Needs libbpf, a C compiler, and clang 17 or newer for the BPF object.
Loading and attaching need root.

## Run

Standalone:

```
sudo ./bfd_tx <local-ip> <peer-ip> --kernel-tx <interface>
```

Under FRR, where bfdd owns the sessions and the packets ride the XDP
path, put this in `/etc/frr/daemons`:

```
bfdd_options="  --daemon -A 127.0.0.1 --dplaneaddr ipv4c:127.0.0.1:50700"
```

then start the engine before FRR and configure peers in vtysh as usual:

```
sudo ./bfd_tx --dplane 50700 --kernel-tx <interface>
```

`--kernel-tx` names the first interface; the rest are attached as bfdd
places sessions on them. `SIGUSR1` writes a JSON snapshot of every
session and counter to `/tmp/bfd_tx_stats.json`.

Authentication works in the fast path but stock bfdd cannot carry the
keys to it yet, so keep authenticated sessions off the data plane for
now. Two of these engines must not face each other: RX-clocked transmit
has no clock of its own.

Deployment notes, tuning, the RFC conformance matrix and the rest of the
caveats are in the [wiki](https://github.com/w453y/xdp-bfd/wiki).

## License

GPL-2.0. See [LICENSE](LICENSE).
