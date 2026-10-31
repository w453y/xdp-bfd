# xdp-bfd

BFD (RFC 5880, 5881, 5883) with the fast path in XDP, so sub-second timers hold under load that makes a userspace BFD daemon flap.

It runs standalone or as the data plane for FRR's bfdd. Single-hop and multihop, IPv4 and IPv6, echo, poll and demand mode, simple password and keyed SHA1 authentication. 1024 sessions by default, up to 8192 with `--max-sessions`.

## Build

```
make             # bfd_xdp.o, bfd_tx, bfd_loader
make check-host  # unit suites, no root
```

Needs libbpf, a C compiler and clang 17 or newer. Loading needs root.

## Run

Standalone:

```
sudo ./bfd_tx <local-ip> <peer-ip> --kernel-tx <interface>
```

Under FRR, set this in `/etc/frr/daemons`:

```
bfdd_options="  --daemon -A 127.0.0.1 --dplaneaddr ipv4c:127.0.0.1:50700"
```

then start the engine before FRR and configure peers in vtysh as usual:

```
sudo ./bfd_tx --dplane 50700 --kernel-tx <interface>
```

Authenticated sessions under FRR need a bfdd that passes the keys to the data plane; FRR 10.7 and older do not.

Installation, configuration, monitoring and limitations are in the [wiki](https://github.com/w453y/xdp-bfd/wiki).
