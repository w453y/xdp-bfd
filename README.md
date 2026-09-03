# xdp-bfd

A BFD implementation (RFC 5880, 5881, 5883) with the fast path in XDP.
Detection and transmission run in the driver path and in softirq, so they
hold aggressive timers under CPU load that makes userspace BFD daemons
flap. It runs standalone, or as a data plane for an unmodified FRR bfdd
over FRR's own distributed-BFD protocol.

It began as a measurement project asking whether software BFD really
cannot hold aggressive timers under load. The measurements said the
interesting failure was narrower than the folklore, and the project became
an implementation.

## Status

| Capability | State |
|---|---|
| Asynchronous mode, RFC 5880 state machine | implemented |
| Single-hop (RFC 5881), GTSM TTL 255 | implemented |
| Multihop (RFC 5883), per-session minimum TTL, UDP 4784 | implemented |
| IPv4 and IPv6, one shared key and one fast path | implemented |
| Echo reflector (RFC 5880 s6.4), entirely in XDP | implemented, both families |
| Echo originator with RTT and loss accounting | implemented, both families |
| Poll sequences and mid-session renegotiation (s6.8.3) | implemented |
| Demand mode (s6.6) | implemented |
| `your_disc` demux validation (s6.8.6) | implemented |
| FRR distributed-BFD data plane (bfddp) | implemented, stock FRR, no patches |
| Graceful control-plane restart (`--dp-hold`) | implemented |
| Authentication (s6.7) | not implemented |
| Concurrent sessions | 64, architectural cap |

## Build

Needs clang 20 or newer for the BPF object, libbpf, and a C compiler for
the userspace engine.

```
make                  # bfd_xdp.o, bfd_tx, bfd_loader
make check            # unit suites, no testbed required
```

## Running standalone

```
sudo ./bfd_tx <local-ip> <peer-ip> --kernel-tx <if>
```

`--kernel-tx` names the interface the XDP program attaches to. Further
interfaces are attached on demand as bfdd places sessions on them.

`SIGUSR1` writes a JSON snapshot of every session, counter and histogram
to `/tmp/bfd_tx_stats.json`.

## Running under FRR

bfdd creates and owns the sessions, assigns discriminators, and displays
state and counters; the packets ride the XDP path.

1. In `/etc/frr/daemons`:
   `bfdd_options="  --daemon -A 127.0.0.1 --dplaneaddr ipv4c:127.0.0.1:50700"`
2. Start the engine first:
   `sudo ./bfd_tx --dplane 50700 --kernel-tx <if>`
3. `systemctl restart frr`, then configure peers in vtysh as usual.

Deployment notes:

- **Reserve the dplane port** from the ephemeral range
  (`net.ipv4.ip_local_reserved_ports = 50700`). A bfdd dplane client
  retrying against a missing listener can TCP self-connect to
  `127.0.0.1:50700` and permanently steal the port; `SO_REUSEADDR` does
  not recover it. Do not also reserve 65472-65535 — `reserved_ports`
  blocks explicit `bind()` too, and the engine binds its own slots there.
- **`--dp-hold <sec>`** keeps wire sessions alive across a bfdd restart:
  orphan on disconnect, adopt live sessions by address pair on re-ADD with
  discriminator continuity, and tear down at the deadline if bfdd never
  returns. Default 0 preserves drop-and-recreate.
- **Echo mode needs the neighbour to forward.** An echo packet is
  self-addressed, so the far end loops it back only with forwarding
  enabled for that family.

Several bfdd fixes this work depended on are upstream; packaged releases
up to 10.5.1 predate some of them. On those, prefer the TCP transport
(`unixc:` client mode fails every connect), and with more than about 20
peers add them via vtysh after the data plane connects rather than from
`frr.conf`.

## Testing

```
make check          # ABI pins, FSM table, bffdp parser, XDP program
sudo make check-netns   # end-to-end on veth and network namespaces
sudo make check-frr     # scenarios against stock FRR bfdd in containers
```

`tests/unit/` runs the XDP program through `BPF_PROG_TEST_RUN` and the
engine's own objects directly, with no NIC and no testbed. `tests/e2e/`
and the standalone rigs in `tests/` need root and, for some, a two-host
setup; `tests/inject_matrix.py` drives single-packet cases from a third
host against a live mesh.

## Limitations

**No authentication (RFC 5880 s6.7).**

**Demand mode does not poll on its own (s6.6).** The mode is implemented,
but nothing periodically initiates the Poll Sequence that would verify an
idle path — matching stock bfdd, which reaches `bfd_set_polling` only from
a parameter change. Demand at both ends without echo can therefore leave a
failure undetected.

**64 concurrent sessions.** Tied to the per-slot source port range
65472-65535, with one `bfd_tx` instance owning that range per host.

**Two of these engines must not face each other.** RX-clocked TX has no
clock of its own: each bounce triggers the peer's bounce immediately, so
two `--kernel-tx` sides transmit as fast as two XDP programs can process
frames. Against bfdd this is safe, because bfdd paces from its own timer
and bounds the rate.

## Layout

- `src/xdp/` — the XDP program: parse, validation, maps, detection sweep,
  echo reflection, RX-clocked TX
- `src/engine/` — the userspace daemon: argv and RX loop, session table,
  bfddp socket, kernel-TX mirror, RFC 5880 state machine, echo originator
- `src/loader/` — standalone observer and loader
- `include/bfd_shared.h` — the kernel/userspace map ABI, wire format and
  constants
- `tests/` — unit suites, end-to-end rigs, and the injection matrix

## License

GPL-2.0. See [LICENSE](LICENSE).
