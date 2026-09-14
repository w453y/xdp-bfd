# xdp-bfd

BFD (RFC 5880, 5881, 5883) with the fast path in XDP. Detection and
transmission run in the driver path and in softirq, so aggressive timers
hold under CPU load that makes userspace BFD daemons flap.

Runs standalone, or as a data plane for an unmodified FRR bfdd over FRR's
own distributed-BFD protocol.

Asynchronous mode with the full RFC 5880 state machine, single-hop and
multihop, IPv4 and IPv6, echo (reflector and originator), poll sequences
and demand mode, all on one shared fast path. Up to 64 concurrent
sessions per host. Authentication is implemented in the fast path but
cannot yet be driven by stock FRR; see Limitations.

## Requirements

Linux with XDP, libbpf, clang 20 or newer for the BPF object, and a C
compiler for the userspace engine. Loading and attaching need root.

## Build

```
make          # bfd_xdp.o, bfd_tx, bfd_loader
make check    # unit suites, no testbed required
```

## Usage

Standalone:

```
sudo ./bfd_tx <local-ip> <peer-ip> --kernel-tx <interface>
```

Under FRR, where bfdd creates and owns the sessions, assigns
discriminators and displays state, and the packets ride the XDP path:

1. In `/etc/frr/daemons`, set
   `bfdd_options="  --daemon -A 127.0.0.1 --dplaneaddr ipv4c:127.0.0.1:50700"`
2. Start the engine first:
   `sudo ./bfd_tx --dplane 50700 --kernel-tx <interface>`
3. `systemctl restart frr`, then configure peers in vtysh as usual.

`--kernel-tx` names the first interface to attach; others are attached on
demand as bfdd places sessions on them. `SIGUSR1` writes a JSON snapshot
of every session, counter and histogram to `/tmp/bfd_tx_stats.json`.

## Deployment

- **Reserve the dplane port** from the ephemeral range
  (`net.ipv4.ip_local_reserved_ports = 50700`). A bfdd dplane client
  retrying against a missing listener can TCP self-connect and
  permanently steal the port, which `SO_REUSEADDR` does not recover. Do
  not also reserve 65472-65535: the engine binds its own session slots
  there, and `ip_local_reserved_ports` blocks explicit `bind()` too.
- **`--dp-hold <sec>`** keeps wire sessions alive across a bfdd restart,
  adopting them again by address pair with discriminator continuity and
  tearing them down at the deadline if bfdd never returns. Default 0
  preserves drop-and-recreate.
- **`--deadman-us <usec>`** bounds how long the fast path will answer for
  an engine that has stopped making progress. Default 1s; 0 disables.
- **`--demand-poll-us <usec>`** bounds how long a demanding session may go
  without verifying its path. Default 1s; 0 disables.
- **Echo needs the neighbour to forward.** An echo packet is
  self-addressed, so the far end loops it back only with forwarding
  enabled for that family.
- **A keychain key needs its algorithm set explicitly.** bfdd selects
  only `cleartext` or `hmac-sha-1`, and a key defaults to neither.
  Configuring `key-string` alone leaves the session unauthenticated
  while `show bfd peer` still reports authentication configured.

Several bfdd fixes this work depends on are upstream but absent from
packaged releases up to 10.5.1. On those, prefer the TCP transport
(`unixc:` client mode fails every connect), and with more than about 20
peers add them via vtysh after the data plane connects rather than from
`frr.conf`.

## Limitations

- **Authentication is unavailable through stock FRR.** `bfddp_session_msg`
  has no field to carry the key, and bfdd offloads an authenticated
  session anyway, then sends it unauthenticated while `show bfd peer`
  reports otherwise. This engine fails closed against that, so such a
  session never comes up. Keep authenticated sessions off the data plane
  until the bfddp key extension lands.
- **Keyed SHA1 follows bfdd, not RFC 5880 s6.7.4.** The RFC computes a
  plain SHA1 with the key in the Auth Key/Hash field; bfdd zeroes that
  field and computes an HMAC. They do not interoperate, and bfdd is the
  control plane on one side of every session here.
- **Keyed MD5 (types 2 and 3) is not implemented,** because no bfdd
  keychain algorithm maps onto those types.
- **Demand mode verifies the path on a timer, where stock bfdd does
  not.** A demanding system holds its detection timer, so without this
  nothing could ever take such a session down. `--demand-poll-us` sets
  how long it may go unverified (default 1s, never faster than the
  session's own detect budget); 0 restores bfdd's behaviour.
- **Two of these engines must not face each other.** RX-clocked TX has no
  clock of its own, so two `--kernel-tx` sides transmit as fast as they
  can process frames. Against bfdd this is bounded, because bfdd paces
  from its own timer.

## Testing

```
make check              # ABI pins, FSM table, bfddp parser, XDP program
sudo make check-netns   # end-to-end on veth and network namespaces
sudo make check-frr     # scenarios against stock FRR bfdd in containers
```

`make check` needs no NIC and no testbed: it drives the XDP program
through `BPF_PROG_TEST_RUN` and the engine's objects directly. The rigs
in `tests/` need root, and some need a second host.

## License

GPL-2.0. See [LICENSE](LICENSE).
