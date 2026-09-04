# xdp-bfd — research archive

The measurement and engineering record behind [xdp-bfd](https://github.com/w453y/xdp-bfd).
This branch holds documentation and evidence only; the tool itself lives
on `main`.

It began as a measurement project asking whether software BFD really
cannot hold aggressive timers under load. Every claim here has a packet
capture, a kernel counter or a log behind it, in the directory that makes
the claim.

## Start here

| | |
|---|---|
| [writeup.md](writeup.md) | The narrative, start to finish. |
| [reproduction.md](reproduction.md) | How to reproduce every number. |
| [benchmarks/](benchmarks/) | The headline figures, the captures they came from, and the tooling that recomputes them. |

## Milestones

In the order they happened.

| | |
|---|---|
| [01-baseline](milestones/01-baseline/) | Userspace BFD (FRR bfdd) under stress: the problem, measured. |
| [02-tx-bakeoff](milestones/02-tx-bakeoff/) | Five transmit architectures under RT starvation. |
| [03-frr-dataplane](milestones/03-frr-dataplane/) | First session driven by stock FRR bfdd over bffdp. |
| [04-hardening](milestones/04-hardening/) | Spoofing, GTSM, demux validation. |
| [05-abi-refactor](milestones/05-abi-refactor/) | One shared kernel/userspace ABI, and the review pass that followed. |
| [06-multisession](milestones/06-multisession/) | Many sessions on one engine. |
| [07-ipv6](milestones/07-ipv6/) | IPv6, one shared key and one fast path. |
| [08-echo](milestones/08-echo/) | Echo mode: reflector in XDP, originator in userspace. |
| [09-multihop](milestones/09-multihop/) | Multihop (RFC 5883) and per-session minimum TTL. |

## Investigations

Questions asked after the fact, each answered with a measurement.

| | |
|---|---|
| [main-loop](investigations/main-loop/) | What the userspace loop does per pass. |
| [tick-ladder](investigations/tick-ladder/) | What the loop's tick interval costs. |
| [sweep-ladder](investigations/sweep-ladder/) | The sweep interval does not set detection latency. |
| [starved-detection](investigations/starved-detection/) | Detection under RT starvation, measured from outside. |
| [wedged-ktx](investigations/wedged-ktx/) | Kernel-TX carries sessions through a stopped userspace. |
| [symmetric-ktx](investigations/symmetric-ktx/) | Two RX-clocked engines facing each other saturate the link. |
| [multi-interface](investigations/multi-interface/) | Attaching the fast path to more than one interface. |
| [v6-echo](investigations/v6-echo/) | IPv6 echo origination, and the assumption it corrected. |
| [netns-rig](investigations/netns-rig/) | Testing the userspace receive path in namespaces. |
| [dp-fuzz](investigations/dp-fuzz/) | An out-of-bounds read in the bffdp parser, found by fuzzing. |

## Review

[review/](review/) — an outside reviewer's read of the tree, and what
came of it.

## License

GPL-2.0. See [LICENSE](LICENSE).
