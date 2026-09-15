
## Injector ceiling (measured)

bfd-chaos into the mesh tops out near 700k pps and adding cores does not
help: 661k / 724k / 716k at 2 / 4 / 8 vCPUs. The bound is per-guest virtio
TX, not the generator's CPU. Do not resize the injector for rate; a second
injector VM on the test segment is the only way higher, and only the
single-flow arms would need it (a spoofed peer is one 5-tuple to one RSS
queue, so one DUT core eats it regardless of injector rate).
