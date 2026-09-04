# FRR data plane integration

First session driven end to end by stock FRR bfdd over the bffdp
distributed-BFD protocol, with this engine as the data plane and no FRR
patches.

`bfd-m4-dplane-L4.pcap` is the wire capture under RT starvation;
`m4-window.txt` holds the inter-packet gaps extracted from it.

The protocol and the operational notes are in
[writeup.md](../../writeup.md).
