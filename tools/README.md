# Tools

Things that produce numbers or reproduce a result, as opposed to the
evidence itself. None of it is needed to build or run xdp-bfd; that is
all on [main](https://github.com/w453y/xdp-bfd).

| | |
|---|---|
| [measure/](measure/) | The instruments: the flood harness, the sweep ladder, the dead-man rig and the starvation measurement. They read the lab's addresses from the environment; defaults are in `measure/sweep_ladder.py`. |
| [matrix/](matrix/) | One support-matrix arm: does this distribution build the engine, load the object, and bring a session up. Output is the JSON under `matrix/`. |
| [retired-rigs/](retired-rigs/) | Standalone rigs the test suites replaced. Kept because each still explains its behaviour more directly than the suite that now covers it. |

All of these need the testbed described in
[reproduction.md](../reproduction.md).
