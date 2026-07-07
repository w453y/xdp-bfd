#!/usr/bin/env python3
"""Generate the money graph: survival function (1-CDF) of DUT->peer
BFD inter-packet gaps during SCHED_FIFO stress, per TX backend.
Data: github.com/w453y/xdp-bfd docs/{baseline,m3-bakeoff}"""
import calendar
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

U = "/mnt/user-data/uploads/"

def load(path, s=None, e=None):
    g = []
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) != 2:
                continue
            t, gap = float(p[0]), float(p[1])
            if s is not None and not (s <= t <= e):
                continue
            if gap <= 0:
                continue
            g.append(gap)
    return np.sort(np.array(g))

# L4 windows (epoch seconds, from test logs)
bfdd_s = calendar.timegm((2026, 7, 6, 19, 2, 42))
bfdd_e = calendar.timegm((2026, 7, 6, 19, 3, 42))

series = [
    ("FRR bfdd",                load(U+"tgaps-234.txt", bfdd_s, bfdd_e),          "#d62728", "-"),
    ("naive userspace loop",    load(U+"cdf-bfd-m3-naive-L4.txt", 1783410430, 1783410490), "#ff7f0e", "-"),
    ("SO_TXTIME + etf",         load(U+"cdf-bfd-m3-txtime-L4.txt", 1783411898, 1783411964), "#9467bd", "-"),
    ("SO_TXTIME + etf, pipelined x5", load(U+"cdf-bfd-m3-txtime-pipe-L4.txt", 1783412705, 1783412766), "#8c564b", "--"),
    ("userspace + SCHED_FIFO 90 + pinned", load(U+"cdf-bfd-m3-rt.txt", 1783410883, 1783410945), "#1f77b4", "-"),
    ("XDP RX-clocked (this work)", load(U+"cdf-bfd-m3-ktx-L4.txt", 1783427215, 1783427276), "#2ca02c", "-"),
]

fig, ax = plt.subplots(figsize=(9, 5.6), dpi=150)

for name, g, color, ls in series:
    n = len(g)
    if n == 0:
        print(f"WARNING: no data for {name}")
        continue
    # survival: fraction of gaps >= x
    surv = 1.0 - (np.arange(1, n + 1) / n)
    # floor at 1/n for log scale visibility of the last point
    surv = np.maximum(surv, 1.0 / n)
    ax.step(g, surv, where="post", label=f"{name}  (n={n})",
            color=color, linestyle=ls, linewidth=1.8)
    print(f"{name:38s} n={n:6d} p50={g[int(n*.5)]:7.2f} p99={g[int(n*.99)]:8.2f} max={g[-1]:8.2f}")

ax.axvline(30, color="red", linewidth=1.2, alpha=0.8)
ax.text(30, 1.3, " 30ms detect budget\n (3 x 10ms)", color="red",
        fontsize=8.5, ha="left", va="top")

ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlim(5, 2000)
ax.set_ylim(5e-5, 1.5)
ax.set_xlabel("inter-packet gap, DUT \u2192 peer (ms, log scale)")
ax.set_ylabel("fraction of gaps \u2265 x (log scale)")
ax.set_title("BFD TX under SCHED_FIFO starvation: gap survival function by backend\n"
             "3\u00d710ms session \u00b7 4\u00d7 prio-50 RT hogs on 4 vCPUs \u00b7 60s \u00b7 wire-truth capture",
             fontsize=10.5)
ax.grid(True, which="both", alpha=0.25, linewidth=0.5)
ax.legend(fontsize=8, loc="lower left", framealpha=0.9)

fig.tight_layout()
fig.savefig("/home/claude/gap-survival.png", dpi=200)
fig.savefig("/home/claude/gap-survival.svg")
print("saved gap-survival.{png,svg}")
