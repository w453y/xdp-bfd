#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""gcovr --json-summary on stdin to a Markdown table for the job summary."""

import json, sys

WHAT = {
    "src/engine/fsm.c": "session state machine",
    "src/engine/dplane.c": "bfddp messages",
    "src/engine/dplane_conn.c": "bfddp connection and framing",
}

d = json.load(sys.stdin)
print("## Coverage of the host test suites\n")
print("From a `--coverage` build run by `fsm_run` and `dp_run`. Reported,")
print("not gated.\n")
print("| source | what it is | lines | branches | functions |")
print("|---|---|---:|---:|---:|")


def row(name, what, lc, lt, bc, bt, fc, ft, bold=False):
    def cell(c, t):
        pct = (100.0 * c / t) if t else 0.0
        s = "%.0f%% (%d/%d)" % (pct, c, t)
        return "**%s**" % s if bold else s

    n = "**%s**" % name if bold else "`%s`" % name
    print(
        "| %s | %s | %s | %s | %s |"
        % (n, what, cell(lc, lt), cell(bc, bt), cell(fc, ft))
    )


for f in sorted(d["files"], key=lambda x: x["filename"]):
    row(
        f["filename"],
        WHAT.get(f["filename"], ""),
        f["line_covered"],
        f["line_total"],
        f["branch_covered"],
        f["branch_total"],
        f["function_covered"],
        f["function_total"],
    )

row(
    "total",
    "",
    d["line_covered"],
    d["line_total"],
    d["branch_covered"],
    d["branch_total"],
    d["function_covered"],
    d["function_total"],
    bold=True,
)
