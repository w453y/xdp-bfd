#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Turn `gcovr --json-summary` into a Markdown table for the job summary.

gcovr --json-summary --filter ... | python3 .github/coverage-summary.py
"""

import json, sys

WHAT = {
    "src/engine/fsm.c": "session state machine",
    "src/engine/dplane.c": "bfddp control-plane parser",
}

d = json.load(sys.stdin)
print("## Coverage of the host test suites\n")
print("How much of the two engine sources the host suites reach, from a")
print("`--coverage` build run by `fsm_run` and `dp_run`. The XDP program and")
print("the kernel-facing paths are covered by other suites and are not")
print("measured here. This is a report: there is no threshold and nothing in")
print("it fails the build.\n")
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
