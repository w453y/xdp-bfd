#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Injection matrix for the XDP BFD engine.

Sends crafted packets from a third host and asserts on the kernel
counters, so the validation properties the engine claims can be checked
by running one command instead of by hand.

Runs on the engine host. Injection happens on a separate host reached
over ssh; this file pipes itself there rather than needing to be
installed on both.

    ./tests/inject_matrix.py                 run everything
    ./tests/inject_matrix.py --list          show the cases
    ./tests/inject_matrix.py --only gtsm-v4  run one
"""

import argparse
import json
import shlex
import subprocess
import sys
import time

INJECTOR_HOST = "w453y@10.66.0.3"
IFACE = "ens19"
COUNT = 20
SETTLE = 0.6

STAT = {0: "seen", 1: "accepted", 2: "malformed", 3: "rejected",
        4: "reflected", 5: "echo-returns"}


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True,
                          text=True).stdout


def bpf_map(name):
    out = sh("sudo bpftool map dump name %s" % name)
    try:
        return json.loads(out)
    except ValueError:
        sys.exit("cannot read map %s; is the engine running?" % name)


def stats():
    return {e["key"]: sum(c["value"] for c in e["values"])
            for e in bpf_map("bfd_stats")}


def addr_of(b):
    """Render a 16-byte key address, v4-mapped or v6."""
    if b[10] == 0xff and b[11] == 0xff:
        return ".".join(str(x) for x in b[12:16]), 4
    parts = ["%02x%02x" % (b[i], b[i + 1]) for i in range(0, 16, 2)]
    return ":".join(parts), 6


def sessions():
    """Configured sessions, as (peer, local, family, my_disc, min_ttl)."""
    out = []
    for e in bpf_map("tx_config"):
        peer, fam = addr_of(e["key"]["peer"]["b"])
        local, _ = addr_of(e["key"]["local"]["b"])
        out.append({
            "peer": peer, "local": local, "family": fam,
            "my_disc": e["value"]["my_disc"],
            "min_ttl": e["value"].get("min_ttl", 255),
            "enable": e["value"]["enable"],
        })
    return out


def pick(sess):
    """Choose the sessions the cases need, or explain what is missing."""
    got = {}
    for s in sess:
        if s["family"] == 4 and s["min_ttl"] == 255 and "v4" not in got:
            got["v4"] = s
        if s["family"] == 6 and s["min_ttl"] == 255 and "v6" not in got:
            got["v6"] = s
        if s["family"] == 4 and s["min_ttl"] < 255 and "mh4" not in got:
            got["mh4"] = s
        if s["family"] == 6 and s["min_ttl"] < 255 and "mh6" not in got:
            got["mh6"] = s
    return got


def inject(spec):
    """Run the sending half of this script on the injector host."""
    cmd = ["ssh", "-o", "BatchMode=yes", INJECTOR_HOST,
           "sudo python3 - --send %s" % shlex.quote(json.dumps(spec))]
    with open(__file__) as f:
        src = f.read()
    r = subprocess.run(cmd, input=src, capture_output=True, text=True)
    if r.returncode:
        return "injector failed: %s" % (r.stderr.strip() or r.stdout.strip())
    return None


def build_cases(got):
    """Each case: what to send, which counter moves, and by how much."""
    c = []

    if "v4" in got:
        s = got["v4"]
        c.append(("gtsm-v4", "TTL 64 to a single-hop session is off-link",
                  dict(family=4, src=s["peer"], dst=s["local"], ttl=64,
                       dport=3784, ydisc=0, state=1),
                  "rejected", COUNT))
        c.append(("disc-mismatch", "your_disc naming no session of ours",
                  dict(family=4, src=s["peer"], dst=s["local"], ttl=255,
                       dport=3784, ydisc=0x11111111, state=3),
                  "rejected", COUNT))
        c.append(("ip-options", "single-hop BFD never carries IP options",
                  dict(family=4, src=s["peer"], dst=s["local"], ttl=255,
                       dport=3784, ydisc=0, state=1, options=True),
                  "rejected", COUNT))
        c.append(("echo-unknown-peer", "echo from a peer we do not serve",
                  dict(family=4, src="10.66.0.250", dst="10.66.0.250",
                       ttl=255, dport=3785, ydisc=0, state=1, l2dst=True),
                  "reflected", 0))

    if "v6" in got:
        s = got["v6"]
        c.append(("gtsm-v6", "hop_limit 64 to a single-hop v6 session",
                  dict(family=6, src=s["peer"], dst=s["local"], ttl=64,
                       dport=3784, ydisc=0, state=1),
                  "rejected", COUNT))

    if "mh4" in got:
        s = got["mh4"]
        c.append(("mhop-below-min", "TTL under the negotiated minimum",
                  dict(family=4, src=s["peer"], dst=s["local"],
                       ttl=s["min_ttl"] - 10, dport=4784, ydisc=0, state=1),
                  "rejected", COUNT))
        if "v4" in got:
            t = got["v4"]
            c.append(("mhop-does-not-leak", "low TTL at a single-hop session "
                      "while multihop is live",
                      dict(family=4, src=t["peer"], dst=t["local"],
                           ttl=s["min_ttl"], dport=3784, ydisc=0, state=1),
                      "rejected", COUNT))

    if "mh6" in got:
        s = got["mh6"]
        c.append(("mhop-below-min-v6", "hop_limit under the minimum, v6",
                  dict(family=6, src=s["peer"], dst=s["local"],
                       ttl=s["min_ttl"] - 10, dport=4784, ydisc=0, state=1),
                  "rejected", COUNT))

    return c


def orchestrate(args):
    sess = sessions()
    if not sess:
        sys.exit("no configured sessions; start the engine first")

    got = pick(sess)
    cases = build_cases(got)

    if args.list:
        for name, desc, _, counter, delta in cases:
            print("%-22s %-8s %+d   %s" % (name, counter, delta, desc))
        return 0

    live = [x for x in sess if x["enable"]]
    if not live:
        sys.exit("no session is up; every case would pass vacuously")

    print("sessions: %d configured, %d up, using %s" %
          (len(sess), len(live), ", ".join(sorted(got))))
    missing = {"v4", "v6", "mh4", "mh6"} - set(got)
    if missing:
        print("no session for %s, those cases are skipped"
              % ", ".join(sorted(missing)))
    print()

    failures = 0
    for name, desc, spec, counter, expect in cases:
        if args.only and name != args.only:
            continue

        spec = dict(spec, iface=IFACE, count=COUNT)
        before = stats()
        err = inject(spec)
        if err:
            print("%-22s ERROR  %s" % (name, err))
            failures += 1
            continue
        time.sleep(SETTLE)
        after = stats()

        idx = [k for k, v in STAT.items() if v == counter][0]
        got_delta = after.get(idx, 0) - before.get(idx, 0)
        ok = got_delta == expect
        print("%-22s %-4s %s %+d (expected %+d)   %s"
              % (name, "ok" if ok else "FAIL", counter, got_delta, expect,
                 desc))
        if not ok:
            failures += 1

    print()
    print("%d case(s) failed" % failures if failures else "all cases passed")
    return 1 if failures else 0


def send(spec):
    """The injector half. Runs on the third host, needs root for scapy."""
    from scapy.all import Ether, IP, IPv6, UDP, Raw, sendp
    from scapy.all import IPOption_NOP

    def bfd(ydisc, state):
        md = 0xcafebabe
        return bytes([
            (1 << 5), (state & 3) << 6, 3, 24,
            (md >> 24) & 0xff, (md >> 16) & 0xff, (md >> 8) & 0xff, md & 0xff,
            (ydisc >> 24) & 0xff, (ydisc >> 16) & 0xff,
            (ydisc >> 8) & 0xff, ydisc & 0xff,
            0, 0x04, 0x93, 0xe0,
            0, 0x04, 0x93, 0xe0,
            0, 0, 0, 0,
        ])

    payload = bfd(spec["ydisc"], spec["state"])
    l4 = UDP(sport=49152, dport=spec["dport"]) / Raw(payload)

    if spec["family"] == 4:
        ip = IP(src=spec["src"], dst=spec["dst"], ttl=spec["ttl"])
        if spec.get("options"):
            # Four NOPs is one option word, so ihl becomes 6 and the UDP
            # header moves. Single-hop BFD never carries options, and the
            # engine drops anything that does rather than parse past them.
            ip.options = [IPOption_NOP() for _ in range(4)]
    else:
        ip = IPv6(src=spec["src"], dst=spec["dst"], hlim=spec["ttl"])

    sendp(Ether() / ip / l4, iface=spec["iface"], count=spec["count"],
          inter=0.005, verbose=0)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--send", help=argparse.SUPPRESS)
    p.add_argument("--list", action="store_true", help="show the cases")
    p.add_argument("--only", help="run a single case by name")
    args = p.parse_args()

    if args.send:
        return send(json.loads(args.send))
    return orchestrate(args)


if __name__ == "__main__":
    sys.exit(main())
