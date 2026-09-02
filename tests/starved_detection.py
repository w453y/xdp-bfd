#!/usr/bin/env python3
"""Detection under RT starvation, measured twice: once by the engine and
once on the wire by a machine that is not being starved.

The engine's own number comes from last_overshoot_us in the SIGUSR1
snapshot. That is the process that was starved, so on its own it is not
enough. This also captures on the hypervisor bridge and measures the same
event from outside: the peer's last packet to the DUT's first State Down.

The two should differ by the detect budget, since the engine reports
overshoot (silence minus budget) and the wire shows total silence.

Everything is driven from here, including the capture start and stop, so
nothing in the timing depends on how fast someone types.

Needs: passwordless ssh to the peer (iptables) and to the hypervisor
(tcpdump), and stress-ng on the DUT.
"""

import argparse
import json
import os
import re
import shlex
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_ladder as sl          # noqa: E402  - path set above

HV = "root@192.168.11.191"
HV_IF = "vmbr3"
BUDGET_MS = 30.0                   # 3 x 10ms, the negotiated detect time


def hv_sh(cmd, check=True):
    """shlex.quote, not json.dumps: sh() goes through the local shell, and
    a double-quoted command lets IT expand $! before ssh sees the string -
    so tcpdump started remotely and the pid came back empty."""
    return sl.sh("ssh -o BatchMode=yes %s %s" % (HV, shlex.quote(cmd)),
                 check)


def capture_start(peer_ip, local_ip, remote_path):
    """Start tcpdump on the hypervisor and return its pid.

    Backgrounded with its own pid echoed rather than pkill'd later: pkill
    patterns match the ssh and sudo wrappers too, and killing those has
    taken down the thing under test before."""
    hv_sh("rm -f %s" % remote_path, check=False)
    out = hv_sh(
        "nohup tcpdump -i %s -nn -w %s "
        "'udp port 3784 and host %s and host %s' "
        ">/dev/null 2>&1 & echo $!"
        % (HV_IF, remote_path, peer_ip, local_ip))
    pid = out.strip().split()[-1] if out.strip() else ""
    if not pid.isdigit():
        sys.exit("capture did not start on %s; got %r" % (HV, out))
    time.sleep(1.0)                # let it attach before anything moves
    return pid


def capture_stop(pid, remote_path, local_path):
    hv_sh("kill %s" % pid, check=False)
    time.sleep(0.5)
    sl.sh("scp -q %s:%s %s" % (HV, remote_path, local_path))
    hv_sh("rm -f %s" % remote_path, check=False)


LINE = re.compile(r"^(\d+\.\d+) IP (\S+?)\.\d+ > \S+: BFDv1.*State (\w+)")


def wire_gap(path, peer_ip, local_ip):
    """Peer's last packet to the DUT's first State Down, in milliseconds.

    Returns None if the capture does not contain the event - better than a
    number nobody can defend."""
    out = sl.sh("tcpdump -r %s -nn -tt 2>/dev/null" % path, check=False)
    last_peer = None
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        ts, src, state = float(m.group(1)), m.group(2), m.group(3)
        if src == peer_ip:
            last_peer = ts
        elif src == local_ip and state == "Down" and last_peer:
            return (ts - last_peer) * 1000.0
    return None


def sample(target, stress_s, outdir, idx):
    peer_ip, local_ip = target["peer"], target["local"]
    lid = target["lid"]
    remote = "/tmp/starve-%d.pcap" % idx
    local = os.path.join(outdir, "sample-%02d.pcap" % idx)

    pid = capture_start(peer_ip, local_ip, remote)
    sl.block(peer_ip, local_ip, True)
    engine_us = None
    try:
        if stress_s:
            sl.sh(sl.STRESS % stress_s, check=False, capture=False)
        deadline = time.time() + 3.0 + stress_s
        while time.time() < deadline:
            time.sleep(0.2)
            d = sl.dump()
            for s in d["sessions"]:
                if s["lid"] == lid and s["state"] == "Down" \
                        and s["last_overshoot_us"]:
                    engine_us = s["last_overshoot_us"]
                    break
            if engine_us:
                break
    finally:
        # Capture stops BEFORE the unblock: once traffic resumes the pcap
        # contains a second event and "last peer packet" stops meaning the
        # one we care about.
        capture_stop(pid, remote, local)
        sl.block(peer_ip, local_ip, False)
        time.sleep(sl.RECOVER)

    wire_ms = wire_gap(local, peer_ip, local_ip)
    return engine_us, wire_ms


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--runs", type=int, default=10)
    p.add_argument("--stress", type=int, default=2)
    p.add_argument("--sweep-us", type=int, default=5000)
    p.add_argument("--out", default="docs/starved-detection")
    args = p.parse_args()

    sl.peer_sh("true")
    hv_sh("true")
    # Any tcpdump left behind by an aborted run would keep writing and
    # would not be ours to kill by pid later.
    hv_sh("pkill -x tcpdump; rm -f /tmp/starve-*.pcap", check=False)
    os.makedirs(args.out, exist_ok=True)

    sl.start_engine(args.sweep_us)
    live = sl.up_sessions(sl.dump())
    if len(live) < args.runs:
        sys.exit("only %d single-hop v4 sessions up, need %d"
                 % (len(live), args.runs))

    print("%d sessions up, %d samples, %ds starvation each\n"
          % (len(live), args.runs, args.stress))
    print("%-4s %-16s %12s %12s %10s" %
          ("n", "peer", "engine(ms)", "wire(ms)", "diff(ms)"))

    eng, wire = [], []
    for i in range(args.runs):
        e, w = sample(live[i % len(live)], args.stress, args.out, i + 1)
        if e is None:
            print("%-4d %-16s %12s %12s %10s"
                  % (i + 1, live[i % len(live)]["peer"], "no detect", "-", "-"))
            continue
        eng.append(e / 1000.0)
        row = "%-4d %-16s %12.2f" % (i + 1, live[i % len(live)]["peer"],
                                     e / 1000.0)
        if w is None:
            print(row + "%12s %10s" % ("not in pcap", "-"))
        else:
            wire.append(w)
            print(row + "%12.2f %10.2f" % (w, w - e / 1000.0))

    def line(name, vals):
        if not vals:
            return "%-8s no samples" % name
        sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
        return ("%-8s n=%d mean %.2fms sd %.2fms min %.2fms max %.2fms"
                % (name, len(vals), statistics.mean(vals), sd,
                   min(vals), max(vals)))

    print()
    print(line("engine", eng))
    print(line("wire", wire))
    if eng and wire:
        print("\nThe wire figure is total silence; the engine reports "
              "overshoot,\nso the difference should sit near the %.0fms "
              "detect budget." % BUDGET_MS)

    with open(os.path.join(args.out, "samples.json"), "w") as f:
        json.dump({"engine_ms": eng, "wire_ms": wire,
                   "stress_s": args.stress, "sweep_us": args.sweep_us}, f,
                  indent=2)
    print("\npcaps and samples.json in %s" % args.out)


if __name__ == "__main__":
    sys.exit(main())
