#!/usr/bin/env python3
"""Sweep ladder: what does the kernel sweep interval cost in detection time?

The README presents a mean detection overshoot of roughly 1.3ms as a
deliberate trade for the 5ms sweep, and nothing has ever tested it. With
--sweep-us settable and the engine recording last_overshoot_us at each
detect-timeout transition, it is finally measurable.

METHOD, and why it is not the obvious one. Stopping frr on the peer
silences all 62 sessions at once, so their deadlines land within a few
milliseconds of each other and most are caught by the SAME sweep tick: 60
numbers, roughly one independent sample. The tell is the maximum sitting
near the peer's TX jitter rather than near the sweep interval.

So one session at a time, silenced by an egress drop rule ON THE PEER.
Dropping on the DUT would not work at all - XDP runs before netfilter, so
the fast path would still see and answer every packet.

Each iteration is one independent draw of sweep phase. The unit of
comparison is still the RUN MEAN across iterations, not the individual
sample, and an arm is only different from another if the gap clears the
spread of an arm against itself - the m8 gap measurement spanned 22.3 to
27.1ms across two runs of identical code, which is what that discipline is
for.

Prerequisites: passwordless sudo and key-based ssh to the peer, the same
setup inject_matrix.py needs for the injector. Nothing is installed there;
only iptables is used.
"""

import argparse
import json
import statistics
import subprocess
import sys
import time

PEER_HOST = "w453y@10.66.0.2"
ENGINE = "/home/w453y/xdp-bfd/bfd_tx"
IFACE = "ens19"
DPLANE = "50700"
STATS = "/tmp/bfd_tx_stats.json"
FRRINIT = "/opt/frr-master/sbin/frrinit.sh"
# frrinit.sh needs the stack's own libfrr; sudo drops the ambient
# environment, so it is passed as an assignment instead.
FRR_ENV = "LD_LIBRARY_PATH=/opt/frr-master/lib"
# Must match mode_b_opt.sh exactly, or these arms are not comparable
# with any other result taken on this testbed.
ENGINE_ARGS = "--dp-hold 60"
VTYSH = "/opt/frr-master/bin/vtysh"

# Which engine flag the arms vary. --sweep-us was the original
# question; the sweep ladder answered it by falsifying the sweep,
# leaving the main loop tick as the remaining candidate for what
# quantizes detection. --tick-us varies that instead.
KNOBS = {"sweep": ("--sweep-us", (5000, 2000, 1000)),
         "tick":  ("--tick-us", (2000, 1000, 500))}
# The L4 arm from docs/benchmarks: RT starvation of userspace. Run in
# short bursts per sample rather than across the whole arm, because a
# starved engine cannot answer SIGUSR1 either.
STRESS = ("sudo stress-ng --cpu 4 --sched fifo --sched-prio 50"
          " --timeout %ds")
RUNS = 10
SETTLE = 25
RECOVER = 8


def sh(cmd, check=True, capture=True):
    """capture=False for anything that starts a daemon.

    capture_output waits for EOF on the pipe, and frrinit.sh starts
    watchfrr, which daemonizes without closing inherited descriptors -
    so it holds the pipe open and this blocks forever. Invisible from
    mode_b_opt.sh, where stdout is a tty rather than a pipe.
    """
    if capture:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True)
    else:
        r = subprocess.run(cmd, shell=True, text=True,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    if check and r.returncode:
        sys.exit("failed: %s\n%s%s" % (cmd, r.stdout or "",
                                      r.stderr or ""))
    return r.stdout or ""


def peer_sh(cmd, check=True):
    return sh("ssh -o BatchMode=yes %s %s" % (PEER_HOST, json.dumps(cmd)),
              check)


def dump():
    """SIGUSR1 the engine and read the snapshot back."""
    sh("sudo pkill -USR1 -x bfd_tx")
    time.sleep(0.3)
    with open(STATS) as f:
        return json.load(f)


def start_engine(value, flag="--sweep-us"):
    """Mirror of mode_b_opt.sh, plus the arm's flag. Engine before
    control plane, which is the ordering the whole project depends on."""
    print("  restarting engine at %s %d" % (flag, value), flush=True)
    sh("sudo %s %s stop" % (FRR_ENV, FRRINIT), check=False, capture=False)
    sh("sudo pkill -x bfd_tx", check=False)
    time.sleep(1)
    sh("sudo ip link set dev %s xdpdrv off" % IFACE, check=False)
    sh("sudo ip link set dev %s xdp off" % IFACE, check=False)
    cmd = ("sudo nohup %s --dplane %s --kernel-tx %s %s %s %d"
           " >/tmp/eng_ladder.log 2>&1 &"
           % (ENGINE, DPLANE, IFACE, ENGINE_ARGS, flag, value))
    sh(cmd, capture=False)
    time.sleep(2)
    sh("sudo %s %s start" % (FRR_ENV, FRRINIT), capture=False)
    time.sleep(SETTLE)


def up_sessions(d):
    return [s for s in d["sessions"]
            if s["state"] == "Up" and s["family"] == 4 and not s["multihop"]]


def block(peer_ip, local_ip, on):
    """Silence one direction on the PEER. Not on the DUT: XDP sits ahead of
    netfilter, so a local rule would never see these packets."""
    flag = "-A" if on else "-D"
    peer_sh("sudo iptables %s OUTPUT -s %s -d %s -p udp --dport 3784 -j DROP"
            % (flag, peer_ip, local_ip))


def one_sample(target, budget_s=3.0, stress_s=0):
    """Silence one session, wait for the engine to declare it Down, and read
    back what that detection cost. Returns microseconds, or None.

    With stress_s, userspace is starved for that long immediately after
    the session goes silent - so the detection deadline falls inside the
    starvation window rather than before it. The stress is synchronous:
    a starved engine cannot answer SIGUSR1, so polling during it would
    time out reading a number that has not been written yet."""
    peer_ip, local_ip = target["peer"], target["local"]
    lid = target["lid"]

    block(peer_ip, local_ip, True)
    try:
        if stress_s:
            sh(STRESS % stress_s, check=False, capture=False)
        deadline = time.time() + budget_s
        while time.time() < deadline:
            time.sleep(0.2)
            d = dump()
            for s in d["sessions"]:
                if s["lid"] != lid:
                    continue
                if s["state"] == "Down" and s["last_overshoot_us"]:
                    return s["last_overshoot_us"]
        return None
    finally:
        block(peer_ip, local_ip, False)
        time.sleep(RECOVER)


def arm(value, runs, stress_s=0, flag="--sweep-us"):
    start_engine(value, flag)
    d = dump()
    live = up_sessions(d)
    if len(live) < runs:
        sys.exit("only %d single-hop v4 sessions up, need %d"
                 % (len(live), runs))

    print("arm %s %d: %d sessions up, %d samples"
          % (flag, value, d["sessions_up"], runs))
    out = []
    for i in range(runs):
        t = live[i % len(live)]
        v = one_sample(t, budget_s=3.0 + stress_s, stress_s=stress_s)
        if v is None:
            print("  %2d %-16s no detection within budget - skipped"
                  % (i + 1, t["peer"]))
            continue
        out.append(v)
        print("  %2d %-16s %.2fms" % (i + 1, t["peer"], v / 1000.0))
    return out


def main():
    p = argparse.ArgumentParser(
        description="measure detection overshoot against an engine knob")
    p.add_argument("--runs", type=int, default=RUNS)
    p.add_argument("--knob", choices=sorted(KNOBS), default="sweep")
    p.add_argument("--arms", default=None,
                   help="comma-separated values; defaults per --knob")
    p.add_argument("--json", action="store_true")
    p.add_argument("--stress", type=int, default=0, metavar="SECONDS",
                   help="starve userspace for this long per sample")
    args = p.parse_args()

    flag, defaults = KNOBS[args.knob]
    arms = ([int(x) for x in args.arms.split(",")] if args.arms
            else list(defaults))

    peer_sh("true")   # fail early and loudly if ssh is not set up

    print("varying %s over %s\n" % (flag, arms))
    results = {}
    for a in arms:
        results[a] = arm(a, args.runs, args.stress, flag)

    print()
    for a, vals in results.items():
        if not vals:
            print("%6dus: no samples" % a)
            continue
        mean = statistics.mean(vals) / 1000.0
        sd = (statistics.stdev(vals) / 1000.0) if len(vals) > 1 else 0.0
        print("%6dus: n=%d mean %.2fms sd %.2fms min %.2fms max %.2fms"
              % (a, len(vals), mean, sd, min(vals) / 1000.0,
                 max(vals) / 1000.0))

    print("\nA difference between arms is only real if it clears the spread\n"
          "of an arm against itself. Re-run an arm before believing a gap.")
    if args.stress:
        print("Stressed arm: these are detection times under %ds of RT\n"
              "starvation, so compare them against an idle run of the same\n"
              "arm, not against the 30ms budget." % args.stress)

    if args.json:
        print(json.dumps({str(k): v for k, v in results.items()}))


if __name__ == "__main__":
    main()
