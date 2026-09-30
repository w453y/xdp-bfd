#!/usr/bin/env python3
"""Floods from testmachine3 (hardware) against the live mesh, one arm at a time, reusing
m9-flood's frames. Root on the DUT. usage: flood1024.py ARM [secs] [gap]"""
import importlib.util, json, os, re, subprocess, sys, time

spec = importlib.util.spec_from_file_location("m9", "/home/w453y/testbed/m9_frames_hw.py")
m9 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m9)

STATS = "/tmp/bfd_tx_stats.json"
INJ = "w453y@10.66.0.3"
PEER = "w453y@10.66.0.2"


def sh(c):
    return subprocess.run(c, shell=True, text=True, capture_output=True).stdout


def user_ssh(host, cmd):
    import shlex
    return sh("sudo -u w453y ssh -o BatchMode=yes %s %s" % (host, shlex.quote(cmd)))


EPID = int([l.split()[0] for l in sh("pgrep -a -x xdp-bfd").splitlines() if "enp1s0" in l][0])


def dump():
    sh("rm -f %s" % STATS)
    os.kill(EPID, 10)
    for _ in range(50):
        if os.path.exists(STATS):
            try:
                return json.load(open(STATS))
            except ValueError:
                pass
        time.sleep(0.1)


def witness():
    return int(user_ssh(PEER, "sudo /opt/frr-master/bin/vtysh -c 'show bfd peers brief' | grep -cw up").strip() or 0)


def prog():
    pid_ = json.loads(sh("ip -j link show enp1s0"))[0]["xdp"]["prog"]["id"]
    j = json.loads(sh("bpftool prog show id %d -j" % pid_))
    return j.get("run_time_ns", 0), j.get("run_cnt", 0)


def rcvbuf():
    m = re.search(r"(\d+) receive buffer errors", sh("netstat -su"))
    return int(m.group(1)) if m else 0


def cpu(p):
    f = open("/proc/%d/stat" % p).read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")


def softirq():
    f = open("/proc/stat").readline().split()[1:]
    return int(f[6]), sum(int(x) for x in f)


d0 = dump()
by = {(s["peer"], s["local"]): s for s in d0["sessions"]}
real = by[("10.66.0.12", "10.66.0.112")]
yd = real["my_disc"]
# H: well-formed, state Up, your_disc naming a real session, from an address
# no session has: the pair misses and the program passes it to userspace.
yb = ", ".join("0x%02x" % b for b in yd.to_bytes(4, "big"))
BFD_MOVED = ("0x20, 0xc0, 0x03, 0x18, 0x11, 0x22, 0x33, 0x44, " + yb +
             ", 0x00, 0x00, 0xc3, 0x50, 0x00, 0x00, 0xc3, 0x50, 0x00, 0x00, 0x00, 0x00")
ARMS = dict(m9.ARMS)
ARMS["H"] = ("moved address naming a real discriminator (passed up)",
             m9.frame_ip(3784, 0xff, BFD_MOVED, src="10.66.0.3", dst="10.66.0.112"), "well-formed")

# I: the real pair and the real discriminator, the peer's timers random in
# every frame: each one is a change the engine mirrors.
BFD_CHURN = ("0x20, 0xc0, 0x03, 0x18, 0x11, 0x22, 0x33, 0x44, " + yb +
             ", 0x00, drnd(1), drnd(1), drnd(1), 0x00, 0x00, 0xc3, 0x50, 0x00, 0x00, 0x00, 0x00")
ARMS["I"] = ("real pair and discriminator, timers churning",
             m9.frame_ip(3784, 0xff, BFD_CHURN, src="10.66.0.12", dst="10.66.0.112"), "well-formed")

arm = sys.argv[1]
secs = int(sys.argv[2]) if len(sys.argv) > 2 else 10
gap = sys.argv[3] if len(sys.argv) > 3 else "0us"
desc, cfg, _ = ARMS[arm]
sh("sysctl -qw kernel.bpf_stats_enabled=1")
w0, p0, r0, c0, s0 = witness(), prog(), rcvbuf(), cpu(EPID), softirq()
downs0 = {s["lid"]: s["down_events"] for s in d0["sessions"]}
remote = ("cat > /tmp/f.cfg <<'CFGEOF'\n%s\nCFGEOF\n"
          "sudo timeout %d trafgen -i /tmp/f.cfg -o enp1s0 -n 0 --gap %s >/tmp/f.out 2>&1;"
          " grep -m1 'packets outgoing' /tmp/f.out" % (cfg, secs, gap))
t0 = time.time()
sent = user_ssh(INJ, remote).strip()
el = time.time() - t0
p1, r1, c1, s1 = prog(), rcvbuf(), cpu(EPID), softirq()
d1 = dump()
w1 = witness()
runs = p1[1] - p0[1]
flapped = [s for s in d1["sessions"] if s["down_events"] > downs0.get(s["lid"], 0)]
print("arm %s: %s" % (arm, desc))
print("  sent: %s over %.0fs" % (sent, el))
lost = d1["stats"].get("changes-lost", 0) - d0["stats"].get("changes-lost", 0)
print("  changes-lost +%d, dplane notifications to bfdd: see engine log" % lost)
print("  xdp %.0f frames/s, %.0f ns/frame; engine cpu %.1f%%; host softirq %.1f%%; rcvbuf errors +%d" % (
    runs / el, (p1[0] - p0[0]) / runs if runs else 0, 100 * (c1 - c0) / el,
    100 * (s1[0] - s0[0]) / max(1, s1[1] - s0[1]), r1 - r0))
print("  during: engine %d up, witness %d -> %d; sessions that flapped: %d %s" % (
    d1["sessions_up"], w0, w1, len(flapped), [s["peer"] for s in flapped][:5]))
end = time.time() + 30
while time.time() < end:
    d = dump()
    if d["sessions_up"] >= len(d["sessions"]) - 2 and witness() >= len(d["sessions"]) - 2:
        break
    time.sleep(1)
print("  after: engine %d/%d, witness %d, recovered in %.0fs" % (
    d["sessions_up"], len(d["sessions"]), witness(), time.time() - (t0 + el)))
