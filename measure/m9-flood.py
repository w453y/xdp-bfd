#!/usr/bin/env python3
"""M9: what a flood costs the fast path, per frame, per drop path.

Headline is ns-per-frame, not pps. A pps figure is a fact about this
injector (virtio TX bound ~700k regardless of cores). ns-per-frame times a
NIC's line rate is the answer for that NIC, which is what the DDoS question
needs. bpftool prog show gives run_time_ns and run_cnt with
kernel.bpf_stats_enabled=1; the delta quotient across an arm is the cost of
that path at that rate.

Arms B-G send ONE 5-tuple, the peer's: a forger spoofing the peer hits one
RSS queue and one CPU eats all of it, so that CPU's softirq % is the
saturation signal. Arm A spreads source ports across queues, because its
question is survival under unrelated line-rate traffic.

Down during a flood is a result, never an abort. Only failure to return to
64/64 within RECOVER_WINDOW after the flood stops is a problem, and it is
recorded before it is fixed.

    python3 m9.py <arm> <rate-label>     e.g. m9.py C 300k
    python3 m9.py --ceiling             just report ns/frame idle
"""
import json, os, re, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_ladder as sl

INJECTOR = "w453y@10.66.0.3"
DUT_IF = "ens19"
DUT_MAC = "bc:24:11:60:0e:53"
INJ_MAC = "bc:24:11:d9:f7:f1"
RECOVER_WINDOW = 30
FLOOD_SECS = 6
RATES = {"100k": "10us", "300k": "3us", "700k": "0us"}


def dut(cmd):
    # Local: this harness runs on the DUT. It used to ssh to the DUT's own
    # address, which has no key to itself, and every call came back empty.
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def _q(s):
    import shlex
    return shlex.quote(s)


def inj_bg(cfg, gap, secs):
    """Fire trafgen on the injector for `secs`. The DUT reaches the injector
    directly. -n 0 with --gap sends until timeout kills it."""
    remote = ("cat > /tmp/m9.cfg <<'CFGEOF'\n%s\nCFGEOF\n"
              "sudo timeout %d trafgen -i /tmp/m9.cfg -o ens19 -n 0 --gap %s "
              ">/tmp/m9.out 2>&1; grep -m1 'packets outgoing' /tmp/m9.out"
              % (cfg, secs, gap))
    return dut("ssh -o BatchMode=yes %s %s" % (INJECTOR, _q(remote)))


PROG_ID = None
def resolve_prog():
    global PROG_ID
    out = dut("sudo bpftool prog show 2>/dev/null | grep bfd_observer")
    m = re.search(r"(\d+): xdp", out)
    if not m:
        raise SystemExit("bfd_observer not attached:\n" + out)
    PROG_ID = m.group(1)


def prog_stats():
    out = dut("sudo bpftool prog show id %s 2>/dev/null" % PROG_ID).replace("\n", " ")
    m = re.search(r"run_time_ns (\d+).*?run_cnt (\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def rcvbuf_errors():
    """UDP datagrams the kernel dropped because the socket queue was full.
    The eviction mechanism by name: this is what separates a flood that
    starves the socket (G2/G3) from one that only saturates the core (G6),
    which the BPF counters cannot, since a malformed frame is XDP_PASS and
    reaches the socket too."""
    out = dut("awk '/^Udp: [0-9]/{print $6}' /proc/net/snmp")
    return int(out.strip() or 0)


def mesh():
    d = sl.dump()
    return d["sessions_up"], d["sessions_configured"], d["stats"]


def peer_downs():
    out = sl.peer_sh("sudo %s -c 'show bfd peers counters json'" % sl.VTYSH)
    return sum(s.get("session-down", 0) for s in json.loads(out))


# --- frames ----------------------------------------------------------------
# Verified against the counters each is meant to move. A frame to a BFD
# port must be a valid control packet first: bfd_ctrl_check tests version
# and length before session, GTSM or auth logic, so a malformed frame to
# 3784 is counted malformed and never reaches the path under test.
def _b(mac):
    return ", ".join("0x" + x for x in mac.split(":"))


def _w16(v):
    return "const16(%d)" % v


# A well-formed 24-byte BFD control packet: vers 1, state Up, no flags,
# mult 3, len 24, my_disc set, your_disc 0, tx/rx 50000, echo 0.
BFD_CTRL = ("0x20, 0xc0, 0x03, 0x18, 0x11, 0x22, 0x33, 0x44, "
            "0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3, 0x50, "
            "0x00, 0x00, 0xc3, 0x50, 0x00, 0x00, 0x00, 0x00")


def frame(dport, ttl, payload, sport="const16(12345)", spread=False):
    """spread=True randomises the source port each packet (arm A only), so
    the flow hashes across every RX queue instead of pinning one core."""
    # payload is a comma-separated byte list; total = eth0 + ip20 + udp8 + len
    n = len([x for x in payload.split(",") if x.strip()])
    total = 20 + 8 + n
    sp = "drnd(2)" if spread else sport
    return ("{\n"
            "  %s,\n  %s,\n  0x08, 0x00,\n"
            "  0x45, 0x00, %s, 0x00, 0x00, 0x40, 0x00, 0x%02x, 0x11,\n"
            "  csumip(14, 33),\n  10, 66, 0, 3,\n  10, 66, 0, 1,\n"
            "  %s, const16(%d), const16(%d), 0x00, 0x00,\n"
            "  %s,\n}\n"
            % (_b(DUT_MAC), _b(INJ_MAC), _w16(total), ttl,
               sp, dport, 8 + n, payload))


# your_disc = 0xDEADBEEF (wrong), state Up: reaches a configured session and
# is dropped by the demux rule, never touching its liveness.
BFD_CTRL_WRONGDISC = ("0x20, 0xc0, 0x03, 0x18, 0x11, 0x22, 0x33, 0x44, "
                      "0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0xc3, 0x50, "
                      "0x00, 0x00, 0xc3, 0x50, 0x00, 0x00, 0x00, 0x00")


def frame_ip(dport, ttl, payload, src, dst, sport="const16(12345)"):
    """Like frame() but with explicit src/dst IPv4 (dotted quad strings), so
    an arm can name a real configured session's address pair."""
    n = len([x for x in payload.split(",") if x.strip()])
    total = 20 + 8 + n
    s = ", ".join(src.split("."))
    d = ", ".join(dst.split("."))
    return ("{\n"
            "  %s,\n  %s,\n  0x08, 0x00,\n"
            "  0x45, 0x00, %s, 0x00, 0x00, 0x40, 0x00, 0x%02x, 0x11,\n"
            "  csumip(14, 33),\n  %s,\n  %s,\n"
            "  %s, const16(%d), const16(%d), 0x00, 0x00,\n"
            "  %s,\n}\n"
            % (_b(DUT_MAC), _b(INJ_MAC), _w16(total), ttl,
               s, d, sport, dport, 8 + n, payload))


# F: A bit set (0x44 = state Down + A), your_disc 0 so the demux "peer
# restarting" exception lets it reach the auth path; auth section keyed-SHA1
# (type 4), len 28, key id 3, an out-of-window seq and a garbage 20-byte
# digest. Every such frame fails the verify and, past 8 in a detect
# interval, is rate-limited by the per-session bucket.
BFD_AUTH_BAD = ("0x20, 0x44, 0x03, 0x34, 0x11, 0x22, 0x33, 0x44, "
                "0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3, 0x50, "
                "0x00, 0x00, 0xc3, 0x50, 0x00, 0x00, 0x00, 0x00, "
                "0x04, 0x1c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, "
                "0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, "
                "0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41")

# G: a self-addressed echo body; the reflector does not parse it on the
# forward path, so a plain 24-byte control-shaped payload suffices.
ECHO_SELF = ("0x20, 0xc0, 0x03, 0x18, 0x11, 0x22, 0x33, 0x44, "
             "0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3, 0x50, "
             "0x00, 0x00, 0xc3, 0x50, 0x00, 0x00, 0x00, 0x00")


ARMS = {
    # A: unrelated UDP, non-BFD port, source ports spread across queues.
    # Only `seen` moves (cbd30d6 leaves it before counting). Question:
    # does the host survive unrelated line-rate traffic on every queue.
    "A": ("non-BFD UDP, spread", frame(12345, 0xff,
          "fill(0x61, 18)", spread=True), "seen"),
    # B: valid BFD control packet at TTL 64 to 3784. The GTSM path (G-none,
    # already handled): must be well-formed to reach the TTL check, so it
    # carries a real control packet. Expect `rejected` to climb.
    "B": ("valid BFD, TTL64 (GTSM)", frame(3784, 0x40, BFD_CTRL), "rejected"),
    # C: short frame to 3784: malformed, dropped in XDP. Expect `malformed`.
    "C": ("malformed BFD", frame(3784, 0xff, "fill(0x61, 2)"), "malformed"),
    # D: valid BFD for an unconfigured pair at TTL 255 (G3). Passed to the
    # socket today; expect `well-formed` to climb and nothing to drop it.
    "D": ("valid BFD, unknown pair (G3)", frame(3784, 0xff, BFD_CTRL),
          "well-formed"),
    # E: well-formed BFD naming a REAL configured session but with the
    # wrong your_disc, at TTL 255. Passes G1/G2/G3 (configured pair) and is
    # dropped by the demux rule (RFC 5880 s6.8.6). Expect `rejected` to
    # climb and the named session NOT to flap: a forger who knows the pair
    # still cannot disturb it without our discriminator.
    "E": ("real session, wrong your_disc (demux)",
          frame_ip(3784, 0xff, BFD_CTRL_WRONGDISC,
                   src="10.66.0.12", dst="10.66.0.112"), "rejected"),
    # F: bad-auth flood at an authenticated session (10.66.0.22). Reaches
    # the auth path and trips the per-session token bucket (G4): a few
    # verifies per interval, the rest rate-limited before the digest. The
    # targeted session goes down by design; the rest of the mesh does not.
    "F": ("bad-auth flood, authenticated session (G4)",
          frame_ip(3784, 0xff, BFD_AUTH_BAD,
                   src="10.66.0.22", dst="10.66.0.122"), "auth-ratelimited"),
    # G: self-addressed UDP/3785 from a known echo peer (10.66.0.18) at TTL
    # 255. Reflected (XDP_TX); measures reflected pps. 3785 from a non-peer
    # is `declined`, never reflected (no amplification).
    "G": ("self-addressed echo, known peer (reflector)",
          frame_ip(3785, 0xff, ECHO_SELF,
                   src="10.66.0.18", dst="10.66.0.18"), "reflected"),
}


def run_arm(arm, rate):
    if arm not in ARMS:
        raise SystemExit("arm %s not defined yet; have %s" % (arm, list(ARMS)))
    name, cfg, counter = ARMS[arm]
    gap = RATES[rate]
    print("=== arm %s (%s) at %s, gap %s ===" % (arm, name, rate, gap))

    up, cfgn, s0 = mesh()
    if up != cfgn:
        raise SystemExit("REFUSING: mesh %d/%d, not clean" % (up, cfgn))
    pd0 = peer_downs()
    rb0 = rcvbuf_errors()
    rt0, rc0 = prog_stats()
    print("before: %d/%d up, peer-downs %d" % (up, cfgn, pd0))

    t0 = time.time()
    out = inj_bg(cfg, gap, FLOOD_SECS)
    sent = re.search(r"(\d+) packets outgoing", out)
    sent = int(sent.group(1)) if sent else 0
    dur = time.time() - t0
    pps = int(sent / dur) if dur else 0

    rt1, rc1 = prog_stats()
    rb1 = rcvbuf_errors()
    up1, _, s1 = mesh()
    pd1 = peer_downs()
    dframes = rc1 - rc0
    ns_per = (rt1 - rt0) / dframes if dframes else 0
    dcounter = s1.get(counter, 0) - s0.get(counter, 0)
    dseen = s1["seen"] - s0["seen"]

    # recovery
    rec = None
    end = time.time() + RECOVER_WINDOW
    while time.time() < end:
        u, c, _ = mesh()
        if u == c:
            rec = time.time() - (t0 + dur)
            break
        time.sleep(1)

    print("sent %d in %.1fs = %d pps" % (sent, dur, pps))
    print("prog: +%d runs, %.0f ns/frame on this path" % (dframes, ns_per))
    print("counters: seen +%d, %s +%d" % (dseen, counter, dcounter))
    print("peer downs +%d, RcvbufErrors +%d; mesh %d/%d after"
          % (pd1 - pd0, rb1 - rb0, up1, cfgn))
    print("recovery: %s" % ("%.0fs" % rec if rec is not None
                            else "DID NOT recover in %ds" % RECOVER_WINDOW))
    return {"arm": arm, "name": name, "rate": rate, "pps": pps,
            "ns_per_frame": round(ns_per, 1), "runs": dframes,
            "counter": counter, "counter_delta": dcounter, "seen_delta": dseen,
            "peer_downs": pd1 - pd0, "rcvbuf_errors": rb1 - rb0,
            "mesh_after": "%d/%d" % (up1, cfgn),
            "recovered_s": round(rec, 1) if rec is not None else None}


if __name__ == "__main__":
    resolve_prog()
    dut("sudo sysctl -w kernel.bpf_stats_enabled=1 >/dev/null 2>&1")
    if sys.argv[1:2] == ["--ceiling"]:
        rt0, rc0 = prog_stats(); time.sleep(5); rt1, rc1 = prog_stats()
        print("idle: %.0f ns/frame over %d runs"
              % ((rt1 - rt0) / max(1, rc1 - rc0), rc1 - rc0))
        raise SystemExit
    r = run_arm(sys.argv[1], sys.argv[2])
    print(json.dumps(r))
