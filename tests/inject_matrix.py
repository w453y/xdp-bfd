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

Four cases need a phantom session: a peer configured on the DUT that
nothing answers on, so its counters move only when we inject. Without
one they are skipped, not failed. Configure two, one per family:

    peer 10.66.0.200 multihop local-address <local v4>
     minimum-ttl 200
    peer fd66::200 multihop local-address <local v6>
     minimum-ttl 200

The session cap is 64, so free a slot first, and `write memory` or the
next restart loses them.
"""

import argparse
import json
import shlex
import subprocess
import sys
import time

# Lab defaults; every one is overridable from the command line so the
# harness is not welded to one testbed.
INJECTOR_HOST = "w453y@10.66.0.3"
IFACE = "ens19"
COUNT = 20
SETTLE = 0.6
UNKNOWN_ECHO = "10.66.0.250"
UNKNOWN_ECHO6 = "fd66::250"

MAC = None
# Fields an injected packet must not disturb on a live session.
WATCH = ("remote_disc", "detect_iv_us", "min_tx_us", "min_rx_us",
         "detect_mult", "peer_mac")
STAT = {0: "seen", 1: "well-formed", 2: "malformed", 3: "rejected",
        4: "reflected", 5: "echo-returns", 6: "declined", 7: "not-self", 8: "echo-ttl"}


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True,
                          text=True).stdout


def local_mac(iface):
    with open("/sys/class/net/%s/address" % iface) as f:
        return f.read().strip()


def echo_peer_addrs():
    """Peers of echo-active sessions, as the reflector sees them."""
    return [addr_of(e["key"]["b"]) for e in bpf_map("echo_peers")]


def bpf_map(name):
    out = sh("sudo bpftool map dump name %s" % name)
    try:
        return json.loads(out)
    except ValueError:
        sys.exit("cannot read map %s; is the engine running?" % name)


def counters():
    """Global stat slots by name, plus rx:<peer>:<local> per session.

    Global slots are useless for anything the live mesh also drives, so a
    case that must observe an accepted packet asserts on one session's own
    rx_pkts instead. A key absent before and present after reads as 0 -> n,
    which is what a session receiving its first packet looks like.
    """
    out = {STAT[e["key"]]: sum(c["value"] for c in e["values"])
           for e in bpf_map("bfd_stats") if e["key"] in STAT}
    for e in bpf_map("bfd_sessions"):
        peer = addr_of(e["key"]["peer"]["b"])[0]
        local = addr_of(e["key"]["local"]["b"])[0]
        out["rx:%s:%s" % (peer, local)] = e["value"]["rx_pkts"]
    return out


def stats():
    return {e["key"]: sum(c["value"] for c in e["values"])
            for e in bpf_map("bfd_stats")}


def session_value(peer, local):
    """Full bfd_sessions value for one pair, or None if it has no state."""
    for e in bpf_map("bfd_sessions"):
        if (addr_of(e["key"]["peer"]["b"])[0] == peer and
                addr_of(e["key"]["local"]["b"])[0] == local):
            return e["value"]
    return None


def rx_of(peer, local):
    """rx_pkts for one session, or None if it has no state yet."""
    v = session_value(peer, local)
    return None if v is None else v["rx_pkts"]


def session_states():
    """(peer, local) -> (alive, remote_disc) for every configured session.

    The counter oracle cannot see collateral damage: a case can move the
    counter it expects and still have disturbed a live session on the way.
    remote_disc is the sharp one, since an accepted payload's my_disc is
    what would overwrite it.
    """
    out = {}
    for e in bpf_map("bfd_sessions"):
        k = (tuple(e["key"]["peer"]["b"]), tuple(e["key"]["local"]["b"]))
        v = e["value"]
        watched = {f: (tuple(v[f]) if isinstance(v.get(f), list) else v.get(f))
                   for f in WATCH}
        out[k] = (v["alive"], watched)
    return out


def addr_of(b):
    """Render a 16-byte key address, v4-mapped or v6."""
    if b[10] == 0xff and b[11] == 0xff:
        return ".".join(str(x) for x in b[12:16]), 4
    import ipaddress
    return str(ipaddress.ip_address(bytes(b))), 6


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
        if (s["family"] == 4 and s["min_ttl"] < 255 and s["enable"]
                and "mh4" not in got):
            got["mh4"] = s
        # A configured peer nothing answers on: enable stays 0, so the
        # TX bounce never fires and its rx_pkts moves only when we inject.
        if (s["family"] == 4 and s["min_ttl"] < 255 and not s["enable"]
                and "phantom" not in got):
            got["phantom"] = s
        if (s["family"] == 6 and s["min_ttl"] < 255 and not s["enable"]
                and "phantom6" not in got):
            got["phantom6"] = s
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
        return "injector failed: %s" % (r.stderr.strip() or r.stdout.strip()), {}
    cap = {}
    for line in r.stdout.splitlines():
        if line.startswith("{"):
            try:
                cap = json.loads(line).get("capture", {})
            except ValueError:
                pass
    return None, cap


# Header rules the engine checks before it will look a session up. Each
# entry breaks exactly one, so a case still isolates its own rule even
# though all six land on the shared malformed counter.
MALFORMED = (
    ("bad-version", "BFD version other than 1", dict(vers=0)),
    ("zero-my-disc", "my_discriminator of zero is illegal", dict(mydisc=0)),
    ("zero-detect-mult", "detect multiplier of zero is illegal", dict(mult=0)),
    ("short-length", "length field below the 24-byte minimum", dict(blen=12)),
    ("length-overruns", "length field claiming more than the UDP payload "
     "holds", dict(blen=40)),
    ("truncated-header", "frame ends before the BFD header does",
     dict(trunc=12)),
)


def malformed_cases(sess, fam):
    """The malformed set for one family. The checks sit after the family
    branch, so running both exercises each parse path into them."""
    out = []
    for cname, cdesc, extra in MALFORMED:
        spec = dict(family=fam, src=sess["peer"], dst=sess["local"],
                    ttl=255, dport=3784, ydisc=0, state=1)
        spec.update(extra)
        out.append(("%s-v%d" % (cname, fam), cdesc, spec, "malformed", COUNT))
    return out


def phantom_cases(ph, fam):
    """Positive controls, only possible against a session nothing answers.

    Global counters are swamped by the live mesh, so these assert the
    phantom's own rx_pkts: no host exists at that address, so cfg->enable
    stays 0, the TX bounce never fires, and nothing but the injector moves
    its counter.
    """
    rx = [("rx:%s:%s" % (ph["peer"], ph["local"]), COUNT)]
    base = dict(family=fam, src=ph["peer"], dst=ph["local"],
                ttl=ph["min_ttl"], dport=4784, ydisc=ph["my_disc"], state=1)
    return [
        ("mhop-at-min-v%d" % fam,
         "TTL at the minimum reaches the session state update",
         dict(base), rx, None),
        ("long-frame-v%d" % fam,
         "trailing bytes past the BFD payload do not confuse the parser",
         dict(base, pad=200), rx, None),
    ]


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
        pf = session_value(s["peer"], s["local"])
        if pf:
            # Poll/Final responder (RFC 5880 s6.5). Everything but the P
            # bit is replayed from the session's own state, so each write
            # in the accept path lands back identical and the collateral
            # check verifies that. Only the reply proves the F bit, so
            # this case needs the capture oracle.
            c.append(("poll-final", "a packet with Poll set is answered "
                      "with Final",
                      dict(family=4, src=s["peer"], dst=s["local"], ttl=255,
                           dport=3784, ydisc=s["my_disc"],
                           state=pf["remote_state"], mydisc=pf["remote_disc"],
                           mult=pf["detect_mult"], mintx=pf["min_tx_us"],
                           minrx=pf["min_rx_us"],
                           minecho=pf.get("remote_min_echo_us", 0),
                           flags=0x20, l2dst=MAC, capture=True),
                      [("cap:final", COUNT)], None))

        c.extend(malformed_cases(s, 4))
        c.append(("echo-not-self", "a 3785 packet that is not self-addressed "
                  "is never reflected",
                  dict(family=4, src=s["peer"], dst=s["local"], ttl=255,
                       dport=3785, ydisc=0, state=1, l2dst=MAC),
                  [("not-self", COUNT), ("reflected", 0)], None))

        c.append(("echo-unknown-peer", "echo from a peer we do not serve",
                  dict(family=4, src=UNKNOWN_ECHO, dst=UNKNOWN_ECHO,
                       ttl=255, dport=3785, ydisc=0, state=1,
                       l2dst=MAC),
                  [("declined", COUNT), ("reflected", 0)], None))

    if "v6" in got:
        s = got["v6"]
        c.append(("gtsm-v6", "hop_limit 64 to a single-hop v6 session",
                  dict(family=6, src=s["peer"], dst=s["local"], ttl=64,
                       dport=3784, ydisc=0, state=1),
                  "rejected", COUNT))
        c.extend(malformed_cases(s, 6))
        c.append(("disc-mismatch-v6", "your_disc naming no session of ours",
                  dict(family=6, src=s["peer"], dst=s["local"], ttl=255,
                       dport=3784, ydisc=0x11111111, state=3),
                  "rejected", COUNT))
        # The v6 reflector is a separate helper, so its declined and
        # not-self branches need their own cases: the v4 ones above never
        # reach them.
        c.append(("echo-unknown-peer-v6", "echo from a v6 peer we do not "
                  "serve",
                  dict(family=6, src=UNKNOWN_ECHO6, dst=UNKNOWN_ECHO6,
                       ttl=255, dport=3785, ydisc=0, state=1, l2dst=MAC),
                  [("declined", COUNT), ("reflected", 0)], None))
        c.append(("echo-not-self-v6", "a v6 3785 packet that is not "
                  "self-addressed is never reflected",
                  dict(family=6, src=s["peer"], dst=s["local"], ttl=255,
                       dport=3785, ydisc=0, state=1, l2dst=MAC),
                  [("not-self", COUNT), ("reflected", 0)], None))

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

    # One case per family: the v4 and v6 reflectors are separate code
    # paths, so taking only the first peer silently under-tests one of them.
    seen_fams = set()
    for addr, fam in echo_peer_addrs():
        if fam in seen_fams:
            continue
        seen_fams.add(fam)
        c.append(("echo-reflect-v%d" % fam,
                  "echo from a peer of an echo-active session is returned",
                  dict(family=fam, src=addr, dst=addr, ttl=255,
                       dport=3785, ydisc=0, state=1, l2dst=MAC,
                       capture=True),
                  [("reflected", COUNT), ("cap:replies", COUNT)], None))
        # Same packet, only the TTL wrong: proves the echo GTSM check is
        # what blocks it, not anything about the peer or the payload.
        c.append(("echo-gtsm-v%d" % fam,
                  "an echo arriving below TTL 255 is not reflected",
                  dict(family=fam, src=addr, dst=addr, ttl=64,
                       dport=3785, ydisc=0, state=1, l2dst=MAC),
                  [("echo-ttl", COUNT), ("reflected", 0)], None))

    for kind, fam in (("phantom", 4), ("phantom6", 6)):
        if kind in got:
            c.extend(phantom_cases(got[kind], fam))

    return c


def orchestrate(args):
    global MAC
    MAC = local_mac(IFACE)
    sess = sessions()
    if not sess:
        sys.exit("no configured sessions; start the engine first")

    got = pick(sess)
    cases = build_cases(got)

    if args.list:
        for name, desc, _, counter, delta in cases:
            checks = counter if isinstance(counter, list) else [(counter, delta)]
            shown = " ".join("%s%+d" % (c, d) for c, d in checks)
            print("%-22s %-24s %s" % (name, shown, desc))
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

    if args.only and not any(c[0] == args.only for c in cases):
        # A name that matches nothing used to run zero cases and still
        # report "all cases passed". Every +0 assertion in this file
        # needs a witness; so does the case list itself.
        sys.exit("no case named %r. Available now: %s"
                 % (args.only, ", ".join(c[0] for c in cases)))

    failures = 0
    report = {"cases": [], "collateral": []}
    sess_before = session_states()

    for name, desc, spec, counter, expect in cases:
        if args.only and name != args.only:
            continue

        spec = dict(spec, iface=IFACE, count=COUNT)
        before = counters()
        err, cap = inject(spec)
        if err:
            print("%-22s ERROR  %s" % (name, err))
            failures += 1
            continue
        time.sleep(SETTLE)
        after = counters()
        # Capture results ride in as pseudo-counters with nothing in
        # `before`, so the existing delta arithmetic yields the raw count
        # and every counter-based case is untouched.
        after.update({"cap:%s" % k: v for k, v in cap.items()})

        checks = counter if isinstance(counter, list) else [(counter, expect)]
        results, ok, recorded = [], True, []
        for cname, cexp in checks:
            b, a = before.get(cname, 0), after.get(cname, 0)
            got = a - b
            recorded.append({"counter": cname, "before": b, "after": a,
                             "delta": got, "expected": cexp})
            if args.verbose:
                results.append("%s %d -> %d = %+d (expected %+d)"
                               % (cname, b, a, got, cexp))
            else:
                results.append("%s %+d (expected %+d)" % (cname, got, cexp))
            ok = ok and got == cexp
        report["cases"].append({"name": name, "ok": ok, "description": desc,
                                "checks": recorded})
        if not args.json:
            print("%-22s %-4s %s   %s"
                  % (name, "ok" if ok else "FAIL", ", ".join(results), desc))
        if not ok:
            failures += 1

    # Collateral check: nothing the matrix sent may have taken a live
    # session down or corrupted its learned remote discriminator.
    disturbed = 0
    sess_after = session_states()
    for k, (alive, disc) in sess_before.items():
        if alive != 1:
            continue
        peer = addr_of(list(k[0]))[0]
        if k not in sess_after:
            report["collateral"].append(
                {"peer": peer, "problem": "vanished"})
            if not args.json:
                print("%-22s FAIL session vanished during the run" % peer)
            disturbed += 1
            continue
        a2, w2 = sess_after[k]
        if a2 != 1:
            report["collateral"].append(
                {"peer": peer, "problem": "went down"})
            if not args.json:
                print("%-22s FAIL session went down during the run" % peer)
            disturbed += 1
            continue
        for f in WATCH:
            if w2[f] != disc[f]:
                report["collateral"].append(
                    {"peer": peer, "problem": "%s changed" % f,
                     "before": disc[f], "after": w2[f]})
                if not args.json:
                    print("%-22s FAIL %s changed %s -> %s"
                          % (peer, f, disc[f], w2[f]))
                disturbed += 1
    if disturbed:
        failures += disturbed
    elif not args.json:
        print()
        print("%d live session(s) undisturbed" % sum(
            1 for a, _ in sess_before.values() if a == 1))

    report["failures"] = failures
    report["undisturbed"] = sum(1 for a, _ in sess_before.values() if a == 1)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print()
        print("%d case(s) failed" % failures if failures
              else "all cases passed")
    return 1 if failures else 0


def send(spec):
    """The injector half. Runs on the third host, needs root for scapy."""
    from scapy.all import Ether, IP, IPv6, UDP, Raw, sendp
    from scapy.all import IPOption_NOP

    def bfd(ydisc, state, vers=1, mult=3, blen=24, mydisc=0xcafebabe,
            mintx=300000, minrx=300000, minecho=0, flags=0):
        """Defaults build a well-formed header; each knob breaks one rule
        the engine checks before it will look a session up."""
        md = mydisc
        return bytes([
            (vers << 5), ((state & 3) << 6) | flags, mult, blen,
            (md >> 24) & 0xff, (md >> 16) & 0xff, (md >> 8) & 0xff, md & 0xff,
            (ydisc >> 24) & 0xff, (ydisc >> 16) & 0xff,
            (ydisc >> 8) & 0xff, ydisc & 0xff,
            (mintx >> 24) & 0xff, (mintx >> 16) & 0xff,
            (mintx >> 8) & 0xff, mintx & 0xff,
            (minrx >> 24) & 0xff, (minrx >> 16) & 0xff,
            (minrx >> 8) & 0xff, minrx & 0xff,
            (minecho >> 24) & 0xff, (minecho >> 16) & 0xff,
            (minecho >> 8) & 0xff, minecho & 0xff,
        ])

    eth = Ether(dst=spec["l2dst"]) if spec.get("l2dst") else Ether()
    payload = bfd(spec["ydisc"], spec["state"],
                  vers=spec.get("vers", 1), mult=spec.get("mult", 3),
                  blen=spec.get("blen", 24),
                  mydisc=spec.get("mydisc", 0xcafebabe),
                  mintx=spec.get("mintx", 300000),
                  minrx=spec.get("minrx", 300000),
                  minecho=spec.get("minecho", 0),
                  flags=spec.get("flags", 0))
    if spec.get("trunc"):
        payload = payload[:spec["trunc"]]
    if spec.get("pad"):
        # Trailing bytes past the BFD payload. Legal: udp_len grows
        # while bfd->len stays 24, so the overread guard still holds
        # and the packet must be accepted, not dropped.
        payload = payload + bytes(spec["pad"])
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

    if not spec.get("capture"):
        sendp(eth / ip / l4, iface=spec["iface"], count=spec["count"],
              inter=0.005, verbose=0)
        return 0

    # Capture oracle. Counters prove the program reached a count() call;
    # they cannot prove a correct frame left the NIC. Both the reflect and
    # the control-bounce paths swap MACs, so whatever comes back is
    # addressed to us even though the IP is the spoofed peer's.
    from scapy.all import AsyncSniffer, get_if_hwaddr
    mymac = get_if_hwaddr(spec["iface"]).lower()
    sn = AsyncSniffer(iface=spec["iface"], store=True,
                      filter="udp and (port 3784 or port 3785)")
    sn.start()
    time.sleep(0.3)
    sendp(eth / ip / l4, iface=spec["iface"], count=spec["count"],
          inter=0.005, verbose=0)
    time.sleep(0.7)

    replies = final = 0
    for pkt in sn.stop():
        if not pkt.haslayer(Ether) or pkt[Ether].dst.lower() != mymac:
            continue
        raw = bytes(pkt[UDP].payload)
        if len(raw) < 2:
            continue
        replies += 1
        if raw[1] & 0x10:          # BFD_F_FINAL
            final += 1
    print(json.dumps({"capture": {"replies": replies, "final": final}}))
    return 0


def main():
    global INJECTOR_HOST, IFACE, COUNT, SETTLE, UNKNOWN_ECHO, UNKNOWN_ECHO6
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--send", help=argparse.SUPPRESS)
    p.add_argument("--list", action="store_true", help="show the cases")
    p.add_argument("--only", help="run a single case by name")
    p.add_argument("--json", action="store_true",
                   help="machine-readable results, for running this in CI")
    p.add_argument("--verbose", action="store_true",
                   help="show the raw counter values, not just the delta")
    p.add_argument("--injector", default=INJECTOR_HOST,
                   help="ssh target that sends the frames")
    p.add_argument("--iface", default=IFACE,
                   help="injector-side interface facing the DUT")
    p.add_argument("--count", type=int, default=COUNT,
                   help="frames per case")
    p.add_argument("--settle", type=float, default=SETTLE,
                   help="seconds to wait before re-reading counters")
    p.add_argument("--unknown-echo", default=UNKNOWN_ECHO,
                   help="address for the echo peer we do not serve")
    p.add_argument("--unknown-echo6", default=UNKNOWN_ECHO6,
                   help="v6 address for the echo peer we do not serve")
    args = p.parse_args()

    INJECTOR_HOST = args.injector
    IFACE = args.iface
    COUNT = args.count
    SETTLE = args.settle
    UNKNOWN_ECHO = args.unknown_echo
    UNKNOWN_ECHO6 = args.unknown_echo6

    if args.send:
        return send(json.loads(args.send))
    return orchestrate(args)


if __name__ == "__main__":
    sys.exit(main())
