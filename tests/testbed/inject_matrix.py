#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Injection matrix for the XDP BFD engine.

Sends crafted packets from an injector host and asserts on the engine's
kernel counters. Runs on the engine host; this file pipes itself to the
injector over ssh.

    ./tests/testbed/inject_matrix.py                 run everything
    ./tests/testbed/inject_matrix.py --list          show the cases
    ./tests/testbed/inject_matrix.py --only gtsm-v4  run one

Four cases need a phantom session, a configured peer nothing answers on,
and are skipped without one. Configure one per family:

    peer 10.66.0.200 multihop local-address <local v4>
     minimum-ttl 200
    peer fd66::200 multihop local-address <local v6>
     minimum-ttl 200
"""

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time

# Lab defaults, all overridable from the command line.
INJECTOR_HOST = "w453y@10.66.0.3"
IFACE = "ens19"
COUNT = 20
SETTLE = 0.6
UNKNOWN_ECHO = "10.66.0.250"
UNKNOWN_ECHO6 = "fd66::250"
# Configured peers nothing answers on, used as positive controls. Pinned by
# address, since a down multihop peer also has enable == 0.
PHANTOM4 = "10.66.0.200"
PHANTOM6 = "fd66::200"

MAC = None
# Fields an injected packet must not disturb on a live session.
WATCH = (
    "remote_disc",
    "detect_iv_us",
    "min_tx_us",
    "min_rx_us",
    "detect_mult",
    "peer_mac",
)
# An address pair with no session, for the deferred-GTSM drop. Must not collide
# with any configured address.
UNKNOWN_SRC = "10.66.0.240"
UNKNOWN_DST = "10.66.0.241"

_STAT = {}


class AtLeast:
    """A lower bound on a delta rather than an exact one, for global
    counters the live mesh also moves. not-self climbs on its own, since
    FRR sources its v6 echoes at the peer.
    """

    __slots__ = ("n",)

    def __init__(self, n):
        self.n = n

    def met(self, got):
        return got >= self.n

    def __str__(self):
        return ">=%+d" % self.n


def stat_names():
    """Slot numbering and names, read from the BFD_STAT_LIST X-macro in
    include/bfd_shared.h. Resolved on first use, not at import: on the
    injector this runs as `python3 -` with no repo checked out.
    """
    if _STAT:
        return _STAT

    # tests/testbed/ -> repo root.
    hdr = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
        "include",
        "bfd_shared.h",
    )
    # Strip comments first: an entry's comment may span lines.
    src = open(hdr).read()
    src = src[src.index("#define BFD_STAT_LIST") :]
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)

    out = {}
    for line in src.split("\n")[1:]:
        m = re.match(r'\s*X\(\w+,\s*"([^"]+)"\)', line)
        if m:
            out[len(out)] = m.group(1)
        if not line.rstrip().endswith("\\"):
            break
    if not out:
        sys.exit("no BFD_STAT_LIST entries found in %s" % hdr)
    _STAT.update(out)
    return _STAT


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def local_mac(iface):
    with open("/sys/class/net/%s/address" % iface) as f:
        return f.read().strip()


def echo_peer_addrs():
    """Peers of echo-active sessions, as the reflector sees them."""
    return [addr_of(e["key"]["b"]) for e in bpf_map("echo_peers")]


def bpf_map(name):
    out = sh("sudo bpftool map dump name %s" % name)
    try:
        data = json.loads(out)
    except ValueError:
        sys.exit("cannot read map %s; is the engine running?" % name)
    # With two engines loaded, `dump name` returns map objects rather than
    # entries; refuse rather than read the wrong engine.
    if data and isinstance(data[0], dict) and "id" in data[0] and "type" in data[0]:
        sys.exit(
            "more than one map named %s is loaded; another engine is "
            "running and this script cannot tell them apart" % name
        )
    return data


def counters():
    """Global stat slots by name, plus rx:<peer>:<local> per session. A key
    absent before and present after reads as 0 -> n.
    """
    names = stat_names()
    out = {
        names[e["key"]]: sum(c["value"] for c in e["values"])
        for e in bpf_map("bfd_stats")
        if e["key"] in names
    }
    for e in bpf_map("bfd_sessions"):
        peer = addr_of(e["key"]["peer"]["b"])[0]
        local = addr_of(e["key"]["local"]["b"])[0]
        out["rx:%s:%s" % (peer, local)] = e["value"]["rx_pkts"]
    return out


def stats():
    return {
        e["key"]: sum(c["value"] for c in e["values"]) for e in bpf_map("bfd_stats")
    }


def session_value(peer, local):
    """Full bfd_sessions value for one pair, or None if it has no state."""
    for e in bpf_map("bfd_sessions"):
        if (
            addr_of(e["key"]["peer"]["b"])[0] == peer
            and addr_of(e["key"]["local"]["b"])[0] == local
        ):
            return e["value"]
    return None


def rx_of(peer, local):
    """rx_pkts for one session, or None if it has no state yet."""
    v = session_value(peer, local)
    return None if v is None else v["rx_pkts"]


def session_states():
    """(peer, local) -> (alive, remote_disc) for every configured session,
    to catch collateral damage the counters cannot see.
    """
    out = {}
    for e in bpf_map("bfd_sessions"):
        k = (tuple(e["key"]["peer"]["b"]), tuple(e["key"]["local"]["b"]))
        v = e["value"]
        watched = {
            f: (tuple(v[f]) if isinstance(v.get(f), list) else v.get(f)) for f in WATCH
        }
        out[k] = (v["alive"], watched)
    return out


def addr_of(b):
    """Render a 16-byte key address, v4-mapped or v6."""
    if b[10] == 0xFF and b[11] == 0xFF:
        return ".".join(str(x) for x in b[12:16]), 4
    import ipaddress

    return str(ipaddress.ip_address(bytes(b))), 6


def sessions():
    """Configured sessions, as (peer, local, family, my_disc, min_ttl)."""
    out = []
    for e in bpf_map("tx_config"):
        peer, fam = addr_of(e["key"]["peer"]["b"])
        local, _ = addr_of(e["key"]["local"]["b"])
        out.append(
            {
                "peer": peer,
                "local": local,
                "family": fam,
                "my_disc": e["value"]["my_disc"],
                "min_ttl": e["value"].get("min_ttl", 255),
                "enable": e["value"]["enable"],
                "auth_type": e["value"].get("auth_type", 0),
            }
        )
    return out


def pick(sess):
    """Choose the sessions the cases need, or explain what is missing."""
    got = {}
    for s in sess:
        # Only sessions the fast path answers for: not in demand hold (enable)
        # and not authenticated, since every frame built here is
        # unauthenticated. Map order is not stable, so either would make
        # results depend on it.
        if (
            s["family"] == 4
            and s["min_ttl"] == 255
            and s["enable"]
            and not s["auth_type"]
            and "v4" not in got
        ):
            got["v4"] = s
        if (
            s["family"] == 6
            and s["min_ttl"] == 255
            and s["enable"]
            and not s["auth_type"]
            and "v6" not in got
        ):
            got["v6"] = s
        if (
            s["family"] == 4
            and s["min_ttl"] < 255
            and s["enable"]
            and not s["auth_type"]
            and "mh4" not in got
        ):
            got["mh4"] = s
        # A configured peer nothing answers on: its rx_pkts moves only when we
        # inject. Matched on address, since enable == 0 also matches a multihop
        # peer during bring-up.
        if s["family"] == 4 and s["peer"] == PHANTOM4 and "phantom" not in got:
            got["phantom"] = s
        if s["family"] == 6 and s["peer"] == PHANTOM6 and "phantom6" not in got:
            got["phantom6"] = s
        if (
            s["family"] == 6
            and s["min_ttl"] < 255
            and s["enable"]
            and not s["auth_type"]
            and "mh6" not in got
        ):
            got["mh6"] = s
    return got


def inject(spec):
    """Run the sending half of this script on the injector host."""
    cmd = [
        "ssh",
        "-o",
        "BatchMode=yes",
        INJECTOR_HOST,
        "sudo python3 - --send %s" % shlex.quote(json.dumps(spec)),
    ]
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


# Header rules checked before session lookup. Each entry breaks exactly one, so
# each case isolates its rule though all share the malformed counter.
MALFORMED = (
    ("bad-version", "BFD version other than 1", dict(vers=0)),
    ("zero-my-disc", "my_discriminator of zero is illegal", dict(mydisc=0)),
    ("zero-detect-mult", "detect multiplier of zero is illegal", dict(mult=0)),
    ("short-length", "length field below the 24-byte minimum", dict(blen=12)),
    (
        "length-overruns",
        "length field claiming more than the UDP payload " "holds",
        dict(blen=40),
    ),
    ("truncated-header", "frame ends before the BFD header does", dict(trunc=12)),
)


# Well-formed headers with a flag we cannot honour; dropped. The M bit counts
# as unsupported-flags, the A bit as auth-mismatch, since it is refused because
# this session has no key.
UNSUPPORTED = (
    ("auth-bit", "the A bit with no authentication configured", 0x04, "auth-mismatch"),
    ("mp-bit", "the M bit is reserved for multipoint", 0x01, "unsupported-flags"),
)


def unsupported_cases(sess, fam):
    """The unsupported-flag set for one family; both families exercise each
    parse path.
    """
    out = []
    for cname, cdesc, fl, counter in UNSUPPORTED:
        # ydisc naming no session with the peer Up, so a build without the flag
        # check drops at demux instead of touching a live session.
        spec = dict(
            family=fam,
            src=sess["peer"],
            dst=sess["local"],
            ttl=255,
            dport=3784,
            ydisc=0x11111111,
            state=3,
            flags=fl,
        )
        out.append(("%s-v%d" % (cname, fam), cdesc, spec, counter, COUNT))
    return out


def malformed_cases(sess, fam):
    """The malformed set for one family; both families exercise each parse
    path.
    """
    out = []
    for cname, cdesc, extra in MALFORMED:
        spec = dict(
            family=fam,
            src=sess["peer"],
            dst=sess["local"],
            ttl=255,
            dport=3784,
            ydisc=0,
            state=1,
        )
        spec.update(extra)
        out.append(("%s-v%d" % (cname, fam), cdesc, spec, "malformed", COUNT))
    return out


def phantom_cases(ph, fam):
    """Positive controls against a session nothing answers: nothing but the
    injector moves the phantom's rx_pkts.
    """
    rx = [("rx:%s:%s" % (ph["peer"], ph["local"]), COUNT)]
    base = dict(
        family=fam,
        src=ph["peer"],
        dst=ph["local"],
        ttl=ph["min_ttl"],
        dport=4784,
        ydisc=ph["my_disc"],
        state=1,
    )
    return [
        (
            "mhop-at-min-v%d" % fam,
            "TTL at the minimum reaches the session state update",
            dict(base),
            rx,
            None,
        ),
        (
            "long-frame-v%d" % fam,
            "trailing bytes past the BFD payload do not confuse the parser",
            dict(base, pad=200),
            rx,
            None,
        ),
    ]


def build_cases(got):
    """Each case: what to send, which counter moves, and by how much."""
    c = []

    if "v4" in got:
        s = got["v4"]
        c.append(
            (
                "gtsm-v4",
                "TTL 64 to a single-hop session is off-link",
                dict(
                    family=4,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=64,
                    dport=3784,
                    ydisc=0,
                    state=1,
                ),
                "rejected",
                COUNT,
            )
        )
        c.append(
            (
                "disc-mismatch",
                "your_disc naming no session of ours",
                dict(
                    family=4,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=255,
                    dport=3784,
                    ydisc=0x11111111,
                    state=3,
                ),
                "rejected",
                COUNT,
            )
        )
        c.append(
            (
                "ip-options",
                "single-hop BFD never carries IP options",
                dict(
                    family=4,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=255,
                    dport=3784,
                    ydisc=0,
                    state=1,
                    options=True,
                ),
                # Its own slot, not rejected: options are refused for
                # what the IP header is, not for anything in the BFD.
                [("ip-options", COUNT), ("rejected", 0)],
                None,
            )
        )
        c.append(
            (
                "frag-first",
                "a first fragment aimed at 3784 is dropped, "
                "not bounced back out with MF set",
                dict(
                    family=4,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=255,
                    dport=3784,
                    ydisc=0,
                    state=1,
                    mf=True,
                ),
                "rejected",
                COUNT,
            )
        )
        # Only meaningful with a multihop session configured, which makes
        # parse_l3 defer the TTL verdict.
        if any(k in got for k in ("mh4", "mh6", "phantom", "phantom6")):
            c.append(
                (
                    "gtsm-unconfigured-pair",
                    "a low-TTL packet naming an address pair we have no "
                    "session for dies in XDP even with multihop configured",
                    dict(
                        family=4,
                        src=UNKNOWN_SRC,
                        dst=UNKNOWN_DST,
                        ttl=64,
                        dport=3784,
                        ydisc=0,
                        state=1,
                        l2dst=MAC,
                    ),
                    "rejected",
                    COUNT,
                )
            )
        pf = session_value(s["peer"], s["local"])
        if pf:
            # Poll/Final (RFC 5880 s6.5). Everything but P is replayed from the
            # session's own state, so the collateral check holds; only the
            # reply proves the F bit.
            c.append(
                (
                    "poll-final",
                    "a packet with Poll set is answered " "with Final",
                    dict(
                        family=4,
                        src=s["peer"],
                        dst=s["local"],
                        ttl=255,
                        dport=3784,
                        ydisc=s["my_disc"],
                        state=pf["remote_state"],
                        mydisc=pf["remote_disc"],
                        mult=pf["detect_mult"],
                        mintx=pf["min_tx_us"],
                        minrx=pf["min_rx_us"],
                        minecho=pf.get("remote_min_echo_us", 0),
                        flags=0x20,
                        l2dst=MAC,
                        capture=True,
                    ),
                    [("cap:final", COUNT)],
                    None,
                )
            )

        c.extend(malformed_cases(s, 4))
        c.extend(unsupported_cases(s, 4))
        c.append(
            (
                "echo-not-self",
                "a 3785 packet that is not self-addressed " "is never reflected",
                dict(
                    family=4,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=255,
                    dport=3785,
                    ydisc=0,
                    state=1,
                    l2dst=MAC,
                    capture=True,
                ),
                [("not-self", AtLeast(COUNT)), ("cap:replies", 0)],
                None,
            )
        )

        c.append(
            (
                "echo-unknown-peer",
                "echo from a peer we do not serve",
                dict(
                    family=4,
                    src=UNKNOWN_ECHO,
                    dst=UNKNOWN_ECHO,
                    ttl=255,
                    dport=3785,
                    ydisc=0,
                    state=1,
                    l2dst=MAC,
                    capture=True,
                ),
                [("declined", COUNT), ("cap:replies", 0)],
                None,
            )
        )

    if "v6" in got:
        s = got["v6"]
        c.append(
            (
                "gtsm-v6",
                "hop_limit 64 to a single-hop v6 session",
                dict(
                    family=6,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=64,
                    dport=3784,
                    ydisc=0,
                    state=1,
                ),
                "rejected",
                COUNT,
            )
        )
        c.extend(malformed_cases(s, 6))
        c.extend(unsupported_cases(s, 6))
        c.append(
            (
                "disc-mismatch-v6",
                "your_disc naming no session of ours",
                dict(
                    family=6,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=255,
                    dport=3784,
                    ydisc=0x11111111,
                    state=3,
                ),
                "rejected",
                COUNT,
            )
        )
        # The v6 reflector is a separate helper, so its declined and not-self
        # branches need their own cases.
        c.append(
            (
                "echo-unknown-peer-v6",
                "echo from a v6 peer we do not " "serve",
                dict(
                    family=6,
                    src=UNKNOWN_ECHO6,
                    dst=UNKNOWN_ECHO6,
                    ttl=255,
                    dport=3785,
                    ydisc=0,
                    state=1,
                    l2dst=MAC,
                    capture=True,
                ),
                [("declined", COUNT), ("cap:replies", 0)],
                None,
            )
        )
        c.append(
            (
                "echo-not-self-v6",
                "a v6 3785 packet that is not " "self-addressed is never reflected",
                dict(
                    family=6,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=255,
                    dport=3785,
                    ydisc=0,
                    state=1,
                    l2dst=MAC,
                    capture=True,
                ),
                [("not-self", AtLeast(COUNT)), ("cap:replies", 0)],
                None,
            )
        )

    if "mh4" in got:
        s = got["mh4"]
        c.append(
            (
                "mhop-below-min",
                "TTL under the negotiated minimum",
                dict(
                    family=4,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=s["min_ttl"] - 10,
                    dport=4784,
                    ydisc=0,
                    state=1,
                ),
                "rejected",
                COUNT,
            )
        )
        if "v4" in got:
            t = got["v4"]
            c.append(
                (
                    "mhop-does-not-leak",
                    "low TTL at a single-hop session " "while multihop is live",
                    dict(
                        family=4,
                        src=t["peer"],
                        dst=t["local"],
                        ttl=s["min_ttl"],
                        dport=3784,
                        ydisc=0,
                        state=1,
                    ),
                    "rejected",
                    COUNT,
                )
            )

    if "mh6" in got:
        s = got["mh6"]
        c.append(
            (
                "mhop-below-min-v6",
                "hop_limit under the minimum, v6",
                dict(
                    family=6,
                    src=s["peer"],
                    dst=s["local"],
                    ttl=s["min_ttl"] - 10,
                    dport=4784,
                    ydisc=0,
                    state=1,
                ),
                "rejected",
                COUNT,
            )
        )

    # One case per family: the v4 and v6 reflectors are separate paths.
    seen_fams = set()
    for addr, fam in echo_peer_addrs():
        if fam in seen_fams:
            continue
        seen_fams.add(fam)
        # Judged by the capture alone: `reflected` is global and the mesh moves
        # it constantly. The capture counts only frames addressed to the
        # injector's MAC, and proves a correct frame left the NIC.
        c.append(
            (
                "echo-reflect-v%d" % fam,
                "echo from a peer of an echo-active session is returned",
                dict(
                    family=fam,
                    src=addr,
                    dst=addr,
                    ttl=255,
                    dport=3785,
                    ydisc=0,
                    state=1,
                    l2dst=MAC,
                    capture=True,
                ),
                [("cap:replies", COUNT)],
                None,
            )
        )
        # Same packet with the TTL wrong: echo-ttl must move, so the zero below
        # is not vacuous.
        c.append(
            (
                "echo-gtsm-v%d" % fam,
                "an echo arriving below TTL 255 is not reflected",
                dict(
                    family=fam,
                    src=addr,
                    dst=addr,
                    ttl=64,
                    dport=3785,
                    ydisc=0,
                    state=1,
                    l2dst=MAC,
                    capture=True,
                ),
                [("echo-ttl", COUNT), ("cap:replies", 0)],
                None,
            )
        )

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

    print(
        "sessions: %d configured, %d up, using %s"
        % (len(sess), len(live), ", ".join(sorted(got))),
        file=sys.stderr,
    )
    missing = {"v4", "v6", "mh4", "mh6"} - set(got)
    if missing:
        print("no session for %s, those cases are skipped" % ", ".join(sorted(missing)))
    for kind, addr in (("phantom", PHANTOM4), ("phantom6", PHANTOM6)):
        if kind not in got:
            # Say when a phantom does not resolve rather than silently dropping
            # its cases.
            print(
                "no configured session for %s %s, its cases are skipped" % (kind, addr),
                file=sys.stderr,
            )
    print()

    if args.only and not any(c[0] == args.only for c in cases):
        # A name matching nothing must not report success.
        sys.exit(
            "no case named %r. Available now: %s"
            % (args.only, ", ".join(c[0] for c in cases))
        )

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
        # Capture results ride in as pseudo-counters with nothing in `before`,
        # so the delta arithmetic is unchanged.
        after.update({"cap:%s" % k: v for k, v in cap.items()})

        checks = counter if isinstance(counter, list) else [(counter, expect)]
        results, ok, recorded = [], True, []
        for cname, cexp in checks:
            b, a = before.get(cname, 0), after.get(cname, 0)
            got = a - b
            bound = isinstance(cexp, AtLeast)
            exp_s = str(cexp) if bound else "%+d" % cexp
            recorded.append(
                {
                    "counter": cname,
                    "before": b,
                    "after": a,
                    "delta": got,
                    "expected": exp_s if bound else cexp,
                }
            )
            if args.verbose:
                results.append(
                    "%s %d -> %d = %+d (expected %s)" % (cname, b, a, got, exp_s)
                )
            else:
                results.append("%s %+d (expected %s)" % (cname, got, exp_s))
            ok = ok and (cexp.met(got) if bound else got == cexp)
        report["cases"].append(
            {"name": name, "ok": ok, "description": desc, "checks": recorded}
        )
        if not args.json:
            print(
                "%-22s %-4s %s   %s"
                % (name, "ok" if ok else "FAIL", ", ".join(results), desc)
            )
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
            report["collateral"].append({"peer": peer, "problem": "vanished"})
            if not args.json:
                print("%-22s FAIL session vanished during the run" % peer)
            disturbed += 1
            continue
        a2, w2 = sess_after[k]
        if a2 != 1:
            report["collateral"].append({"peer": peer, "problem": "went down"})
            if not args.json:
                print("%-22s FAIL session went down during the run" % peer)
            disturbed += 1
            continue
        for f in WATCH:
            if w2[f] != disc[f]:
                report["collateral"].append(
                    {
                        "peer": peer,
                        "problem": "%s changed" % f,
                        "before": disc[f],
                        "after": w2[f],
                    }
                )
                if not args.json:
                    print("%-22s FAIL %s changed %s -> %s" % (peer, f, disc[f], w2[f]))
                disturbed += 1
    if disturbed:
        failures += disturbed
    elif not args.json:
        print()
        print(
            "%d live session(s) undisturbed"
            % sum(1 for a, _ in sess_before.values() if a == 1)
        )

    report["failures"] = failures
    report["undisturbed"] = sum(1 for a, _ in sess_before.values() if a == 1)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print()
        print("%d case(s) failed" % failures if failures else "all cases passed")
    return 1 if failures else 0


def send(spec):
    """The injector half. Runs on the third host, needs root for scapy."""
    from scapy.all import Ether, IP, IPv6, UDP, Raw, sendp, get_if_hwaddr
    from scapy.all import IPOption_NOP

    def bfd(
        ydisc,
        state,
        vers=1,
        mult=3,
        blen=24,
        mydisc=0xCAFEBABE,
        mintx=300000,
        minrx=300000,
        minecho=0,
        flags=0,
    ):
        """Defaults build a well-formed header; each knob breaks one rule
        the engine checks before session lookup.
        """
        md = mydisc
        return bytes(
            [
                (vers << 5),
                ((state & 3) << 6) | flags,
                mult,
                blen,
                (md >> 24) & 0xFF,
                (md >> 16) & 0xFF,
                (md >> 8) & 0xFF,
                md & 0xFF,
                (ydisc >> 24) & 0xFF,
                (ydisc >> 16) & 0xFF,
                (ydisc >> 8) & 0xFF,
                ydisc & 0xFF,
                (mintx >> 24) & 0xFF,
                (mintx >> 16) & 0xFF,
                (mintx >> 8) & 0xFF,
                mintx & 0xFF,
                (minrx >> 24) & 0xFF,
                (minrx >> 16) & 0xFF,
                (minrx >> 8) & 0xFF,
                minrx & 0xFF,
                (minecho >> 24) & 0xFF,
                (minecho >> 16) & 0xFF,
                (minecho >> 8) & 0xFF,
                minecho & 0xFF,
            ]
        )

    # Set the source MAC explicitly: scapy takes it from the route, which may
    # name another interface, and the capture below matches on our own MAC.
    eth = Ether(src=get_if_hwaddr(spec["iface"]))
    if spec.get("l2dst"):
        eth.dst = spec["l2dst"]
    payload = bfd(
        spec["ydisc"],
        spec["state"],
        vers=spec.get("vers", 1),
        mult=spec.get("mult", 3),
        blen=spec.get("blen", 24),
        mydisc=spec.get("mydisc", 0xCAFEBABE),
        mintx=spec.get("mintx", 300000),
        minrx=spec.get("minrx", 300000),
        minecho=spec.get("minecho", 0),
        flags=spec.get("flags", 0),
    )
    if spec.get("trunc"):
        payload = payload[: spec["trunc"]]
    if spec.get("pad"):
        # Trailing bytes past the payload: udp_len grows, bfd->len stays 24,
        # and the packet must be accepted.
        payload = payload + bytes(spec["pad"])
    l4 = UDP(sport=49152, dport=spec["dport"]) / Raw(payload)

    if spec["family"] == 4:
        ip = IP(src=spec["src"], dst=spec["dst"], ttl=spec["ttl"])
        if spec.get("mf"):
            # Offset 0 with MF set: the fragment that could pass every check
            # and be bounced still marked MF.
            ip.flags = "MF"
        if spec.get("options"):
            # Four NOPs, one option word: ihl 6 and the UDP header moves. BFD
            # never carries options, so the engine drops these.
            ip.options = [IPOption_NOP() for _ in range(4)]
    else:
        ip = IPv6(src=spec["src"], dst=spec["dst"], hlim=spec["ttl"])

    if not spec.get("capture"):
        sendp(
            eth / ip / l4,
            iface=spec["iface"],
            count=spec["count"],
            inter=0.005,
            verbose=0,
        )
        return 0

    # Capture oracle: counters prove a count() call ran, not that a correct
    # frame left the NIC. Replies swap MACs, so they come back to us.
    from scapy.all import AsyncSniffer, get_if_hwaddr

    mymac = get_if_hwaddr(spec["iface"]).lower()
    sn = AsyncSniffer(
        iface=spec["iface"], store=True, filter="udp and (port 3784 or port 3785)"
    )
    sn.start()
    time.sleep(0.3)
    sendp(
        eth / ip / l4, iface=spec["iface"], count=spec["count"], inter=0.005, verbose=0
    )
    time.sleep(0.7)

    replies = final = 0
    for pkt in sn.stop():
        if not pkt.haslayer(Ether) or pkt[Ether].dst.lower() != mymac:
            continue
        raw = bytes(pkt[UDP].payload)
        if len(raw) < 2:
            continue
        replies += 1
        if raw[1] & 0x10:  # BFD_F_FINAL
            final += 1
    print(json.dumps({"capture": {"replies": replies, "final": final}}))
    return 0


def main():
    global INJECTOR_HOST, IFACE, COUNT, SETTLE, UNKNOWN_ECHO, UNKNOWN_ECHO6
    global PHANTOM4, PHANTOM6
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--send", help=argparse.SUPPRESS)
    p.add_argument("--list", action="store_true", help="show the cases")
    p.add_argument("--only", help="run a single case by name")
    p.add_argument(
        "--json",
        action="store_true",
        help="machine-readable results, for running this in CI",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="show the raw counter values, not just the delta",
    )
    p.add_argument(
        "--injector", default=INJECTOR_HOST, help="ssh target that sends the frames"
    )
    p.add_argument(
        "--iface", default=IFACE, help="injector-side interface facing the DUT"
    )
    p.add_argument("--count", type=int, default=COUNT, help="frames per case")
    p.add_argument(
        "--settle",
        type=float,
        default=SETTLE,
        help="seconds to wait before re-reading counters",
    )
    p.add_argument(
        "--unknown-echo",
        default=UNKNOWN_ECHO,
        help="address for the echo peer we do not serve",
    )
    p.add_argument(
        "--unknown-echo6",
        default=UNKNOWN_ECHO6,
        help="v6 address for the echo peer we do not serve",
    )
    p.add_argument(
        "--phantom", default=PHANTOM4, help="configured peer with no host behind it"
    )
    p.add_argument(
        "--phantom6", default=PHANTOM6, help="v6 configured peer with no host behind it"
    )
    args = p.parse_args()

    INJECTOR_HOST = args.injector
    IFACE = args.iface
    COUNT = args.count
    SETTLE = args.settle
    UNKNOWN_ECHO = args.unknown_echo
    UNKNOWN_ECHO6 = args.unknown_echo6
    PHANTOM4 = args.phantom
    PHANTOM6 = args.phantom6

    if args.send:
        return send(json.loads(args.send))
    return orchestrate(args)


if __name__ == "__main__":
    sys.exit(main())
