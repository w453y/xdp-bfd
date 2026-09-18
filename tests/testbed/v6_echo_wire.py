#!/usr/bin/env python3
"""The IPv6 echo originator, end to end on the wire.

A self-addressed v6 echo comes back at hop limit 254 exactly as a v4 one
does, provided the neighbour has ipv6 forwarding on. That sysctl is the
only difference between the two arms below.

This drives the whole path and asserts on the wire rather than on the
engine's own counters. Two arms against one config, changing only the
neighbour's sysctl:

  peer forwarding off   frames sent, none returned          negative arm
  peer forwarding on    frames sent, all returned, RTT set

Three properties, in the order they matter:

  1. Every outbound frame carries a valid UDP checksum, which is mandatory
     in v6 and is folded over a 40-byte pseudo-header rather than v4's 12.
     The oracle is tcpdump's own [udp sum ok], computed independently of
     echo_build_v6 - recomputing the fold here would only prove the test
     agrees with itself.
  2. Every returned frame's payload is byte-identical to one we sent. A
     count of frames at hop limit 254 would pass on any 254 frame that
     happened to be on the bridge; the payload match is what ties the
     return to the transmission.
  3. The engine demuxes them: echo rx climbs and rtt_last_us is non-zero,
     which only happens on a nonce match in ktx_poll_map.

Needs: passwordless sudo locally, key-based ssh to the peer and to the
hypervisor, and a v6 mesh session in Up. Writes no config permanently -
no write memory, so a botched revert lasts until the next frrinit reload.
"""
import argparse
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import time

PAIR = re.compile(r"(\S+)\.3785 > (\S+)\.3785")
HLIM = re.compile(r"hlim (\d+)")
HEX = re.compile(r"^\s+0x[0-9a-f]+:\s+(.*)$")

args = None


def sh(cmd, capture=True):
    r = subprocess.run(cmd, shell=True, text=True,
                       stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                       stderr=subprocess.PIPE if capture else subprocess.DEVNULL)
    return (r.stdout or "").strip()


def rsh(host, cmd, capture=True):
    """Quote with shlex, not json.dumps: the remote shell has to be the one
    that expands $!, and json's double quotes let the local shell do it
    first - which returns an empty pid and looks like tcpdump failing."""
    return sh("ssh -o BatchMode=yes %s %s" % (host, shlex.quote(cmd)), capture)


def vtysh_config(lines):
    """One heredoc, not repeated -c flags: each -c is its own transaction."""
    body = "configure terminal\nbfd\n" + "\n".join(lines) + "\n"
    subprocess.run("sudo " + args.vtysh, shell=True, input=body, text=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def check_fresh():
    """The process under test must be the binary that was built.

    make replaces the file rather than writing through it, so an engine
    started before the build has /proc/<pid>/exe reading (deleted). An
    empty capture from a stale binary looks exactly like a broken frame
    builder - that misreading cost a full run when this was written.
    """
    pid = sh("pgrep -x bfd_tx")
    if not pid.isdigit():
        sys.exit("no bfd_tx running")
    exe = sh("sudo readlink /proc/%s/exe" % pid)
    if exe.endswith("(deleted)"):
        sys.exit("running bfd_tx is a DELETED binary: rebuilt but not "
                 "restarted. Run ~/mode_b_opt.sh first.")
    elapsed = sh("ps -o etimes= -p %s" % pid)
    if not elapsed.isdigit():
        sys.exit("cannot read the engine's start time")
    started = time.time() - int(elapsed)
    built = os.stat(args.binary).st_mtime
    if started < built:
        sys.exit("running bfd_tx started %.0fs before %s was built: restart it"
                 % (built - started, args.binary))
    print("engine pid %s is running the current binary" % pid)


def dump():
    """SIGUSR1 by pid. Never pkill -f: it matches sudo and ssh wrappers,
    and SIGUSR1's default disposition kills them."""
    pid = sh("pgrep -x bfd_tx")
    if not pid.isdigit():
        sys.exit("no bfd_tx running")
    sh("sudo rm -f %s %s.tmp" % (args.snap, args.snap))
    sh("sudo kill -USR1 %s" % pid)
    for _ in range(50):
        time.sleep(0.1)
        try:
            return json.load(open(args.snap))
        except Exception:
            pass
    sys.exit("no stats snapshot after SIGUSR1")


def find_session(snap, peer):
    want = ipaddress.ip_address(peer)
    for s in snap["sessions"]:
        try:
            if ipaddress.ip_address(s["peer"]) == want:
                return s
        except ValueError:
            continue
    return None


def parse_pcap(path):
    """One record per tcpdump line naming IP6, with the hex continuation
    folded in. Splitting the output on a marker does not work: every record
    is prefixed with a timestamp, so nothing starts a line with IP6 and the
    whole capture collapses into a single block."""
    out = subprocess.run("tcpdump -nvr %s" % path, shell=True, text=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL).stdout
    pkts, cur = [], None
    for line in out.splitlines():
        m = HEX.match(line)
        if m and cur is not None:
            cur["hex"] += m.group(1).replace(" ", "")
            continue
        if "IP6" not in line:
            continue
        p, h = PAIR.search(line), HLIM.search(line)
        if not p or not h:
            cur = None
            continue
        cur = {"src": p.group(1), "dst": p.group(2), "hlim": int(h.group(1)),
               "sumok": "udp sum ok" in line, "hex": ""}
        pkts.append(cur)
    return pkts


def arm(name, local, peer, fwd, outdir):
    path = os.path.join(outdir, "v6echo-%s.pcap" % name)
    remote = "/tmp/v6echo-%s.pcap" % name
    filt = "ip6 and udp port 3785 and host %s" % local

    rsh(args.peer_host, "sudo sysctl -qw net.ipv6.conf.all.forwarding=%s" % fwd)
    rsh(args.hv, "pkill -x tcpdump; rm -f %s" % remote)
    pid = rsh(args.hv,
              "nohup tcpdump -i %s -n -v -s 128 -w %s %s >/dev/null 2>&1 & echo $!"
              % (args.bridge, remote, shlex.quote(filt)))
    if not pid.isdigit():
        sys.exit("tcpdump pid on the hypervisor was %r" % pid)

    before = find_session(dump(), peer)
    time.sleep(args.secs)
    after = find_session(dump(), peer)

    rsh(args.hv, "kill %s" % pid)
    time.sleep(0.5)
    sh("scp -q %s:%s %s" % (args.hv, remote, path), capture=False)

    pkts = parse_pcap(path)
    tx = [p for p in pkts if p["src"] == p["dst"] and p["hlim"] == 255]
    rx = [p for p in pkts if p["src"] == p["dst"] and p["hlim"] == 254]
    other = len(pkts) - len(tx) - len(rx)
    sent = {p["hex"] for p in tx if p["hex"]}
    matched = sum(1 for p in rx if p["hex"] and p["hex"] in sent)
    sumok = sum(1 for p in tx if p["sumok"])

    e = after["echo"] if after else {}
    b = before["echo"] if before else {}
    print("\n--- %s (peer ipv6 forwarding=%s) ---" % (name, fwd))
    print("    records parsed: %d" % len(pkts))
    print("    sent    (self-addressed, hlim 255): %d, [udp sum ok]: %d"
          % (len(tx), sumok))
    print("    returned(self-addressed, hlim 254): %d, payload matches a sent frame: %d"
          % (len(rx), matched))
    print("    other v6 3785 frames on this address: %d" % other)
    print("    engine: active=%s tx %s->%s rx %s->%s rtt_last=%sus alive=%s"
          % (e.get("active"), b.get("tx"), e.get("tx"), b.get("rx"), e.get("rx"),
             e.get("rtt_last_us"), e.get("alive")))
    return {"tx": len(tx), "sumok": sumok, "rx": len(rx), "matched": matched,
            "echo": e, "pcap": path}


def main():
    global args
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--peer-host", default="w453y@10.66.0.2")
    ap.add_argument("--hv", default="root@192.168.11.191")
    ap.add_argument("--bridge", default="vmbr3")
    ap.add_argument("--secs", type=int, default=15)
    ap.add_argument("--interval-ms", type=int, default=50)
    ap.add_argument("--vtysh", default="/opt/frr-master/bin/vtysh")
    ap.add_argument("--binary", default=os.path.expanduser("~/xdp-bfd/bfd_tx"))
    ap.add_argument("--snap", default="/tmp/bfd_tx_stats.json")
    ap.add_argument("--outdir", default="/tmp")
    args = ap.parse_args()

    check_fresh()

    line = sh("sudo %s -c 'show running-config' | grep -E '^ peer fd66::10:' | head -1"
              % args.vtysh)
    if not line.strip():
        sys.exit("no v6 mesh peer in running-config")
    m = re.search(r"peer (\S+) local-address (\S+)", line)
    if not m:
        sys.exit("could not read peer and local out of: %s" % line.strip())
    peer, local = m.group(1), m.group(2)
    # Copied verbatim rather than reconstructed: a peer line that does not
    # match an existing one creates a new peer, which is then refused at the
    # 64 cap with no error anywhere.
    print("peer line: %s" % line.strip())

    s = find_session(dump(), peer)
    if not s or s["state"] != "Up":
        sys.exit("that session is not Up (%s)" % (s and s.get("state")))

    orig = rsh(args.peer_host, "sysctl -n net.ipv6.conf.all.forwarding")
    vtysh_config([line.rstrip(), "  echo-mode",
                  "  echo transmit-interval %d" % args.interval_ms])
    time.sleep(2)
    armed = find_session(dump(), peer)
    if not armed or not armed["echo"]["active"]:
        vtysh_config([line.rstrip(), "  no echo-mode"])
        sys.exit("echo did not arm (on=%s active=%s): nothing would transmit "
                 "and every wire count below would be vacuous"
                 % (armed and armed["echo"]["on"],
                    armed and armed["echo"]["active"]))
    print("echo armed: active=%s" % armed["echo"]["active"])

    try:
        a = arm("noforward", local, peer, "0", args.outdir)
        b = arm("forward", local, peer, "1", args.outdir)
    finally:
        vtysh_config([line.rstrip(), "  no echo-mode"])
        rsh(args.peer_host,
            "sudo sysctl -qw net.ipv6.conf.all.forwarding=%s" % orig)
        print("\nreverted: no echo-mode, peer forwarding back to %s" % orig)

    print("\n=== verdict ===")
    ok = True
    if a["tx"] == 0:
        print("FAIL nothing was transmitted; every other result is vacuous")
        return 1
    for name, r in (("noforward", a), ("forward", b)):
        if r["sumok"] != r["tx"]:
            print("FAIL %s: %d of %d outbound frames failed the checksum check"
                  % (name, r["tx"] - r["sumok"], r["tx"]))
            ok = False
        else:
            print("ok   %s: %d frames sent, all with a valid v6 UDP checksum"
                  % (name, r["tx"]))
    if a["rx"] != 0:
        print("FAIL negative arm: %d returns with the neighbour not forwarding"
              % a["rx"])
        ok = False
    else:
        print("ok   negative arm: no returns with forwarding off")
    if b["rx"] == 0 or b["matched"] != b["rx"]:
        print("FAIL forward arm: %d returns, %d matching a sent payload"
              % (b["rx"], b["matched"]))
        ok = False
    else:
        print("ok   forward arm: %d returns, every payload matching one we sent"
              % b["rx"])
    e = b["echo"]
    if not e.get("rx") or not e.get("rtt_last_us"):
        print("FAIL engine did not demux the returns: rx=%s rtt_last_us=%s"
              % (e.get("rx"), e.get("rtt_last_us")))
        ok = False
    else:
        print("ok   engine demuxed: rx=%s rtt_last=%sus alive=%s"
              % (e["rx"], e["rtt_last_us"], e["alive"]))
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


sys.exit(main())
