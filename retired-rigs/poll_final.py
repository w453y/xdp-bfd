#!/usr/bin/env python3
"""Poll sequence termination, the half the injection matrix cannot reach.

bfd_xdp.c sets st->final_seq = cfg->poll_seq when a packet with F arrives
during a poll. That cannot be driven from the injector: cfg->poll is only
mirrored for a session in ST_UP (ktx_mirror, src/engine/ktx.c), so the phantom never polls,
and on a live session the real peer answers within a few milliseconds, so
an injected F could never be attributed.

So observe a real one instead. Raising transmit-interval makes bfd_tx bump
poll_seq and set polling (dp_handle_add, src/engine/dplane.c), the peer answers with F, the
kernel records final_seq, and bfd_tx ends the poll on the match in ktx_poll_map.
Every step is readable from the maps.

Run it separately: it changes session config, which the matrix must not
see mid-run.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import inject_matrix as im

IFACE = "ens19"
VTYSH = "/opt/frr-master/bin/vtysh"
RAISED_MS = 50          # transmit-interval is in ms
TIMEOUT = 20


def cfg_of(peer, local):
    for e in im.bpf_map("tx_config"):
        if (im.addr_of(e["key"]["peer"]["b"])[0] == peer and
                im.addr_of(e["key"]["local"]["b"])[0] == local):
            return e["value"]
    return None


def set_interval(peer, local, ms):
    script = ("configure terminal\nbfd\n"
              "peer %s local-address %s interface %s\n"
              "transmit-interval %d\nexit\nexit\nexit\n"
              % (peer, local, IFACE, ms))
    subprocess.run("sudo %s" % VTYSH, shell=True, input=script,
                   capture_output=True, text=True)


def main():
    sess = [s for s in im.sessions()
            if s["family"] == 4 and s["min_ttl"] == 255 and s["enable"]]
    if not sess:
        sys.exit("no live single-hop v4 session")
    s = sess[0]
    peer, local = s["peer"], s["local"]

    cfg = cfg_of(peer, local)
    st = im.session_value(peer, local)
    if not cfg or not st:
        sys.exit("session %s has no state yet" % peer)
    seq0, alive0 = cfg["poll_seq"], st["alive"]
    orig_ms = max(1, cfg["min_tx_us"] // 1000)
    print("session %s -> %s, poll_seq %d, final_seq %d, alive %d"
          % (local, peer, seq0, st["final_seq"], alive0))

    print("raising transmit-interval %dms -> %dms" % (orig_ms, RAISED_MS))
    set_interval(peer, local, RAISED_MS)

    seen_poll = False
    seq1 = final = None
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        cfg = cfg_of(peer, local)
        st = im.session_value(peer, local)
        if not cfg or not st:
            continue
        if cfg["poll"]:
            seen_poll = True
        if cfg["poll_seq"] != seq0:
            seq1 = cfg["poll_seq"]
            final = st["final_seq"]
            if final == seq1 and not cfg["poll"]:
                break
        if st["alive"] != 1:
            print("FAIL session went down during the poll")
            set_interval(peer, local, orig_ms)
            return 1

    print("restoring transmit-interval to %dms" % orig_ms)
    set_interval(peer, local, orig_ms)
    time.sleep(2)

    print()
    if seq1 is None:
        print("FAIL poll_seq never advanced; did the interval change apply?")
        return 1
    print("poll_seq %d -> %d%s" % (seq0, seq1,
                                   ", saw poll=1" if seen_poll else
                                   " (poll=1 too brief to observe)"))
    if final != seq1:
        print("FAIL final_seq stuck at %s, expected %d" % (final, seq1))
        return 1
    st = im.session_value(peer, local)
    if st["alive"] != 1:
        print("FAIL session is not alive after the poll")
        return 1
    print("final_seq caught up to %d and the poll ended; session stayed up"
          % seq1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
