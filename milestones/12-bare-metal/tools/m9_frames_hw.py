DUT_MAC = "68:05:ca:e7:95:64"
INJ_MAC = "68:05:ca:e7:8c:f6"
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


