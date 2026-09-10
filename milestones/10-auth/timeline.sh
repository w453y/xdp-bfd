#!/bin/bash
# State-change timeline per watched session. Prints a line whenever a side's
# transmitted State changes, so the whole flap reads top to bottom.
PCAP=$1
pairs="10.66.0.124:10.66.0.24:3784:sym-demand+auth
10.66.0.125:10.66.0.25:3784:engine-demands+noauth
10.66.0.122:10.66.0.22:4784:peer-demands+auth-mh
10.66.0.110:10.66.0.10:3784:async+meticulous
10.66.0.118:10.66.0.18:3784:async+auth+echo
10.66.0.111:10.66.0.11:3784:async+noauth"
for e in $pairs; do
  L=${e%%:*}; r=${e#*:}; R=${r%%:*}; r=${r#*:}; P=${r%%:*}; N=${r#*:}
  echo "=== $N   engine=$L peer=$R ==="
  tshark -r $PCAP -Y "ip.addr==$L && ip.addr==$R && udp.port==$P" \
    -T fields -e frame.time_relative -e ip.src -e bfd.sta \
    -e bfd.my_discriminator -e bfd.your_discriminator 2>/dev/null |
  awk -v L=$L '
    function nm(s){return s=="0x00"?"AdminDown":s=="0x01"?"Down":s=="0x02"?"Init":"Up"}
    { who = ($2==L) ? "engine" : "peer  "
      key = who" "$3
      if (key != last[who]) {
        printf "  %9.4f  %s -> %-9s my=%-10s your=%s\n", $1, who, nm($3), $4, $5
        last[who] = key
      }
    }'
done
