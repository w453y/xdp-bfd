#!/bin/bash
# Peer-side snapshot of the six watched sessions.
V=${VTYSH:-/opt/frr-master/bin/vtysh}
echo "TOTAL $(sudo $V -c 'show bfd peers brief' | grep -c ' up ') up of $(sudo $V -c 'show bfd peers brief' | sed -n 's/^Session count: //p')"
sudo $V -c 'show bfd peers' | awk '
  /^\tpeer /              { p=$2; keep=0 }
  p ~ /^10\.66\.0\.1(24|25|22|10|18|11)$/ { keep=1 }
  keep && /ID:/          { if ($1=="ID:") id=$2; if ($1=="Remote") rid=$3 }
  keep && /Status:/      { st=$2 }
  keep && /Uptime:/      { ut=substr($0, index($0,$2)) }
  keep && /^$/           { if(p!=""){ printf "%-14s %-6s id=%-11s rid=%-11s up %s\n", p, st, id, rid, ut; p=""; keep=0 } }
'
sudo $V -c 'show bfd peers counters' | awk '
  /^\tpeer /                 { p=$2; keep=0; i=""; o=""; f=""; d="" }
  p ~ /^10\.66\.0\.1(24|25|22|10|18|11)$/ { keep=1 }
  keep && /Control packet input/  { i=$4 }
  keep && /Control packet output/ { o=$4 }
  keep && /Session down events/   { d=$4 }
  keep && /RX fail packet/        { f=$4 }
  keep && /^$/               { if(p!=""){ printf "%-14s in=%-8s out=%-8s rxfail=%-6s down_events=%s\n", p, i, o, f, d; p=""; keep=0 } }
'
