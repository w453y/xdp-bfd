#!/bin/bash
# One support-matrix arm: does this distro build it, load it, and run it.
#
#     tools/matrix/run-arm.sh <ssh-target> <arm-name> [object ...]
#
# Answers, per arm, in this order, because each one only matters if the
# previous passed:
#   does the native toolchain build the BPF object at all
#   does the engine build against this distro's gcc and libbpf-dev
#   do the host suites pass with nothing installed beyond that
#   does an object load on this kernel, and if not, what does the verifier
#     say in its own words
#   does a session come up over the isolated bridge, in which attach mode
#
# The object comes from the build host and the ENGINE is built on the arm.
# That split is the package's own shape: the object is architecture
# independent bytecode built once with a pinned clang, the engine is
# compiled per distro. It also keeps two unrelated failures apart. A
# build-host engine carried to an older distro can fail on glibc, or on
# libbpf's versioned symbols (LIBBPF_1.x) even when the soname matches,
# and either would read as "this kernel refuses us" and be wrong.
#
# More than one object may be given. Loading several on one kernel is how
# a row answers "are the verifier workarounds load-bearing here, or only
# at the floor".
#
# Output is one JSON object on stdout. Redirect it into docs/matrix/.
set -u

TARGET=${1:?ssh target, e.g. matrix@192.168.11.201}
ARM=${2:?arm name, e.g. m1c-debian12-backports}
shift 2
OBJECTS=("$@")
[ ${#OBJECTS[@]} -eq 0 ] && OBJECTS=(bfd_xdp.o)

SRC_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SSH="ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=15"
# /usr/sbin and /sbin are not on PATH for a non-login shell as a normal
# user on Debian, so ethtool and ip report "not found" while dpkg has them
# installed. Put them back rather than reporting the tool as absent.
R() { $SSH "$TARGET" "PATH=\$PATH:/usr/sbin:/sbin; $*"; }
say() { echo "[$ARM] $*" >&2; }

# ---------------------------------------------------------------- staging
say "staging source and $((${#OBJECTS[@]})) object(s)"
TAR=$(mktemp /tmp/xdpbfd-src-XXXX.tgz)
tar czf "$TAR" -C "$SRC_ROOT" --exclude=.git --exclude='*.o' --exclude=bfd_tx \
    --exclude=bfd_loader --exclude=__pycache__ --exclude='tests/unit/xdp_run' \
    --exclude='tests/unit/fsm_run' --exclude='tests/unit/dp_run' \
    --exclude='tests/unit/dp_fuzz' . 2>/dev/null
scp -q -o BatchMode=yes "$TAR" "$TARGET:/tmp/src.tgz" || { say "scp source failed"; exit 1; }
rm -f "$TAR"

i=0
for o in "${OBJECTS[@]}"; do
	scp -q -o BatchMode=yes "$o" "$TARGET:/tmp/obj$i.o" || { say "scp $o failed"; exit 1; }
	i=$((i + 1))
done

# Everything the probes need, before any probe runs. Installing a tool
# half way through once cost a row its ethtool fields.
say "installing toolchain"
R 'if command -v apt-get >/dev/null; then
     sudo apt-get update -qq >/dev/null 2>&1
     sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
       gcc make libbpf-dev clang llvm ethtool iproute2 pkg-config >/dev/null 2>&1
   elif command -v dnf >/dev/null; then
     sudo dnf install -y -q gcc make libbpf-devel clang llvm ethtool \
       iproute pkgconf-pkg-config >/dev/null 2>&1
   fi' >/dev/null 2>&1

R 'rm -rf ~/arm && mkdir -p ~/arm && cd ~/arm && tar xzf /tmp/src.tgz' || exit 1

# ------------------------------------------------------------------ facts
OSNAME=$(R '. /etc/os-release 2>/dev/null; printf "%s" "$PRETTY_NAME"')
KERNEL=$(R 'uname -r')
ARCH=$(R 'uname -m')
GCC=$(R 'gcc --version 2>/dev/null | head -1')
CLANG=$(R 'clang --version 2>/dev/null | head -1')
GLIBC=$(R 'ldd --version 2>/dev/null | head -1')
LIBBPF=$(R 'dpkg -l libbpf-dev 2>/dev/null | awk "/^ii/{print \$3; exit}" ||
             rpm -q --qf "%{VERSION}" libbpf-devel 2>/dev/null')
[ -n "$LIBBPF" ] || LIBBPF=$(R 'ls /usr/lib/*/libbpf.so.* 2>/dev/null | head -1 | sed "s@.*libbpf.so.@@"')
KCFG=$(R 'for f in /proc/config.gz /boot/config-$(uname -r); do
            [ -e "$f" ] || continue
            (zcat "$f" 2>/dev/null || cat "$f") | grep -E "^CONFIG_(BPF_JIT|BPF_JIT_ALWAYS_ON|DEBUG_INFO_BTF|XDP_SOCKETS)=" | tr "\n" ";"
            break
          done')

# ---------------------------------------------------- can it build itself
say "native clang on the BPF object"
NATIVE_OBJ=$(R 'cd ~/arm && make bfd_xdp.o >/tmp/c.log 2>&1 && echo ok || grep -m1 -E "error" /tmp/c.log | head -1')

say "engine against this distro's gcc and libbpf"
ENGINE=$(R 'cd ~/arm && cp /tmp/obj0.o bfd_xdp.o && touch bfd_xdp.o &&
            make bfd_tx bfd_loader >/tmp/b.log 2>&1 && echo ok ||
            (grep -m1 -E "error|No such file" /tmp/b.log | head -1)')

say "host suites"
# Not a bare grep for "error": every compile line contains -Werror, so
# that reports the command as the failure. Match what a failure says.
FAILPAT='FAIL |error:|Error [0-9]|No such file'
CHECKHOST=$(R "cd ~/arm && make check-host >/tmp/h.log 2>&1 && echo pass || (grep -m1 -E '$FAILPAT' /tmp/h.log|head -1)")
say "full suites"
CHECKALL=$(R "cd ~/arm && sudo make check >/tmp/f.log 2>&1 && echo pass || (grep -m1 -E '$FAILPAT' /tmp/f.log|head -1)")

# --------------------------------------------------------------- the load
IF=$(R 'ip -br link | awk "\$1!=\"lo\" && \$1!~/^(docker|veth)/ {print \$1}" | sed -n 2p')
R "sudo ip link set $IF up 2>/dev/null" >/dev/null 2>&1
DRIVER=$(R "command -v ethtool >/dev/null && ethtool -i $IF 2>/dev/null |
             awk -F': ' '/^driver:|^version:/{printf \"%s \", \$2}' || echo 'ethtool absent'")
QUEUES=$(R "command -v ethtool >/dev/null && ethtool -l $IF 2>/dev/null |
             awk '/^Combined:/{c=\$2} END{print c+0}' || echo 0")
[ -n "$IF" ] || IF="(no second interface)"

LOADS=""
i=0
for o in "${OBJECTS[@]}"; do
	say "loading $(basename "$o") on $KERNEL"
	# The object has to be in place before the loader runs, so that is
	# its own call rather than an argument to this one.
	R "cp /tmp/obj$i.o ~/arm/bfd_xdp.o" >/dev/null 2>&1
	v=$(R "cd ~/arm && sudo timeout 30 ./bfd_loader $IF >/tmp/l$i.log 2>&1;
	       if grep -q 'open/load failed' /tmp/l$i.log; then
	         grep -vE '^[0-9]+: \(|^;|^\$' /tmp/l$i.log |
	           grep -iE 'too large|invalid|min value|unknown func|not supported|Permission|Operation' |
	           head -1
	       else echo LOADS; fi")
	LOADS="$LOADS$(printf '{"object":"%s","result":"%s"}' "$(basename "$o")" "$(echo "$v" | tr -d '"' | head -c 200)"),"
	i=$((i + 1))
done
LOADS="[${LOADS%,}]"

# ------------------------------------------------------------- does it run
say "engine on the isolated bridge"
R "cp /tmp/obj0.o ~/arm/bfd_xdp.o" >/dev/null 2>&1
RUN=$(R "cd ~/arm && sudo ip addr add 10.99.0.1/24 dev $IF 2>/dev/null;
         sudo timeout 20 ./bfd_tx 10.99.0.1 10.99.0.2 --kernel-tx $IF 2>&1 |
           grep -m1 -E 'XDP attached|load failed|refusing' | head -1")

python3 - "$ARM" "$OSNAME" "$KERNEL" "$ARCH" "$GCC" "$CLANG" "$GLIBC" \
  "$LIBBPF" "$KCFG" "$NATIVE_OBJ" "$ENGINE" "$CHECKHOST" "$CHECKALL" \
  "$DRIVER" "$QUEUES" "$RUN" "$LOADS" <<'PY'
import json, sys
k = ["arm","os","kernel","arch","gcc","clang","glibc","libbpf_dev",
     "kernel_config","native_bpf_object","engine_build","check_host",
     "check_all","nic_driver","nic_queues","engine_run"]
d = dict(zip(k, sys.argv[1:17]))
d["object_load"] = json.loads(sys.argv[17])
print(json.dumps(d, indent=2))
PY
