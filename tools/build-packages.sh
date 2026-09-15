#!/bin/bash
# Build the xdp-bfd .deb (and .rpm where mock is available) for each
# target in clean containers. Each .deb target installs clang-21 from
# apt.llvm.org first: stock debian:12 has only clang-14, which builds the
# BPF object but produces one that will not load (verifier stack budget),
# so the object would ship broken and only fail at postinst --check.
#
# Usage: tools/build-packages.sh [deb|rpm|all]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Version from the git tag: strip a leading v, and turn a '-' from
# git describe into '~' so a pre-release orders before the release.
RAW="$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0)"
VERSION="$(echo "${RAW#v}" | sed 's/-/~/')"
echo "building xdp-bfd $VERSION (from $RAW)"

RUNTIME="${BFD_CONTAINER_RUNTIME:-podman}"
DIST="$REPO_ROOT/dist"
mkdir -p "$DIST"

DEB_TARGETS="debian:12 debian:13 ubuntu:24.04"
RPM_TARGETS="rockylinux:9"

build_deb() {
    local image="$1"
    local suite
    suite="$(echo "$image" | tr ':/' '__')"
    local out="$DIST/$suite"
    mkdir -p "$out"
    echo "=== .deb on $image -> $out ==="
    git archive --format=tar --prefix=xdp-bfd/ HEAD | \
      "$RUNTIME" run --rm -i -e VERSION="$VERSION" -v "$out":/out:Z "$image" bash -c '
        set -e
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends \
            build-essential libbpf-dev debhelper dpkg-dev devscripts \
            ca-certificates wget gnupg lsb-release software-properties-common \
            make gcc pkgconf llvm >/dev/null
        wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh
        chmod +x /tmp/llvm.sh
        /tmp/llvm.sh 21 >/tmp/llvm.log 2>&1 || { tail -20 /tmp/llvm.log; exit 1; }
        mkdir -p /src && tar -x -C /src
        cd /src/xdp-bfd
        dch --create --package xdp-bfd -v "${VERSION}-1" --distribution unstable \
            "Release ${VERSION}." 2>/dev/null || \
          dch -b -v "${VERSION}-1" --distribution unstable "Release ${VERSION}."
        dpkg-buildpackage -b -us -uc
        cp ../xdp-bfd_*.deb ../xdp-bfd-dbgsym_*.* /out/ 2>/dev/null || cp ../*.deb /out/
      '
    echo "--- $image artifacts ---"; ls -l "$out"
}

build_rpm() {
    local image="$1"
    echo "=== .rpm on $image (mock) ==="
    echo "rpm build via mock is not wired into this host yet; skipping $image" >&2
}

MODE="${1:-all}"
case "$MODE" in
  deb|all) for t in $DEB_TARGETS; do build_deb "$t"; done ;;
esac
case "$MODE" in
  rpm|all) for t in $RPM_TARGETS; do build_rpm "$t"; done ;;
esac
echo "done. artifacts under $DIST"
