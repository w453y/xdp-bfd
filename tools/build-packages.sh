#!/bin/bash
# Build the xdp-bfd .deb (and .rpm where mock is available) for each
# target in clean containers. Each .deb target installs clang-21 from
# apt.llvm.org first: stock debian/ubuntu clang is below the floor and
# builds a BPF object the kernel verifier rejects, so the object would
# ship broken and only fail at postinst --check.
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
RPM_TARGETS="fedora:42"

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
            ca-certificates wget gnupg lsb-release linux-libc-dev \
            make gcc pkgconf llvm >/dev/null
        # clang-21 from apt.llvm.org. The repo is set up by hand rather
        # than with llvm.sh, which needs software-properties-common: that
        # package is not in the base set on Debian trixie.
        . /etc/os-release
        wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
            | gpg --dearmor > /usr/share/keyrings/llvm.gpg
        echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-21 main" \
            > /etc/apt/sources.list.d/llvm.list
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends clang-21 >/dev/null
        mkdir -p /src && tar -x -C /src
        cd /src/xdp-bfd
        dch --create --package xdp-bfd -v "${VERSION}-1" --distribution unstable \
            "Release ${VERSION}." 2>/dev/null || \
          dch -b -v "${VERSION}-1" --distribution unstable "Release ${VERSION}."
        dpkg-buildpackage -b -us -uc
        cp ../xdp-bfd_*.deb /out/
        cp ../xdp-bfd-dbgsym_*.* /out/ 2>/dev/null || true
      '
    echo "--- $image artifacts ---"; ls -l "$out"
}

build_rpm() {
    local image="$1"
    local suite
    suite="$(echo "$image" | tr ':/' '__')"
    local out="$DIST/$suite"
    mkdir -p "$out"
    echo "=== .rpm on $image -> $out ==="
    local rpmver="${VERSION//\~/_}"
    git archive --format=tar.gz --prefix="xdp-bfd-${rpmver}/" HEAD -o "/tmp/xdp-bfd-${rpmver}.tar.gz"
    "$RUNTIME" run --rm -i -e RPMVER="$rpmver" \
        -v "$out":/out:Z -v "/tmp/xdp-bfd-${rpmver}.tar.gz":/src.tar.gz:Z "$image" bash -c '
        set -e
        dnf -y -q install rpm-build rpmdevtools make gcc clang llvm \
            libbpf-devel kernel-headers systemd-rpm-macros pkgconf-pkg-config >/dev/null
        rpmdev-setuptree
        cp /src.tar.gz ~/rpmbuild/SOURCES/xdp-bfd-${RPMVER}.tar.gz
        tar -xzf /src.tar.gz -C /tmp
        cp /tmp/xdp-bfd-${RPMVER}/rpm/xdp-bfd.spec ~/rpmbuild/SPECS/
        rpmbuild -bb --define "_version ${RPMVER}" ~/rpmbuild/SPECS/xdp-bfd.spec
        cp ~/rpmbuild/RPMS/*/*.rpm /out/
      '
    echo "--- $image artifacts ---"; ls -l "$out"
}

MODE="${1:-all}"
case "$MODE" in
  deb|all) for t in $DEB_TARGETS; do build_deb "$t"; done ;;
esac
case "$MODE" in
  rpm|all) for t in $RPM_TARGETS; do build_rpm "$t"; done ;;
esac
echo "done. artifacts under $DIST"
