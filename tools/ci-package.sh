#!/bin/bash
# Build the package inside the current distro container, for the ci.yml package
# job. tools/build-packages.sh is the workstation form, which starts its own
# containers.
#
# Usage: tools/ci-package.sh deb|rpm
set -euo pipefail
cd "$(dirname "$0")/.."
KIND="${1:?deb or rpm}"
DIST="$PWD/dist"; mkdir -p "$DIST"

RAW="$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0)"
PKGVER="$(echo "${RAW#v}" | sed 's/-/~/')"
# Debian upstream versions must start with a digit; a tagless describe
# gives a bare commit hash, so turn that into a dev version.
case "$PKGVER" in [0-9]*) ;; *) PKGVER="0.0.0~git${PKGVER}" ;; esac
echo "building xdp-bfd $PKGVER ($KIND) from $RAW"

if [ "$KIND" = deb ]; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends \
		build-essential libbpf-dev debhelper dpkg-dev devscripts \
		ca-certificates wget gnupg lsb-release linux-libc-dev \
		make gcc pkgconf llvm lintian >/dev/null
	# clang-21 from apt.llvm.org, since some targets' stock clang is below
	# the floor of 17. Repo set up by hand; llvm.sh needs
	# software-properties-common.
	. /etc/os-release
	wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
		| gpg --dearmor > /usr/share/keyrings/llvm.gpg
	echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-21 main" \
		> /etc/apt/sources.list.d/llvm.list
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends clang-21 >/dev/null

	# Sign as the maintainer: in a container DEBEMAIL defaults to
	# root@<container id>, which lintian rejects.
	export DEBFULLNAME="Abdul Wasey"
	export DEBEMAIL="w453y.me@gmail.com"
	dch --create --package xdp-bfd -v "${PKGVER}-1" --distribution unstable \
		"CI build ${PKGVER}." 2>/dev/null || \
	  dch -b -v "${PKGVER}-1" --distribution unstable "CI build ${PKGVER}."
	dpkg-buildpackage -b -us -uc
	cp ../xdp-bfd_*.deb "$DIST"/
	echo "=== lintian (informational) ==="
	lintian ../xdp-bfd_*.deb || true
	ls -l "$DIST"

elif [ "$KIND" = rpm ]; then
	dnf -y -q install rpm-build rpmdevtools make gcc clang llvm \
		libbpf-devel kernel-headers systemd-rpm-macros \
		pkgconf-pkg-config rpmlint git >/dev/null
	rpmver="${PKGVER//\~/_}"
	rpmdev-setuptree
	git archive --format=tar.gz --prefix="xdp-bfd-${rpmver}/" HEAD \
		-o ~/rpmbuild/SOURCES/xdp-bfd-${rpmver}.tar.gz
	cp rpm/xdp-bfd.spec ~/rpmbuild/SPECS/
	rpmbuild -bb --define "_version ${rpmver}" ~/rpmbuild/SPECS/xdp-bfd.spec
	cp ~/rpmbuild/RPMS/*/*.rpm "$DIST"/
	echo "=== rpmlint (informational) ==="
	rpmlint "$DIST"/*.rpm || true
	ls -l "$DIST"
else
	echo "unknown kind: $KIND" >&2; exit 2
fi
