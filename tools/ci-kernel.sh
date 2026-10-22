#!/bin/bash
# Fetch a distro kernel for ci.yml's kernel job and print the image path for
# vng -r. Its modules go under /usr/lib/modules, where vng finds 9p; the image
# stays out of /boot, so the runner's bootloader never sees it.
# Usage: tools/ci-kernel.sh VERSION [IMAGE-DEB-URL [MODULES-DEB-URL]]
# With no URL the kernel comes from apt.
set -euo pipefail
VER="${1:?kernel version}"
IMG_URL="${2:-}"
MOD_URL="${3:-}"

if [ -z "$IMG_URL" ]; then
	if [ ! -f "/boot/vmlinuz-$VER" ] || [ ! -f "/usr/lib/modules/$VER/modules.dep" ]; then
		sudo apt-get update -qq >&2
		sudo apt-get install -y -qq --reinstall "linux-image-$VER" "linux-modules-$VER" >&2
	fi
	# Installed mode 600; vng reads it as the runner user.
	sudo chmod 644 "/boot/vmlinuz-$VER"
	echo "/boot/vmlinuz-$VER"
	exit 0
fi

CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/xdp-bfd-kernels"
IMG="$CACHE/vmlinuz-$VER"
# The image is cached last, once its modules are in place.
if [ -f "$IMG" ] && [ -f "/usr/lib/modules/$VER/modules.dep" ]; then
	echo "$IMG"
	exit 0
fi

mkdir -p "$CACHE"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# dpkg-deb -x into a scratch root: into / it would replace the /lib symlink.
for url in "$IMG_URL" $MOD_URL; do
	curl -sfL --retry 3 -o "$tmp/k.deb" "$url"
	dpkg-deb -x "$tmp/k.deb" "$tmp/root"
done
for d in lib/modules usr/lib/modules; do
	if [ -d "$tmp/root/$d/$VER" ]; then
		sudo rm -rf "/usr/lib/modules/$VER"
		sudo cp -a "$tmp/root/$d/$VER" "/usr/lib/modules/$VER"
	fi
done
test -d "/usr/lib/modules/$VER"
sudo depmod "$VER"
install -m 644 "$tmp/root/boot/vmlinuz-$VER" "$IMG.tmp"
mv "$IMG.tmp" "$IMG"
echo "$IMG"
