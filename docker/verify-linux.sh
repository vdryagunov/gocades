#!/bin/sh
# Build and test the port inside a throwaway Linux container against the local
# CryptoPro packages. Nothing is installed on the host.
#
#   ./docker/verify-linux.sh debian       # debian:bookworm-slim + local .deb set
#   ./docker/verify-linux.sh almalinux    # almalinux:9 + local .rpm set
#
# Environment:
#   ARCH        container architecture (default: amd64)
#   GO_VERSION  Go toolchain to install (default: 1.25.2)
#   IMAGE       override the base image
#   PKGS        override the CryptoPro package set (.tgz archive or directory)
#   VENDOR_DIR  directory with the linux-*.tgz archives (default: docker/packages)
#   DOCKER      container CLI (default: docker)

set -eu

DISTRO=${1:-debian}
ARCH=${ARCH:-amd64}
GO_VERSION=${GO_VERSION:-1.25.2}
DOCKER=${DOCKER:-docker}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
# shellcheck source=docker/lib.sh
. "$SCRIPT_DIR/lib.sh"

usage() {
	echo "usage: $0 {debian|almalinux}   (ARCH=amd64|arm64)" >&2
	exit 2
}

IMAGE=$(base_image "$DISTRO") || usage
if [ -z "${PKGS:-}" ]; then
	PKGS=$(pkg_set "$DISTRO" "$ARCH") || usage
fi

if [ ! -e "$PKGS" ]; then
	echo "package set not found: $PKGS" >&2
	echo "download the linux-*.tgz sets from cryptopro.ru into ${VENDOR_DIR:-$ROOT/docker/packages}" >&2
	exit 2
fi

echo "distro   : $DISTRO"
echo "image    : $IMAGE (linux/$ARCH)"
echo "packages : $PKGS"
echo "source   : $ROOT"
echo

exec "$DOCKER" run --rm \
	--platform "linux/$ARCH" \
	-v "$ROOT:/work:ro" \
	-v "$PKGS:/packages:ro" \
	-v gocades-verify-gopath:/cache/gopath \
	-v gocades-verify-gocache:/cache/gocache \
	-e DISTRO="$DISTRO" \
	-e GO_VERSION="$GO_VERSION" \
	"$IMAGE" sh /work/docker/verify-linux-inner.sh
