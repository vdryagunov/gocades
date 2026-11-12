#!/bin/sh
# Local CryptoPro verification: build docker/local image and run smoke.
#
# Prefer: make -C docker verify-crypto|local-image|ghcr-push-all
#
#   ./docker/verify-crypto.sh debian
#   BUILD_ONLY=1 ./docker/verify-crypto.sh debian   # image only
#   STRICT=1 ARCH=arm64 ./docker/verify-crypto.sh debian
#
# Build context: module root. Dockerfile: docker/local/Dockerfile.$DISTRO
#
# For GHCR environment images: make -C docker ghcr-push-all

set -eu

DISTRO=${1:-debian}
DOCKER=${DOCKER:-docker}
GO_VERSION=${GO_VERSION:-1.25.2}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
# shellcheck source=docker/lib.sh
. "$SCRIPT_DIR/lib.sh"

usage() {
	echo "usage: $0 {debian|almalinux}   (ARCH=amd64|arm64)" >&2
	exit 2
}

if [ -z "${ARCH:-}" ]; then
	ARCH=$(host_arch) || {
		echo "unsupported host architecture: $(uname -m)" >&2
		exit 1
	}
fi

case "$DISTRO" in
debian | almalinux)
	DOCKERFILE=$SCRIPT_DIR/local/Dockerfile.$DISTRO
	;;
*) usage ;;
esac

IMAGE=${IMAGE:-gocades-crypto:$DISTRO-$ARCH}

if [ -z "${PKGS:-}" ]; then
	PKGS=$(pkg_set "$DISTRO" "$ARCH") || usage
fi

if [ ! -e "$PKGS" ]; then
	echo "CryptoPro package set not found: $PKGS" >&2
	echo "download the linux-*.tgz sets from cryptopro.ru into ${VENDOR_DIR:-$ROOT/docker/packages}" >&2
	exit 2
fi

case "$PKGS" in
"$ROOT"/*) ;;
*)
	echo "CryptoPro packages must be inside the build context ($ROOT)" >&2
	exit 2
	;;
esac

REL_PKGS=$(printf '%s' "$PKGS" | sed "s|^$ROOT/||")
CRYPTOPRO_PKG=${CRYPTOPRO_PKG:-$REL_PKGS}

echo "distro   : $DISTRO"
echo "arch     : $ARCH"
echo "packages : $CRYPTOPRO_PKG"
echo "dockerfile: docker/local/Dockerfile.$DISTRO"
echo "image    : $IMAGE"
echo

"$DOCKER" build --platform "linux/$ARCH" \
	--build-arg "GO_VERSION=$GO_VERSION" \
	--build-arg "CRYPTOPRO_PKG=$CRYPTOPRO_PKG" \
	-f "$DOCKERFILE" \
	-t "$IMAGE" \
	"$ROOT"

if [ "${BUILD_ONLY:-0}" = "1" ]; then
	echo "BUILD_ONLY=1: image ready: $IMAGE"
	exit 0
fi

set -- --rm --platform "linux/$ARCH"
set -- "$@" -v gocades-verify-gopath:/cache/gopath
set -- "$@" -v gocades-verify-gocache:/cache/gocache

if [ -n "${RNGSEED:-}" ]; then
	set -- "$@" -v "$RNGSEED:/rngseed:ro"
fi
if [ -n "${KEYCONT:-}" ]; then
	set -- "$@" -v "$KEYCONT:/keycont:ro"
fi
if [ -n "${CRYPTOPRO_TEST_PIN:-}" ]; then
	set -- "$@" -e "CRYPTOPRO_TEST_PIN=$CRYPTOPRO_TEST_PIN"
fi
if [ -n "${STRICT:-}" ]; then
	set -- "$@" -e "STRICT=$STRICT"
fi
if [ -n "${SKIP_PADES:-}" ]; then
	set -- "$@" -e "SKIP_PADES=$SKIP_PADES"
fi
if [ -n "${OUT:-}" ]; then
	mkdir -p "$OUT"
	set -- "$@" -v "$(cd "$OUT" && pwd):/out"
fi
if [ -n "${SMOKE_TSA:-}" ]; then
	set -- "$@" -e "SMOKE_TSA=$SMOKE_TSA"
fi
if [ -n "${GOGC:-}" ]; then
	set -- "$@" -e "GOGC=$GOGC"
fi
if [ -n "${COVERDIR:-}" ]; then
	mkdir -p "$COVERDIR"
	set -- "$@" -v "$(cd "$COVERDIR" && pwd):/cover"
	set -- "$@" -e "GOFLAGS=-cover -coverpkg=github.com/vdryagunov/gocades/..."
	set -- "$@" -e "GOCOVERDIR=/cover"
fi

echo
exec "$DOCKER" run "$@" "$IMAGE"
