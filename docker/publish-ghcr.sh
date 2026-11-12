#!/bin/sh
# Build GHCR environment images (CSP + RNG, no Go, no source) and optionally push.
# Go is supplied in CI via actions/setup-go + bind-mount (see verify-crypto.yml).
#
# Build context is docker/ (packages/ + rng/ via bind mounts).
#
# One variant:
#   VERSION=v1.0.0 ./docker/publish-ghcr.sh debian amd64
#
# All four (debian/almalinux × amd64/arm64):
#   VERSION=v1.0.0 PUSH=1 GHCR_IMAGE=ghcr.io/<owner>/gocades-test \
#     ./docker/publish-ghcr.sh all
#
# Tags pushed for each variant:
#   gocades-test:v1.0.0-debian-amd64
#   gocades-test:debian-amd64
# Plus for debian/amd64 (CI default on ubuntu-latest):
#   gocades-test:v1.0.0
#   gocades-test:latest
#
# Package must be Private (CryptoPro license).

set -eu

DOCKER=${DOCKER:-docker}
VERSION=${VERSION:-v1.0.0}
GHCR_IMAGE=${GHCR_IMAGE:-ghcr.io/${GHCR_OWNER:-${USER}}/gocades-test}

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

usage() {
	echo "usage: $0 all" >&2
	echo "       $0 {debian|almalinux} {amd64|arm64}" >&2
	echo "env:   VERSION=v1.0.0 PUSH=1 GHCR_IMAGE=ghcr.io/<owner>/gocades-test" >&2
	exit 2
}

pkg_for() {
	case "$1/$2" in
	debian/amd64) echo "$SCRIPT_DIR/packages/linux-amd64_deb.tgz" ;;
	debian/arm64) echo "$SCRIPT_DIR/packages/linux-arm64_deb.tgz" ;;
	almalinux/amd64) echo "$SCRIPT_DIR/packages/linux-amd64.tgz" ;;
	almalinux/arm64) echo "$SCRIPT_DIR/packages/linux-arm64.tgz" ;;
	*) return 1 ;;
	esac
}

build_one() {
	distro=$1
	arch=$2
	dockerfile=$SCRIPT_DIR/ghcr/Dockerfile.$distro
	pkg=$(pkg_for "$distro" "$arch")

	if [ ! -f "$pkg" ]; then
		echo "missing vendor archive: $pkg" >&2
		return 1
	fi
	if [ ! -f "$dockerfile" ]; then
		echo "missing Dockerfile: $dockerfile" >&2
		return 1
	fi

	variant_tag=$VERSION-$distro-$arch
	floating_tag=$distro-$arch
	local_tag=gocades-test:$floating_tag

	echo
	echo "== $distro/$arch =="
	echo "dockerfile : docker/ghcr/Dockerfile.$distro"
	echo "tags       : $GHCR_IMAGE:$variant_tag"
	echo "             $GHCR_IMAGE:$floating_tag"
	if [ "$distro" = "debian" ] && [ "$arch" = "amd64" ]; then
		echo "             $GHCR_IMAGE:$VERSION"
		echo "             $GHCR_IMAGE:latest"
	fi
	echo

	set -- \
		--platform "linux/$arch" \
		-f "$dockerfile" \
		-t "$local_tag" \
		-t "$GHCR_IMAGE:$variant_tag" \
		-t "$GHCR_IMAGE:$floating_tag"

	if [ "$distro" = "debian" ] && [ "$arch" = "amd64" ]; then
		set -- "$@" -t "$GHCR_IMAGE:$VERSION" -t "$GHCR_IMAGE:latest"
	fi

	"$DOCKER" build "$@" "$SCRIPT_DIR"

	if [ "${PUSH:-0}" = "1" ]; then
		"$DOCKER" push "$GHCR_IMAGE:$variant_tag"
		"$DOCKER" push "$GHCR_IMAGE:$floating_tag"
		if [ "$distro" = "debian" ] && [ "$arch" = "amd64" ]; then
			"$DOCKER" push "$GHCR_IMAGE:$VERSION"
			"$DOCKER" push "$GHCR_IMAGE:latest"
		fi
		echo "pushed $distro/$arch"
	fi
}

if [ "${1:-}" = "all" ]; then
	echo "VERSION    : $VERSION"
	echo "GHCR_IMAGE : $GHCR_IMAGE"
	echo "PUSH       : ${PUSH:-0}"
	for distro in debian almalinux; do
		for arch in amd64 arm64; do
			build_one "$distro" "$arch"
		done
	done
	echo
	echo "done. CI default: CRYPTO_IMAGE=$GHCR_IMAGE:latest"
	echo "or pin:          CRYPTO_IMAGE=$GHCR_IMAGE:$VERSION"
	echo "or variant:      CRYPTO_IMAGE=$GHCR_IMAGE:$VERSION-debian-amd64"
	exit 0
fi

DISTRO=${1:-}
ARCH=${2:-}
case "$DISTRO" in
debian | almalinux) ;;
*) usage ;;
esac
case "$ARCH" in
amd64 | arm64) ;;
*) usage ;;
esac

echo "VERSION    : $VERSION"
echo "GHCR_IMAGE : $GHCR_IMAGE"
echo "PUSH       : ${PUSH:-0}"
build_one "$DISTRO" "$ARCH"
