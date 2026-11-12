#!/bin/sh
# Runs inside the container started by verify-linux.sh. Not meant for direct use.
#
# Expects:
#   DISTRO   debian | almalinux   (selects the package format)
#   GO_VERSION                    (Go toolchain to install)
# Mounts:
#   /work       the src tree (read-only)
#   /packages   the CryptoPro package set: the linux-*.tgz archive or an
#               already unpacked directory with the same install.sh and
#               packages (read-only)
#   /cache      persistent GOPATH and GOCACHE

set -eu

log() { printf '\n== %s\n' "$*"; }

# retry runs a command up to three times. Package mirrors are the one thing in
# this script that depends on an external network.
retry() {
	n=0
	until "$@"; do
		n=$((n + 1))
		if [ "$n" -ge 3 ]; then
			echo "failed after $n attempts: $*" >&2
			return 1
		fi
		sleep 5
	done
}

# ---- toolchain ----------------------------------------------------------

# apt_get relaxes TLS peer verification for the bootstrap. The slim image
# ships no CA bundle, so HTTPS cannot be verified until ca-certificates is
# installed; package authenticity still comes from apt's GPG signatures.
apt_get() {
	apt-get -o Acquire::https::Verify-Peer=false \
		-o Acquire::https::Verify-Host=false "$@"
}

if command -v apt-get >/dev/null 2>&1; then
	log "installing build dependencies (apt)"
	# Debian's default sources use plain HTTP; some networks only allow HTTPS.
	for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources; do
		[ -f "$f" ] || continue
		sed -i 's|http://deb.debian.org|https://deb.debian.org|g;
		        s|http://security.debian.org|https://security.debian.org|g' "$f"
	done
	retry apt_get update -qq
	retry apt_get install -y -qq --no-install-recommends \
		gcc g++ libc6-dev make curl ca-certificates xz-utils clang >/dev/null
elif command -v dnf >/dev/null 2>&1; then
	log "installing build dependencies (dnf)"
	# The stock AlmaLinux image resolves repositories through a metalink that
	# can return an unusable document behind some proxies. Fall back to the
	# canonical baseurls when the metadata cannot be fetched.
	if ! dnf -q makecache >/dev/null 2>&1; then
		log "metalink repositories unusable, switching to direct baseurls"
		rm -f /etc/yum.repos.d/almalinux*.repo
		cat >/etc/yum.repos.d/verify.repo <<EOF
[baseos]
name=baseos
baseurl=https://repo.almalinux.org/almalinux/9/BaseOS/\$basearch/os/
gpgcheck=0
enabled=1
[appstream]
name=appstream
baseurl=https://repo.almalinux.org/almalinux/9/AppStream/\$basearch/os/
gpgcheck=0
enabled=1
EOF
	fi
	retry dnf install -y -q gcc gcc-c++ glibc-devel make tar xz cpio clang >/dev/null
fi

# ---- Go -----------------------------------------------------------------

case "$(uname -m)" in
x86_64) goarch=amd64 ;;
aarch64 | arm64) goarch=arm64 ;;
*)
	echo "unsupported architecture: $(uname -m)" >&2
	exit 1
	;;
esac

if [ ! -x /usr/local/go/bin/go ]; then
	log "installing Go ${GO_VERSION} (linux-${goarch})"
	retry curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz" -o /tmp/go.tgz
	tar -C /usr/local -xzf /tmp/go.tgz
fi
export PATH=/usr/local/go/bin:$PATH
go version

# ---- CryptoPro headers and libraries ------------------------------------

# /packages is either the .tgz archive downloaded from cryptopro.ru or an
# already unpacked directory with the same install.sh and packages.
if [ -d /packages ]; then
	pkgdir=/packages
else
	log "unpacking the CryptoPro archive"
	pkgdir=/tmp/cryptopro-packages
	mkdir -p "$pkgdir"
	tar -xzf /packages -C "$pkgdir" --strip-components=1
fi

log "unpacking CryptoPro packages into /opt/cprocsp"
stage=/tmp/cryptopro-stage
mkdir -p "$stage" /opt
case "$DISTRO" in
debian)
	for f in "$pkgdir"/*.deb; do
		dpkg-deb -x "$f" "$stage"
	done
	;;
almalinux)
	for f in "$pkgdir"/*.rpm; do
		case "$f" in
		*.src.rpm) continue ;;
		esac
		rpm2cpio "$f" | cpio -idm --quiet -D "$stage"
	done
	;;
*)
	echo "unknown DISTRO: $DISTRO" >&2
	exit 1
	;;
esac

# Only the CryptoPro tree is copied out of the staging directory. Extracting
# vendor packages straight into / can overwrite system files, and under an
# emulated architecture that is a good way to break the container mid-run.
cp -a "$stage/opt/." /opt/
if [ -d "$stage/var/opt" ]; then
	mkdir -p /var/opt
	cp -a "$stage/var/opt/." /var/opt/
fi

export LD_LIBRARY_PATH="/opt/cprocsp/lib/amd64:/opt/cprocsp/lib/aarch64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# ---- build and test -----------------------------------------------------

cd /work

# Command-line assignments win over the := defaults in the Makefile, so the
# module caches stay in the mounted volume instead of inside the read-only tree.
CACHE_VARS="GOPATH=/cache/gopath GOCACHE=/cache/gocache"

log "make doctor"
# shellcheck disable=SC2086
make --no-print-directory $CACHE_VARS doctor || true

log "make build vet test"
# shellcheck disable=SC2086
make --no-print-directory $CACHE_VARS build vet test

# The cades test binary links libcades, libxades, libcapi20, libcapi10 and
# librdrsup, so running it also proves the dynamic loader resolves the vendor
# library chain. -count=1 skips the cached test result.
log "go test -count=1 . (runtime load check)"
GOPATH=/cache/gopath GOCACHE=/cache/gocache go test -count=1 .

log "make c-syntax"
make --no-print-directory c-syntax

log "PASS: Linux build, vet, tests and C syntax check"
