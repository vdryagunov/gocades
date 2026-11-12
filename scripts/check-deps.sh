#!/bin/sh
# Reports whether this machine can build the port: Go, the C compiler, the
# CryptoPro SDK, the licence and the key containers.
#
#   ./scripts/check-deps.sh
#
# CryptoPro CSP (Linux) / CryptoPro ECP (macOS) is licensed vendor software.
# This script never installs it: it only verifies the SDK and tells you what to
# run. Install the vendor packages first, then:
#
#   sudo ./install.sh --yes kc1 lsb-cprocsp-devel cprocsp-pki-cades
#
# Environment:
#   GO_MIN=1.22   minimum Go version
#
# Exit status: 0 when the port can be built, 1 when a hard requirement is
# missing, 2 on a usage error.

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

pass=0
warn=0
fail=0

ok() { pass=$((pass + 1)); printf '  ok    %s\n' "$*"; }
miss() { fail=$((fail + 1)); printf '  MISS  %s\n' "$*"; }
note() { warn=$((warn + 1)); printf '  warn  %s\n' "$*"; }

section() { printf '\n%s\n' "$*"; }

check_compiler() {
	section "Toolchain"
	if command -v go >/dev/null 2>&1; then
		gover=$(go env GOVERSION 2>/dev/null | sed 's/^go//')
		if awk -v a="$gover" -v b="$GO_MIN" 'BEGIN {
			if (a == "") exit 1
			split(a, x, "."); split(b, y, ".")
			exit (x[1] > y[1] || (x[1] == y[1] && x[2] >= y[2])) ? 0 : 1
		}'; then
			ok "go $gover (>= $GO_MIN)"
		else
			miss "go $gover is too old, need >= $GO_MIN"
		fi
	else
		miss "go not found in PATH"
	fi

	if command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 ||
		command -v clang >/dev/null 2>&1; then
		ok "C compiler: $(command -v cc || command -v gcc || command -v clang)"
	else
		miss "no C compiler (gcc or clang); cgo cannot work"
	fi

	if command -v make >/dev/null 2>&1; then
		ok "make"
	else
		note "make not found (only needed for the Makefile targets)"
	fi

	if [ "$OS" = "Darwin" ] && ! xcode-select -p >/dev/null 2>&1; then
		note "Xcode command line tools missing: xcode-select --install"
	fi
}

# check_file prints ok/MISS for a path.
check_file() {
	if [ -e "$2" ]; then
		ok "$1: $2"
	else
		miss "$1: $2"
	fi
}

check_sdk() {
	section "CryptoPro SDK"
	if [ "$OS" = "Linux" ]; then
		case "$ARCH" in
		x86_64 | amd64) libdir=amd64 ;;
		aarch64 | arm64) libdir=aarch64 ;;
		*) libdir=$ARCH ;;
		esac
		inc=/opt/cprocsp/include
		lib=/opt/cprocsp/lib/$libdir

		check_file "CAdES headers" "$inc/pki/cades.h"
		check_file "XAdES headers" "$inc/pki/xades.h"
		check_file "CryptoAPI headers" "$inc/cpcsp/CSP_WinCrypt.h"
		check_file "libcades" "$lib/libcades.so"
		check_file "libxades" "$lib/libxades.so"
		check_file "libcapi20" "$lib/libcapi20.so"
		check_file "libcapi10" "$lib/libcapi10.so"
		check_file "librdrsup (GetLastError)" "$lib/librdrsup.so"
	elif [ "$OS" = "Darwin" ]; then
		app=/Applications/CryptoPro_ECP.app
		inc=$app/Contents/Resources/include/pki
		lib=$app/Contents/MacOS/lib

		check_file "CAdES headers" "$inc/cades.h"
		check_file "XAdES headers" "$inc/xades.h"
		check_file "CryptoAPI headers" "/opt/cprocsp/include/cpcsp/CSP_WinCrypt.h"
		check_file "libcades" "$lib/libcades.dylib"
		check_file "libxades" "$lib/libxades.dylib"
		check_file "libcapi20" "/opt/cprocsp/lib/libcapi20.dylib"
		check_file "libcapi10" "/opt/cprocsp/lib/libcapi10.dylib"
		check_file "librdrsup (GetLastError)" "/opt/cprocsp/lib/librdrsup.dylib"
	else
		miss "unsupported platform: $OS"
		return
	fi
}

check_license() {
	section "CryptoPro licence and keys"
	cpconfig=$(ls /opt/cprocsp/sbin/*/cpconfig /opt/cprocsp/sbin/cpconfig 2>/dev/null | head -1 || true)
	if [ -z "$cpconfig" ]; then
		note "cpconfig not found; cannot check the licence"
		return
	fi

	lic=$("$cpconfig" -license -view 2>/dev/null || true)
	if printf '%s' "$lic" | grep -qi 'expires'; then
		ok "licence: $(printf '%s' "$lic" | tr '\n' ' ' | sed 's/  */ /g')"
	elif printf '%s' "$lic" | grep -qi 'licen'; then
		ok "licence is installed"
	else
		note "no usable licence found (run: $cpconfig -license -view)"
	fi

	csptest=$(ls /opt/cprocsp/bin/*/csptest /opt/cprocsp/bin/csptest 2>/dev/null | head -1 || true)
	certmgr=$(ls /opt/cprocsp/bin/*/certmgr /opt/cprocsp/bin/certmgr 2>/dev/null | head -1 || true)
	if [ -z "$certmgr" ]; then
		note "certmgr not found; skipping the certificate check"
		return
	fi

	# The smoke test signs with a certificate from uMy that has a private key.
	certs=$("$certmgr" -list -store uMy 2>/dev/null | grep -c 'SHA1 Thumbprint' || true)
	if [ "${certs:-0}" -gt 0 ]; then
		ok "certificates in uMy: $certs"
	else
		note "uMy is empty (fine for building; the smoke test needs a certificate)"
	fi

	if [ -z "$csptest" ]; then
		return
	fi
	containers=$("$csptest" -list </dev/null 2>/dev/null | grep -c 'Container name' || true)
	if [ "${containers:-0}" -gt 0 ]; then
		ok "key containers visible: $containers"
	fi
}

usage() {
	cat <<'EOF'
usage: check-deps.sh

Reports Go, the C compiler, the CryptoPro SDK, the licence and the key
containers, then exits non-zero if something required is missing.

environment:
  GO_MIN=1.22   minimum Go version
EOF
}

main() {
	case "${1:-}" in
	"")
		check_compiler
		check_sdk
		check_license
		printf '\n%d ok, %d warning(s), %d missing\n' "$pass" "$warn" "$fail"
		if [ "$fail" -gt 0 ]; then
			printf '\nNot ready to build. See the MISS lines above.\n'
			exit 1
		fi
		printf '\nReady to build: make build\n'
		;;
	-h | --help | help)
		usage
		;;
	*)
		usage >&2
		exit 2
		;;
	esac
}

main "$@"
