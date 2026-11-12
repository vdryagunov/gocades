#!/bin/sh
# Installs the build dependencies for the current OS: compiler, make and the
# certificates bundle. Go is reported but not installed.
#
#   ./scripts/install-deps.sh
#
# CryptoPro CSP (Linux) / CryptoPro ECP (macOS) is licensed vendor software.
# This script never installs it: it only prints the command to run.
#
# Environment:
#   SUDO=sudo|doas|""   privilege escalation (default: sudo unless root)
#   GO_MIN=1.22         minimum Go version
#
# Exit status: 0 on success, 2 on an unsupported platform or a usage error.

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/lib.sh
. "$SCRIPT_DIR/lib.sh"

install_deps() {
	printf '\nInstalling build dependencies for %s/%s\n' "$OS" "$ARCH"

	if [ "$OS" = "Darwin" ]; then
		if ! xcode-select -p >/dev/null 2>&1; then
			printf 'Xcode command line tools are missing. Run:\n\n'
			printf '    xcode-select --install\n\n'
			printf 'then re-run: make deps\n'
		fi
		if ! command -v go >/dev/null 2>&1; then
			printf 'Go is missing. Install it with one of:\n\n'
			printf '    brew install go\n'
			printf '    https://go.dev/dl/\n\n'
		fi
		printf '\nCryptoPro ECP is installed by its own .pkg:\n\n'
		printf '    installer -pkg cprocsp-*.pkg -target /\n\n'
		return 0
	fi

	if [ "$OS" != "Linux" ]; then
		echo "unsupported platform: $OS" >&2
		return 2
	fi

	family=$(distro_family)
	case "$family" in
	debian)
		printf 'Using apt-get\n'
		$SUDO apt-get update
		$SUDO apt-get install -y --no-install-recommends \
			gcc g++ libc6-dev make ca-certificates
		;;
	rhel)
		printf 'Using dnf/yum\n'
		if command -v dnf >/dev/null 2>&1; then
			pkg=dnf
		else
			pkg=yum
		fi
		$SUDO "$pkg" install -y gcc gcc-c++ glibc-devel make ca-certificates
		;;
	suse)
		printf 'Using zypper\n'
		$SUDO zypper install -y gcc gcc-c++ glibc-devel make ca-certificates
		;;
	arch)
		printf 'Using pacman\n'
		$SUDO pacman -S --needed --noconfirm base-devel
		;;
	alpine)
		printf 'Using apk\n'
		$SUDO apk add --no-cache gcc g++ musl-dev make ca-certificates
		printf '\nNOTE: CryptoPro ships glibc binaries; musl (Alpine) is not\n'
		printf 'a supported target for libcades. Use Debian or RHEL instead.\n'
		;;
	*)
		printf 'Unknown distribution. Install manually:\n'
		printf '  gcc/clang, libc6-dev or glibc-devel, make, Go >= %s\n' "$GO_MIN"
		;;
	esac

	if ! command -v go >/dev/null 2>&1; then
		printf '\nGo is still missing. Install Go >= %s from https://go.dev/dl/\n' "$GO_MIN"
	fi

	printf '\nCryptoPro CSP is licensed software and is not installed by this\n'
	printf 'script. From the unpacked vendor package set run:\n\n'
	printf '    sudo ./install.sh --yes kc1 lsb-cprocsp-devel cprocsp-pki-cades\n\n'
	printf 'Then verify everything with: make doctor\n'
}

usage() {
	cat <<'EOF'
usage: install-deps.sh

Installs the build dependencies for this OS (compiler, make, certificates).
Go is reported but not installed, and CryptoPro is never installed by this
script: it prints the vendor install.sh command instead.

environment:
  SUDO=sudo|doas|""   privilege escalation (default: sudo unless root)
  GO_MIN=1.22         minimum Go version
EOF
}

main() {
	case "${1:-}" in
	"") install_deps ;;
	-h | --help | help) usage ;;
	*)
		usage >&2
		exit 2
		;;
	esac
}

main "$@"
