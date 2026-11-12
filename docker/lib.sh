#!/bin/sh
# Shared helpers for the container verification launchers.
#
# Source this file; it has no entry point of its own. Callers must set ROOT to
# the module root before using pkg_set.

# host_arch prints the container architecture that matches this host.
host_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	arm64 | aarch64) echo arm64 ;;
	*) return 1 ;;
	esac
}

# pkg_set prints the CryptoPro package archive for a distro/arch pair.
# VENDOR_DIR overrides where the archives are looked up.
pkg_set() {
	vendor=${VENDOR_DIR:-$ROOT/docker/packages}
	case "$1/$2" in
	debian/amd64) echo "$vendor/linux-amd64_deb.tgz" ;;
	debian/arm64) echo "$vendor/linux-arm64_deb.tgz" ;;
	almalinux/amd64) echo "$vendor/linux-amd64.tgz" ;;
	almalinux/arm64) echo "$vendor/linux-arm64.tgz" ;;
	*) return 1 ;;
	esac
}

# base_image prints the base image for a distro. IMAGE overrides it.
base_image() {
	case "$1" in
	debian) echo "${IMAGE:-debian:bookworm-slim}" ;;
	almalinux) echo "${IMAGE:-almalinux:9}" ;;
	*) return 1 ;;
	esac
}
