#!/bin/sh
# Shared helpers for the host scripts (check-deps.sh, install-deps.sh).
#
# Source this file; it has no entry point of its own.

GO_MIN=${GO_MIN:-1.22}

OS=$(uname -s)
ARCH=$(uname -m)

if [ "$(id -u)" -eq 0 ]; then
	SUDO=${SUDO-}
else
	SUDO=${SUDO-sudo}
fi

# distro_family prints debian, rhel, suse, arch, alpine or unknown.
distro_family() {
	if [ ! -r /etc/os-release ]; then
		echo unknown
		return
	fi
	# shellcheck disable=SC1091
	. /etc/os-release
	case " ${ID:-} ${ID_LIKE:-} " in
	*debian* | *ubuntu*) echo debian ;;
	*rhel* | *fedora* | *centos* | *almalinux* | *rocky*) echo rhel ;;
	*suse* | *sles*) echo suse ;;
	*arch*) echo arch ;;
	*alpine*) echo alpine ;;
	*) echo unknown ;;
	esac
}
