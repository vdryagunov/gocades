#!/bin/sh
# Runs inside a CryptoPro test/environment image
# (docker/local/Dockerfile.* or docker/ghcr/Dockerfile.*).
#
# STAGE selects what to run (default: all — local one-shot):
#   build  — make build vet c-syntax
#   test   — unit tests + cades runtime load
#   smoke  — keygen, cert/PFX, make smoke [, cmd/pdfsign]
#   all    — build + test + smoke
#
# Environment:
#   CRYPTOPRO_TEST_PIN   PIN for the throwaway test container (default 12345678)
#   STRICT=1             fail if the signing checks cannot run
#   SKIP_PADES=1         skip smoke PAdES section and cmd/pdfsign (slim GHCR CI)
#
# Optional volumes:
#   /rngseed   CryptoPro CPSD source data (db1/, db2/)
#   /keycont   Pre-created key container files
#   /out       Writable directory for signed PDFs

set -eu

STAGE=${STAGE:-all}
PIN=${CRYPTOPRO_TEST_PIN:-12345678}
CONT='\\.\HDIMAGE\gocades-test'
CERT=/tmp/gocades-test.cer

BIN=$(dirname "$(ls /opt/cprocsp/bin/*/csptest | head -1)")
SBIN=$(dirname "$(ls /opt/cprocsp/sbin/*/cpconfig | head -1)")
CSPTEST="$BIN/csptest"
CERTMGR="$BIN/certmgr"
CPCONFIG="$SBIN/cpconfig"

log() { printf '\n== %s\n' "$*"; }
warn() { printf '!! %s\n' "$*" >&2; }

store_has_cert() {
	"$CERTMGR" -list -store "$1" 2>/dev/null | grep -q 'SHA1 Thumbprint'
}

want() {
	case "$STAGE" in
	all) return 0 ;;
	"$1") return 0 ;;
	*) return 1 ;;
	esac
}

cd /work
CACHE="GOPATH=/cache/gopath GOCACHE=/cache/gocache"

# Linux #cgo has -L for link time, but no rpath. GHCR images copy only
# /opt/cprocsp (not ld.so.conf.d from install.sh), so the runtime loader
# needs this for libxades/libcades/….
export LD_LIBRARY_PATH="/opt/cprocsp/lib/amd64:/opt/cprocsp/lib/aarch64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

log "CryptoPro license"
"$CPCONFIG" -license -view || true

if [ -d /rngseed/db1 ] || [ -d /rngseed/db2 ]; then
	log "installing CPSD source data from /rngseed"
	cp -a /rngseed/. /var/opt/cprocsp/dsrf/
fi

if [ -d /keycont ] && [ -n "$(ls -A /keycont 2>/dev/null)" ]; then
	log "installing key container material from /keycont"
	KEYDIR="/var/opt/cprocsp/keys/$(id -un)"
	mkdir -p "$KEYDIR"
	for f in /keycont/*; do
		[ -f "$f" ] || continue
		case "$f" in
		*.cer | *.crt | *.pem) : ;;
		*) cp -a "$f" "$KEYDIR/" ;;
		esac
	done
	for f in /keycont/*.cer /keycont/*.crt /keycont/*.pem; do
		[ -f "$f" ] || continue
		"$CERTMGR" -inst -file "$f" -store uMy -autocont 2>&1 | tail -3
	done
fi

# ---- build ----------------------------------------------------------------
if want build; then
	log "build, vet, C syntax"
	# shellcheck disable=SC2086
	make --no-print-directory $CACHE build vet c-syntax
fi

# ---- test -----------------------------------------------------------------
if want test; then
	log "unit tests"
	# Default go test timeout is 10m; a hung CryptGenKey (BIO RNG) would
	# burn the whole job. Fail faster and print which test is running.
	# shellcheck disable=SC2086
	GOPATH=/cache/gopath GOCACHE=/cache/gocache \
		go test -timeout 4m -count=1 -v ./...

	# Linked test binary proves the dynamic loader finds libcades/….
	log "cades runtime load check"
	GOCADES_TEST_MROOT=1 GOPATH=/cache/gopath GOCACHE=/cache/gocache \
		go test -timeout 2m -count=1 -v -run 'TestIsValidRevocation' .
fi

# ---- smoke ----------------------------------------------------------------
if ! want smoke; then
	log "done (STAGE=$STAGE)"
	exit 0
fi

signing=0

log "key generation"
if timeout 60 "$CSPTEST" -notime -keyset -newkeyset -container "$CONT" \
	-password "$PIN" </dev/null >/tmp/keygen.log 2>&1; then
	signing=1
	echo "key container created"
else
	warn "key generation is unavailable in this environment:"
	sed -n '1,10p' /tmp/keygen.log | sed 's/^/    /'
fi

if [ "$signing" -eq 1 ]; then
	log "self-signed certificate for the test container"
	if timeout 60 "$CSPTEST" -notime -keyset -fmakecert "$CERT" \
		-container "$CONT" -password "$PIN" </dev/null >>/tmp/keygen.log 2>&1 &&
		[ -s "$CERT" ]; then
		echo "certificate written to $CERT"
	else
		warn "could not create the self-signed certificate"
		signing=0
	fi
fi

if [ "$signing" -eq 1 ]; then
	log "installing the certificate into uMy with the key link"
	"$CERTMGR" -inst -file "$CERT" -store uMy -container "$CONT" \
		-pin "$PIN" >/tmp/certmgr-user.log 2>&1 || true
	if store_has_cert uMy; then
		echo "certificate installed in uMy"
	else
		warn "certificate import into uMy failed:"
		sed -n '1,6p' /tmp/certmgr-user.log | sed 's/^/    /'
		signing=0
	fi
fi

if [ "$signing" -eq 1 ]; then
	log "trusting the certificate for chain building"
	trusted=0
	for st in mRoot uRoot; do
		"$CERTMGR" -inst -file "$CERT" -store "$st" \
			>/tmp/certmgr-root.log 2>&1 || true
		if store_has_cert "$st"; then
			echo "trusted in $st"
			trusted=1
			break
		fi
	done
	if [ "$trusted" -eq 0 ]; then
		warn "could not install the test certificate as a trusted root:"
		sed -n '1,6p' /tmp/certmgr-root.log | sed 's/^/    /'
	fi
fi

PFX=/tmp/gocades-pfx.pfx
PFX_PASSWORD=pfx-$PIN
if [ "$signing" -eq 1 ]; then
	log "PFX for Store.ImportPFX"
	PFX_CONT='\\.\HDIMAGE\gocades-pfx'
	if timeout 60 "$CSPTEST" -notime -keyset -newkeyset -container "$PFX_CONT" \
		-password "$PIN" -exportable -keytype signature </dev/null >/tmp/pfx.log 2>&1 &&
		timeout 60 "$CSPTEST" -notime -keyset -fmakecert /tmp/gocades-pfx.cer \
			-container "$PFX_CONT" -password "$PIN" -keytype signature </dev/null >>/tmp/pfx.log 2>&1 &&
		"$CERTMGR" -inst -file /tmp/gocades-pfx.cer -store uMy -container "$PFX_CONT" \
			-pin "$PIN" -at_signature </dev/null >>/tmp/pfx.log 2>&1 &&
		printf '%s\n' "$PIN" | timeout 60 "$CERTMGR" -export -pfx -dest "$PFX" \
			-store uMy -dn CN=gocades-pfx -pin "$PFX_PASSWORD" -at_signature >>/tmp/pfx.log 2>&1 &&
		[ -s "$PFX" ]; then
		echo "PFX written to $PFX ($(wc -c <"$PFX") bytes)"
		"$CERTMGR" -inst -file /tmp/gocades-pfx.cer -store mRoot >>/tmp/pfx.log 2>&1 || true
	else
		warn "could not create a PFX:"
		sed -n '1,10p' /tmp/pfx.log | sed 's/^/    /'
		rm -f "$PFX"
		if [ "${STRICT:-0}" = "1" ]; then
			exit 1
		fi
	fi
	"$CERTMGR" -delete -store uMy -dn CN=gocades-pfx </dev/null >>/tmp/pfx.log 2>&1 || true
	"$CSPTEST" -notime -keyset -deletekeyset -container "$PFX_CONT" </dev/null >>/tmp/pfx.log 2>&1 || true
fi

log "smoke test"
if [ "$signing" -eq 1 ] && [ -s "$PFX" ]; then
	SMOKE_PIN="$PIN" SMOKE_PFX="$PFX" SMOKE_PFX_PASSWORD="$PFX_PASSWORD" \
		make --no-print-directory $CACHE smoke
elif [ "$signing" -eq 1 ]; then
	SMOKE_PIN="$PIN" make --no-print-directory $CACHE smoke
else
	make --no-print-directory $CACHE smoke
	warn "signing checks were skipped: the software RNG plugin could not"
	warn "create a key container in this environment"
	if [ "${STRICT:-0}" = "1" ]; then
		warn "STRICT=1: treating skipped signing checks as a failure"
		exit 1
	fi
fi

if [ "${SKIP_PADES:-0}" = "1" ]; then
	log "SKIP_PADES=1: skipping cmd/pdfsign (run locally: make verify-crypto)"
elif [ "$signing" -eq 1 ]; then
	log "cmd/pdfsign: sign a real document end to end"
	if CRYPTOPRO_PIN="$PIN" GOPATH=/cache/gopath GOCACHE=/cache/gocache go run ./cmd/pdfsign \
		-in cmd/pdfsign/testdata/sample.pdf -out /tmp/sample.signed.pdf \
		-reason "container verification" \
		-stamp -signer "gocades container test"; then
		ls -l /tmp/sample.signed.pdf
	else
		warn "cmd/pdfsign failed"
		if [ "${STRICT:-0}" = "1" ]; then
			exit 1
		fi
	fi

	log "cmd/pdfsign: xref-stream source, two signatures"
	if CRYPTOPRO_PIN="$PIN" GOPATH=/cache/gopath GOCACHE=/cache/gocache go run ./cmd/pdfsign \
		-in cmd/pdfsign/testdata/xref-stream.pdf -out /tmp/xref.signed.pdf \
		-stamp -signer "gocades container test" &&
		CRYPTOPRO_PIN="$PIN" GOPATH=/cache/gopath GOCACHE=/cache/gocache go run ./cmd/pdfsign \
			-in /tmp/xref.signed.pdf -out /tmp/xref.signed2.pdf; then
		if grep -a -q '^xref' /tmp/xref.signed2.pdf; then
			warn "the update over an xref-stream source wrote a classic xref table"
			if [ "${STRICT:-0}" = "1" ]; then
				exit 1
			fi
		fi
	else
		warn "cmd/pdfsign failed on the xref-stream source"
		if [ "${STRICT:-0}" = "1" ]; then
			exit 1
		fi
	fi

	if [ -d /out ] && [ -f /tmp/sample.signed.pdf ]; then
		log "cmd/pdfsign: second signature with Cyrillic text fields"
		CRYPTOPRO_PIN="$PIN" GOPATH=/cache/gopath GOCACHE=/cache/gocache go run ./cmd/pdfsign \
			-in /tmp/sample.signed.pdf -out /tmp/sample.cyrillic.pdf \
			-reason "Согласовано (финал) — проверка «кавычек» \\ и эмодзи 🙂" \
			-location "Москва, ул. Тверская, д. 1" \
			-contact "Иван Петров, +7 (495) 000-00-00" \
			-signer "Иванов Иван Иванович" \
			-field "Подпись руководителя"
		cp /tmp/sample.signed.pdf /tmp/sample.cyrillic.pdf /out/
		cp "$CERT" /out/gocades-test.cer
		chmod a+r /out/sample.signed.pdf /out/sample.cyrillic.pdf /out/gocades-test.cer
		ls -l /out
	fi
fi

log "done (STAGE=$STAGE)"
