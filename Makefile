# CryptoPro Go port — build, test, verify and package targets.
#
# Supported hosts: Linux and macOS with CryptoPro installed.
#   Linux  — /opt/cprocsp (headers and libs from cprocsp-*-cades / -devel)
#   macOS  — CryptoPro ECP app bundle for CAdES headers and dylibs
#
# Quick start:
#   make deps          # install build dependencies for this OS
#   make doctor        # verify toolchain, SDK, licence and keys
#   make build test
#   SMOKE_PIN=12345678 make smoke
#
# The PIN is read from the environment only, so it never shows up in `ps`.

SHELL := /bin/sh
GO    ?= go

ROOT := $(CURDIR)

# Go caches live in their usual locations (~/Library/Caches/go-build or
# ~/.cache/go-build, plus ~/go) so the source tree stays clean. Set
# GO_LOCAL_CACHE=1 when those are not writable, for example inside a sandbox
# or a build container.
ifeq ($(strip $(GO_LOCAL_CACHE)),1)
GOPATH  := $(ROOT)/.gopath
GOCACHE := $(ROOT)/.gocache
export GOPATH GOCACHE
endif

export CGO_ENABLED := 1

UNAME_S := $(shell uname -s)
VERSION ?= 0.1.0
PREFIX  ?= /usr/local

# ---- smoke options --------------------------------------------------------
SMOKE_ARGS :=
ifneq ($(strip $(THUMBPRINT)),)
SMOKE_ARGS += -thumbprint $(THUMBPRINT)
endif
ifneq ($(strip $(TSA)),)
SMOKE_ARGS += -tsa $(TSA)
endif
ifeq ($(strip $(VERBOSE)),1)
SMOKE_ARGS += -v
endif

# ---- CryptoPro SDK locations ---------------------------------------------
MACROOT := /Applications/CryptoPro_ECP.app

.PHONY: all build vet test fmt fmt-fix c-syntax smoke deps doctor check cover
.PHONY: binaries dist install gen-error-names verify-linux verify-crypto
.PHONY: c-syntax-Linux c-syntax-Darwin
.PHONY: clean help

all: build

## build: compile every package
build:
	$(GO) build ./...

## vet: run go vet
vet:
	$(GO) vet ./...

## test: run the unit tests that do not need a token
test:
	$(GO) test ./...

## fmt: fail when files are not gofmt'ed
fmt:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed in:"; gofmt -l .; exit 1; }

## fmt-fix: rewrite files with gofmt
fmt-fix:
	gofmt -w .

## c-syntax: compile the C layer against the real CryptoPro headers
c-syntax: c-syntax-$(UNAME_S)

# gcc keeps GHCR images free of clang/LLVM; behaviour matches -fsyntax-only.
c-syntax-Linux:
	gcc -fsyntax-only -std=c11 -Wall -Wextra -DUNIX -DSIZEOF_VOID_P=8 \
	  -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp \
	  -I/opt/cprocsp/include/pki -I/opt/cprocsp/include/pki/atl \
	  -I/opt/cprocsp/include/pki/cplib gocades.c

c-syntax-Darwin:
	clang -fsyntax-only -std=c11 -Wall -Wextra -DUNIX -DSIZEOF_VOID_P=8 \
	  -I$(MACROOT)/Contents/Resources/include/pki \
	  -I$(MACROOT)/Contents/Resources/include/pki/cplib \
	  -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp gocades.c

## deps: install the build dependencies for this OS
#
# CryptoPro itself is licensed vendor software and is not installed here;
# the script prints the exact install.sh invocation for the vendor packages.
deps:
	./scripts/install-deps.sh

## doctor: verify toolchain, CryptoPro SDK, licence and key containers
doctor:
	@./scripts/check-deps.sh

## smoke: run the port against the local CSP (read-only without SMOKE_PIN)
smoke: build
	@if [ "$$SMOKE_PIN_PROMPT" = "1" ]; then \
	  echo "note: SMOKE_PIN_PROMPT=1, the CSP will ask for the PIN in its window"; \
	elif [ -z "$$SMOKE_PIN" ]; then \
	  echo "note: SMOKE_PIN is not set, signing checks will be skipped"; \
	fi
	$(GO) run ./cmd/smoke $(SMOKE_ARGS)

## check: fmt + vet + test
check: fmt vet test

## cover: unit + integration coverage via go tool covdata
#
# Unit coverage lands in COVER_UNIT (default /tmp/cov-unit). Integration
# coverage requires a CryptoPro container image; set COVERDIR (default
# /tmp/cov-int) and run verify-crypto. Pass SKIP_INT=1 to measure unit only.
COVER_UNIT ?= /tmp/cov-unit
COVER_INT  ?= /tmp/cov-int
cover:
	@rm -rf "$(COVER_UNIT)" && mkdir -p "$(COVER_UNIT)"
	$(GO) test -count=1 -cover -coverpkg=./... ./... -args -test.gocoverdir="$(COVER_UNIT)"
	@if [ "$(SKIP_INT)" = "1" ]; then \
	  $(GO) tool covdata percent -i="$(COVER_UNIT)"; \
	else \
	  COVERDIR="$(COVER_INT)" $(MAKE) verify-crypto DISTRO="$(if $(DISTRO),$(DISTRO),debian)" STRICT="$(if $(STRICT),$(STRICT),1)"; \
	  $(GO) tool covdata percent -i="$(COVER_UNIT),$(COVER_INT)"; \
	  echo "text profile: $(GO) tool covdata textfmt -i=$(COVER_UNIT),$(COVER_INT) -o /tmp/cov.txt"; \
	fi

## verify-linux: build and test inside a Linux container (see docker/Makefile)
verify-linux:
	$(MAKE) -C docker verify-linux DISTRO=$(if $(DISTRO),$(DISTRO),debian) ARCH="$(ARCH)"

## verify-crypto: local CryptoPro image + smoke (see docker/Makefile)
verify-crypto:
	$(MAKE) -C docker verify-crypto DISTRO=$(if $(DISTRO),$(DISTRO),debian) \
		ARCH="$(ARCH)" STRICT="$(STRICT)" SKIP_PADES="$(SKIP_PADES)" \
		COVERDIR="$(COVERDIR)" RNGSEED="$(RNGSEED)" KEYCONT="$(KEYCONT)"

## publish-ghcr: delegate to docker/Makefile (ghcr-push-all or one variant)
publish-ghcr:
	@if [ "$(or $(TARGET),all)" = "all" ]; then \
		$(MAKE) -C docker ghcr-push-all VERSION="$(or $(VERSION),v1.0.0)" \
			GHCR_IMAGE="$(or $(GHCR_IMAGE),ghcr.io/$(USER)/gocades-test)"; \
	else \
		$(MAKE) -C docker ghcr-push DISTRO="$(or $(DISTRO),debian)" ARCH="$(or $(ARCH),amd64)" \
			VERSION="$(or $(VERSION),v1.0.0)" \
			GHCR_IMAGE="$(or $(GHCR_IMAGE),ghcr.io/$(USER)/gocades-test)"; \
	fi

## binaries: build the command-line binaries into bin/
binaries:
	@mkdir -p bin
	$(GO) build -o bin/smoke ./cmd/smoke
	$(GO) build -o bin/pdfsign ./cmd/pdfsign
	@ls -l bin

## dist: build a distributable source tarball into dist/
dist:
	@rm -rf dist/gocades-$(VERSION)
	@mkdir -p dist/gocades-$(VERSION)
	@tar -cf - \
	  --exclude='./.git' --exclude='./.gocache' --exclude='./.gopath' \
	  --exclude='./.verify-cache' --exclude='./bin' --exclude='./dist' \
	  --exclude='./docker/packages' --exclude='./.DS_Store' \
	  --exclude='./sample.signed.pdf' \
	  . | tar -C dist/gocades-$(VERSION) -xf -
	@tar -C dist -czf dist/gocades-$(VERSION).tar.gz gocades-$(VERSION)
	@rm -rf dist/gocades-$(VERSION)
	@ls -l dist/gocades-$(VERSION).tar.gz

## install: install the built binaries into PREFIX/bin (default /usr/local)
install: binaries
	@install -d "$(DESTDIR)$(PREFIX)/bin"
	@install -m 0755 bin/smoke "$(DESTDIR)$(PREFIX)/bin/gocades-smoke"
	@install -m 0755 bin/pdfsign "$(DESTDIR)$(PREFIX)/bin/gocades-pdfsign"
	@echo "installed into $(DESTDIR)$(PREFIX)/bin"

## gen-error-names: regenerate error_names.go from the CryptoPro headers
gen-error-names:
	./scripts/gen-error-names.sh > error_names.go
	@gofmt -w error_names.go

## clean: remove build artefacts (keeps the module cache)
clean:
	$(GO) clean ./...
	@rm -rf .tmpcheck .tmpdarwin bin dist .gocache .gopath

## help: list targets
help:
	@echo "targets:"
	@sed -n 's/^## \([a-z-]*\): \(.*\)/  \1  — \2/p' $(MAKEFILE_LIST)
	@echo
	@echo "misc:"
	@echo "  VERSION=$(VERSION)   version stamped into dist/gocades-<VERSION>.tar.gz"
	@echo "  PREFIX=$(PREFIX)   install prefix for make install"
	@echo "  GO_LOCAL_CACHE=1   keep the Go build cache in ./.gocache instead of the default location"
	@echo
	@echo "layout:"
	@echo "  ./                the library (package gocades: CAdES + CryptoAPI binding)"
	@echo "  cmd/smoke/        environment self-check (make smoke)"
	@echo "  cmd/pdfsign/      sign a PDF file, with an independent check (make binaries)"
	@echo "  internal/pdfsign/ pure-Go PAdES helper used by both commands"
	@echo "  internal/pdfcheck external PDF validators (pdfinfo, pdfsig)"
	@echo "  docker/Makefile    local + GHCR image targets (make -C docker help)"
	@echo "  docker/packages/   CryptoPro vendor archives for the containers"
	@echo
	@echo "smoke options:"
	@echo "  SMOKE_PIN=...     key PIN (enables signing, decryption, XMLDSig)"
	@echo "  SMOKE_PIN_PROMPT=1 the same checks, PIN entered in the CSP window (macOS GUI)"
	@echo "  SMOKE_TSA=url     TSA URL (adds the CAdES-T check)"
	@echo "  THUMBPRINT=hex    pick the signer certificate explicitly"
	@echo "  VERBOSE=1         print certificate details"
	@echo
	@echo "docker images (full help: make -C docker help):"
	@echo "  make verify-crypto STRICT=1 DISTRO=debian"
	@echo "  make -C docker local-image / ghcr-all / ghcr-push-all"
	@echo "  VERSION=v1.0.1 GHCR_IMAGE=ghcr.io/owner/gocades-test make -C docker ghcr-push-all"
	@echo
	@echo "deps/doctor options:"
	@echo "  SUDO=sudo|doas|''        privilege escalation for make deps"
	@echo "  GO_MIN=1.22              minimum Go version for make doctor"
