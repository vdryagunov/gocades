# Docker images and container checks for gocades.
#
# From repo root:
#   make -C docker help
#   make -C docker verify-crypto STRICT=1
#   make -C docker ghcr-push-all VERSION=v1.0.1 GHCR_IMAGE=ghcr.io/<owner>/gocades-test
#
# Or from here: make verify-crypto / make ghcr-push-all ...

SHELL := /bin/sh
DOCKER ?= docker

ROOT := $(abspath ..)
HERE := $(CURDIR)

DISTRO  ?= debian
VERSION ?= v1.0.0
GHCR_IMAGE ?= ghcr.io/$(USER)/gocades-test
PUSH    ?= 0
STRICT  ?=
SKIP_PADES ?=
GO_VERSION ?= 1.25.2

# Default ARCH = host (amd64|arm64).
UNAME_M := $(shell uname -m)
ifeq ($(ARCH),)
  ifeq ($(UNAME_M),x86_64)
    ARCH := amd64
  else ifeq ($(UNAME_M),amd64)
    ARCH := amd64
  else ifeq ($(UNAME_M),arm64)
    ARCH := arm64
  else ifeq ($(UNAME_M),aarch64)
    ARCH := arm64
  else
    $(error unsupported host arch $(UNAME_M); set ARCH=amd64|arm64)
  endif
endif

LOCAL_IMAGE ?= gocades-crypto:$(DISTRO)-$(ARCH)

.PHONY: help
.PHONY: verify-linux verify-crypto local local-image
.PHONY: ghcr ghcr-all ghcr-push ghcr-push-all
.PHONY: print-vars

help:
	@echo "docker/ — local one-shot vs GHCR env images"
	@echo
	@echo "Local (context = module root, Dockerfile in local/):"
	@echo "  make local-image DISTRO=debian|almalinux [ARCH=amd64|arm64]"
	@echo "  make verify-crypto|local   # build + full smoke (incl. PAdES)"
	@echo "      STRICT=1 SKIP_PADES=1 COVERDIR=... RNGSEED=... KEYCONT=..."
	@echo "  make verify-linux DISTRO=debian|almalinux"
	@echo
	@echo "GHCR (context = docker/, Dockerfile in ghcr/; no Go in image):"
	@echo "  make ghcr                  # one variant: DISTRO + ARCH"
	@echo "  make ghcr-all              # debian/almalinux × amd64/arm64"
	@echo "  make ghcr-push / ghcr-push-all   # same + docker push"
	@echo "      VERSION=v1.0.1 GHCR_IMAGE=ghcr.io/<owner>/gocades-test"
	@echo
	@echo "Current: DISTRO=$(DISTRO) ARCH=$(ARCH) VERSION=$(VERSION)"
	@echo "         LOCAL_IMAGE=$(LOCAL_IMAGE)"
	@echo "         GHCR_IMAGE=$(GHCR_IMAGE) PUSH=$(PUSH)"

print-vars: help

# ---- local -----------------------------------------------------------------

## local-image: build local one-shot image only (CSP+Go+RNG+source)
local-image:
	BUILD_ONLY=1 ARCH=$(ARCH) IMAGE=$(LOCAL_IMAGE) GO_VERSION=$(GO_VERSION) \
		./verify-crypto.sh $(DISTRO)

## verify-crypto / local: build local image and run smoke (incl. PAdES unless SKIP_PADES=1)
verify-crypto local:
	ARCH=$(ARCH) IMAGE=$(LOCAL_IMAGE) GO_VERSION=$(GO_VERSION) \
	STRICT=$(STRICT) SKIP_PADES=$(SKIP_PADES) \
	COVERDIR="$(COVERDIR)" RNGSEED="$(RNGSEED)" KEYCONT="$(KEYCONT)" \
	OUT="$(OUT)" SMOKE_TSA="$(SMOKE_TSA)" GOGC="$(GOGC)" \
	CRYPTOPRO_TEST_PIN="$(CRYPTOPRO_TEST_PIN)" \
		./verify-crypto.sh $(DISTRO)

## verify-linux: throwaway container, install CSP from packages, build/test
verify-linux:
	ARCH=$(ARCH) GO_VERSION=$(GO_VERSION) ./verify-linux.sh $(DISTRO)

# ---- GHCR ------------------------------------------------------------------

## ghcr: build one GHCR env image (CSP+RNG, no Go)
ghcr:
	VERSION=$(VERSION) GHCR_IMAGE=$(GHCR_IMAGE) PUSH=$(PUSH) \
		./publish-ghcr.sh $(DISTRO) $(ARCH)

## ghcr-all: build all four GHCR env images
ghcr-all:
	VERSION=$(VERSION) GHCR_IMAGE=$(GHCR_IMAGE) PUSH=$(PUSH) \
		./publish-ghcr.sh all

## ghcr-push: build + push one variant
ghcr-push:
	$(MAKE) ghcr PUSH=1 DISTRO=$(DISTRO) ARCH=$(ARCH) \
		VERSION=$(VERSION) GHCR_IMAGE=$(GHCR_IMAGE)

## ghcr-push-all: build + push all four (also tags :VERSION and :latest on debian-amd64)
ghcr-push-all:
	$(MAKE) ghcr-all PUSH=1 VERSION=$(VERSION) GHCR_IMAGE=$(GHCR_IMAGE)
