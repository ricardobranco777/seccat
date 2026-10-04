# SPDX-License-Identifier: BSD-2-Clause

# The version comes from git: v0.1.0 on a tagged commit, something like
# v0.1.0-3-g1a2b3c4 after it, with -dirty for uncommitted changes. It goes into the
# binary with -ldflags and reaches the shell as a variable, never pasted into a
# command, because it can come from a tag name.
VERSION := $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
export VERSION
LDFLAGS = -X main.version=$$VERSION

# Linux architectures in the release binaries.
RELEASE_ARCHES = amd64 arm64

.PHONY: build test fix check update-golden update-syscalls release version

build:
	go build -ldflags "$(LDFLAGS)" -o seccat .

test:
	go test -race ./...

fix:
	go fix ./...
	golangci-lint fmt

check:
	go mod tidy -diff
	go fix -diff ./...
	go vet ./...
	golangci-lint run
	go test -race ./...

update-golden:
	go test -run Golden -update ./...

update-syscalls:
	curl -sSfL -o third_party/libseccomp/syscalls.csv \
		https://raw.githubusercontent.com/seccomp/libseccomp/main/src/syscalls.csv
	@echo "now update the commit and date in third_party/libseccomp/README"

# release writes one binary per architecture and a SHA256SUMS file to dist/. The
# names carry no version, so that .../releases/latest/download/seccat-linux-amd64
# always works; the version is in the release and in seccat --version. The
# binaries are static (no cgo), with debug information stripped and build paths
# removed. Building the same commit with the same Go version gives the same files, so
# anyone can check a release against their own build.
release:
	@case "$$VERSION" in ''|*[!A-Za-z0-9._+-]*) \
		echo "the version must be letters, digits and . _ + - only, but is: $$VERSION" >&2; exit 1;; esac
	rm -rf dist
	mkdir dist
	@for arch in $(RELEASE_ARCHES); do \
		name=seccat-linux-$$arch; \
		echo $$name; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w $(LDFLAGS)" -o dist/$$name . || exit 1; \
	done
	cd dist && sha256sum seccat-* > SHA256SUMS

version:
	@echo "$$VERSION"
