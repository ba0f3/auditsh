# Tools: go1.27.3 (GOTOOLCHAIN=local), shellcheck, actionlint, visudo (sudo), curl.
# GoReleaser and govulncheck are version-pinned; GoReleaser is sha256-verified by its wrapper.
SHELL := /bin/sh
export GOTOOLCHAIN := local
export GOFLAGS :=
export PATH := $(PATH):/usr/sbin:/sbin:$(shell go env GOPATH 2>/dev/null)/bin

GORELEASER   := .github/scripts/goreleaser.sh
GOVULNCHECK  := golang.org/x/vuln/cmd/govulncheck@v1.9.0
FUZZTIME     ?= 30s
FUZZLONGTIME ?= 30m
FUZZPARALLEL ?= 2
FUZZ_TARGETS := FuzzParseCommand FuzzAllowlistExec FuzzEnvSanitize FuzzLogEncoder FuzzProcRead
SHELL_FILES  := install.sh build.sh packaging/*.sh tests/chroot-test.sh tests/pkg-test.sh deploy/auditsh-jvm .github/scripts/*.sh

.DEFAULT_GOAL := help
.PHONY: help build test lint fuzz fuzz-long vuln check snapshot pkg release clean

help: ## list targets
	@awk 'BEGIN{FS=":.*## "} /^[a-z-]+:.*## /{printf "  %-10s %s\n",$$1,$$2}' $(MAKEFILE_LIST)

build: ## reproducible single binary for HEAD -> dist/auditsh (GOOS/GOARCH/OUT honoured)
	./build.sh

test: ## go vet + race tests
	go vet ./...
	go test -race -count=1 ./...

lint: ## gofmt, shellcheck, actionlint, action SHA pins, visudo, goreleaser check
	@out=$$(gofmt -l .); [ -z "$$out" ] || { echo "gofmt needed: $$out"; exit 1; }
	shellcheck $(SHELL_FILES)
	actionlint
	.github/scripts/check-action-pins.sh
	visudo -cf deploy/sudoers.botaudit
	$(GORELEASER) check

fuzz: ## each fuzz target for FUZZTIME (default 30s)
	@for f in $(FUZZ_TARGETS); do \
	  echo "== $$f ($(FUZZTIME))"; \
	  go test -run '^$$' -fuzz "^$$f\$$" -fuzztime $(FUZZTIME) -parallel $(FUZZPARALLEL) . || exit 1; \
	done

fuzz-long: ## each fuzz target for FUZZLONGTIME (default 30m)
	$(MAKE) fuzz FUZZTIME=$(FUZZLONGTIME)

vuln: ## govulncheck (pinned v1.9.0)
	go run $(GOVULNCHECK) ./...

check: test lint vuln ## test + lint + vuln

snapshot: ## local untagged release build (binaries, deb/rpm, SHA256SUMS) in dist/ and release/
	$(GORELEASER) release --snapshot --clean
	.github/scripts/collect-release.sh

pkg: snapshot ## alias for snapshot

release: ## tag must be on HEAD, tree clean, GITHUB_TOKEN set: build + publish the GitHub release
	@[ -n "$$GITHUB_TOKEN" ] || { echo "GITHUB_TOKEN is not set"; exit 1; }
	@[ -z "$$(git status --porcelain)" ] || { echo "working tree is not clean"; exit 1; }
	@git describe --tags --exact-match --match 'v[0-9]*' HEAD >/dev/null 2>&1 || { echo "HEAD has no v* tag"; exit 1; }
	@[ "$$(go env GOVERSION)" = go1.27.3 ] || { echo "need go1.27.3, have $$(go env GOVERSION)"; exit 1; }
	$(GORELEASER) release --clean
	.github/scripts/collect-release.sh

clean: ## remove build outputs (dist/, release/, stage/)
	rm -rf dist release stage
