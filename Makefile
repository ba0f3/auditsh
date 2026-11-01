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
FUZZ_TARGETS_DOCKER := FuzzValidate FuzzRedactContainers
SHELL_FILES  := install.sh build.sh packaging/*.sh tests/chroot-test.sh tests/pkg-test.sh tests/account-check-test.sh deploy/auditsh-jvm .github/scripts/*.sh

.DEFAULT_GOAL := help
.PHONY: help build test lint fuzz fuzz-long vuln check snapshot pkg release verify-release clean

help: ## list targets
	@awk 'BEGIN{FS=":.*## "} /^[a-z-]+:.*## /{printf "  %-10s %s\n",$$1,$$2}' $(MAKEFILE_LIST)

build: ## reproducible single binary for HEAD -> dist/auditsh (GOOS/GOARCH/OUT honoured)
	./build.sh

test: ## go vet + race tests (fetches and verifies modules first, so a clean checkout works)
	go mod download
	go mod verify
	go vet ./...
	go test -race -count=1 ./...
	sh tests/account-check-test.sh

lint: ## gofmt, shellcheck, actionlint, action SHA pins, visudo, goreleaser check
	@out=$$(gofmt -l .); [ -z "$$out" ] || { echo "gofmt needed: $$out"; exit 1; }
	shellcheck $(SHELL_FILES)
	actionlint
	.github/scripts/check-action-pins.sh
	visudo -cf deploy/sudoers.botaudit
	visudo -cf deploy/docker/sudoers.botaudit-docker
	$(GORELEASER) check

fuzz: ## each fuzz target for FUZZTIME (default 30s)
	@for f in $(FUZZ_TARGETS); do \
	  echo "== $$f ($(FUZZTIME))"; \
	  go test -run '^$$' -fuzz "^$$f\$$" -fuzztime $(FUZZTIME) -parallel $(FUZZPARALLEL) . || exit 1; \
	done; \
	for f in $(FUZZ_TARGETS_DOCKER); do \
	  echo "== dockerpolicy $$f ($(FUZZTIME))"; \
	  go test -run '^$$' -fuzz "^$$f\$$" -fuzztime $(FUZZTIME) -parallel $(FUZZPARALLEL) ./internal/dockerpolicy || exit 1; \
	done

fuzz-long: ## each fuzz target for FUZZLONGTIME (default 30m)
	$(MAKE) fuzz FUZZTIME=$(FUZZLONGTIME)

vuln: ## govulncheck (pinned v1.9.0)
	go run $(GOVULNCHECK) ./...

check: test lint vuln ## test + lint + vuln

snapshot: ## local untagged build (version 0.0.0~git<sha>; does NOT reproduce a release's SHA256SUMS) (binaries, deb/rpm, SHA256SUMS) in dist/ and release/
	$(GORELEASER) release --snapshot --clean
	.github/scripts/collect-release.sh

pkg: snapshot ## alias for snapshot

release: ## LOCAL publish (no provenance attestation): annotated v* tag pushed to origin == HEAD, clean tree, GITHUB_TOKEN
	@.github/scripts/release-gate.sh
	@echo "WARNING: a local release carries NO build-provenance attestation (install --require-attestation will fail)."
	@echo "WARNING: prefer the release.yml workflow as publisher once GitHub Actions works."
	$(GORELEASER) release --clean
	.github/scripts/collect-release.sh

verify-release: ## rebuild the tag at HEAD without publishing; compare with the published SHA256SUMS
	@[ -z "$$(git status --porcelain)" ] || { echo "working tree is not clean"; exit 1; }
	@t=$$(git describe --tags --exact-match --match 'v[0-9]*' HEAD) || { echo "HEAD has no v* tag"; exit 1; }; \
	$(GORELEASER) release --clean --skip=publish,announce && .github/scripts/collect-release.sh && \
	curl --proto '=https' --tlsv1.2 -fsSL -o dist/SHA256SUMS.published "https://github.com/ba0f3/auditsh/releases/download/$$t/SHA256SUMS" && \
	cmp dist/SHA256SUMS.published release/SHA256SUMS && echo "OK: $$t reproduces the published SHA256SUMS"

clean: ## remove build outputs (dist/, release/, stage/)
	rm -rf dist release stage
