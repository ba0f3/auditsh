#!/bin/sh
# Reproducible build of auditsh from a clean clone of a committed revision.
# Usage: ./build.sh [rev]   (default HEAD). Output: ./dist/auditsh (unstripped), or $OUT.
# GOOS/GOARCH from the environment select the target (e.g. GOARCH=arm64 OUT=dist/auditsh-linux-arm64).
set -eu
out=${OUT:-dist/auditsh}
want=go1.27.3
rev=$(git rev-parse "${1:-HEAD}")
have=$(GOTOOLCHAIN=local go env GOVERSION)
[ "$have" = "$want" ] || { echo "need $want, have $have" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git clone -q --no-local "$(git rev-parse --show-toplevel)" "$tmp/src"
git -C "$tmp/src" checkout -q --detach "$rev"
( cd "$tmp/src" && GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS='' go build -trimpath -buildvcs=true -o "$tmp/auditsh" . )
mkdir -p "$(dirname "$out")" && cp "$tmp/auditsh" "$out"
go version -m "$out" | grep -E 'vcs\.(revision|modified)'
sha256sum "$out"
