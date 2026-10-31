#!/bin/sh
# Run the pinned, sha256-verified GoReleaser (OSS). Tarball cached in .bin/ (gitignored), re-verified every run.
# Usage: .github/scripts/goreleaser.sh <goreleaser args...>
# Checksums are from the release's checksums.txt (goreleaser/goreleaser v2.19.0).
set -eu
GORELEASER_VERSION=2.19.0
case "$(uname -m)" in
  x86_64) a=x86_64 sum=ebc3194ad1d1b1787614405285a0039665cd4c5bd3305215a1b201600f90630b ;;
  aarch64 | arm64) a=arm64 sum=ef33741b684c9f62d6a21e7a3c8b051f139ea7b1d301693b67cc819c46226d53 ;;
  *) echo "unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac
root=$(git rev-parse --show-toplevel)
cache=$root/.bin
tgz=$cache/goreleaser_${GORELEASER_VERSION}_Linux_$a.tar.gz
bin=$cache/goreleaser-$GORELEASER_VERSION
ok() { [ -f "$tgz" ] && echo "$sum  $tgz" | sha256sum -c - >/dev/null 2>&1; }
# The cached tarball is re-verified on every run; on mismatch it is re-downloaded once, then we fail.
if ! ok; then
  mkdir -p "$cache"; rm -f "$tgz"
  curl --proto '=https' --tlsv1.2 -fsSL -o "$tgz.part" \
    "https://github.com/goreleaser/goreleaser/releases/download/v$GORELEASER_VERSION/goreleaser_Linux_$a.tar.gz"
  mv "$tgz.part" "$tgz"
  ok || { rm -f "$tgz"; echo "goreleaser tarball sha256 mismatch (expected $sum)" >&2; exit 1; }
fi
# Always re-extract the binary from the verified tarball, so a tampered cached binary is never run.
tmp=$(mktemp -d "$cache/x.XXXXXX"); trap 'rm -rf "$tmp"' EXIT
tar -xzf "$tgz" -C "$tmp" goreleaser
mv -f "$tmp/goreleaser" "$bin"
"$bin" "$@"
