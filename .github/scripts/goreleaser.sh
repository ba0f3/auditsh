#!/bin/sh
# Run the pinned, sha256-verified GoReleaser (OSS). Cached in .bin/ (gitignored).
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
bin=$root/.bin/goreleaser-$GORELEASER_VERSION
if [ ! -x "$bin" ]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/gr.tgz" \
    "https://github.com/goreleaser/goreleaser/releases/download/v$GORELEASER_VERSION/goreleaser_Linux_$a.tar.gz"
  echo "$sum  $tmp/gr.tgz" | sha256sum -c - >/dev/null
  tar -xzf "$tmp/gr.tgz" -C "$tmp" goreleaser
  mkdir -p "$root/.bin" && mv "$tmp/goreleaser" "$bin"
fi
exec "$bin" "$@"
