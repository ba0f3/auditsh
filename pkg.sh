#!/bin/sh
# Build dist/auditsh_*.deb and dist/auditsh-*.rpm (amd64 + arm64) from reproducible binaries (build.sh).
# Usage: ./pkg.sh [rev]   (default HEAD). SOURCE_DATE_EPOCH = commit time of rev, so packages are
# byte-reproducible. nfpm is pinned and its tarball sha256-verified (or set NFPM=/path/to/verified/nfpm).
# rpm variants use /usr/sbin/ss (RHEL/Rocky/Alma/Fedora path); deb keeps /usr/bin/ss (Debian usrmerge).
set -eu
export PATH="$PATH" LC_ALL=C
NFPM_VERSION=2.48.0
NFPM_SHA256=6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750 # nfpm_2.48.0_Linux_x86_64.tar.gz
rev=$(git rev-parse "${1:-HEAD}")
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct "$rev")
export SOURCE_DATE_EPOCH
v=$(git describe --tags --match 'v[0-9]*' --exact-match "$rev" 2>/dev/null || echo "v0.0.0~git$(git log -1 --format=%cd --date=format:%Y%m%d "$rev").$(git rev-parse --short=12 "$rev")")
VERSION=${v#v}
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

if [ -z "${NFPM:-}" ]; then
  [ "$(uname -m)" = x86_64 ] || { echo "pinned nfpm is x86_64 only; set NFPM=" >&2; exit 1; }
  curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/nfpm.tgz" \
    "https://github.com/goreleaser/nfpm/releases/download/v$NFPM_VERSION/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
  echo "$NFPM_SHA256  $tmp/nfpm.tgz" | sha256sum -c - >/dev/null
  tar -xzf "$tmp/nfpm.tgz" -C "$tmp" nfpm
  NFPM=$tmp/nfpm
fi

# Package from a clean checkout of rev (same tree as the binaries).
git clone -q --no-local "$(git rev-parse --show-toplevel)" "$tmp/src"
git -C "$tmp/src" checkout -q --detach "$rev"
BINDIR=$tmp/src/stage
mkdir -p "$BINDIR/rpm" dist
sed 's#/usr/bin/ss #/usr/sbin/ss #g' "$tmp/src/deploy/sudoers.botaudit" > "$BINDIR/rpm/sudoers.botaudit"
sed 's#path: /usr/bin/ss,#path: /usr/sbin/ss,#' "$tmp/src/allowlist.yaml" > "$BINDIR/rpm/allowlist.yaml"
mkdir -p "$tmp/out"
for ARCH in amd64 arm64; do
  GOOS=linux GOARCH=$ARCH OUT=$BINDIR/auditsh ./build.sh "$rev" >&2
  for p in deb rpm; do
    ( cd "$tmp/src" && ARCH=$ARCH VERSION=$VERSION "$NFPM" package -f nfpm.yaml -p "$p" -t "$tmp/out/" >&2 )
  done
done
cp "$tmp"/out/* dist/
( cd "$tmp/out" && sha256sum -- * )
