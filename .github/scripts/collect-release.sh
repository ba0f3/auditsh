#!/bin/sh
# Flatten a GoReleaser dist/ into release/ with the published asset names, then verify every asset
# against dist/SHA256SUMS and that SHA256SUMS lists exactly these files (no more, no less).
set -eu
cd "$(git rev-parse --show-toplevel)"
rm -rf release && mkdir release
for arch in amd64 arm64; do
  set -- dist/auditsh_linux_"$arch"_*/auditsh
  [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "expected one $arch binary in dist/" >&2; exit 1; }
  cp "$1" "release/auditsh-linux-$arch"
  set -- dist/auditsh-docker_linux_"$arch"_*/auditsh-docker
  [ "$#" -eq 1 ] && [ -f "$1" ] || { echo "expected one $arch auditsh-docker binary in dist/" >&2; exit 1; }
  cp "$1" "release/auditsh-docker-linux-$arch"
done
cp dist/*.deb dist/*.rpm dist/SHA256SUMS release/
cp allowlist.yaml install.sh deploy/auditsh-jvm deploy/sudoers.botaudit deploy/sshd_config.d/50-botaudit.conf release/
cd release
sha256sum -c --quiet SHA256SUMS
[ "$(awk '{print $2}' SHA256SUMS | sort)" = "$(find . -maxdepth 1 -type f ! -name SHA256SUMS | sed "s|^\./||" | sort)" ] || { echo "SHA256SUMS does not list exactly release/*" >&2; exit 1; }
cat SHA256SUMS
echo "AUDITSH_SHA256 (sha256 of SHA256SUMS): $(sha256sum SHA256SUMS | cut -d' ' -f1)"
