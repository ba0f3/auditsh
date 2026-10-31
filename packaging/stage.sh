#!/bin/sh
# GoReleaser before-hook: stage the per-packager config variants into stage/ and validate them.
# rpm variants use /usr/sbin/ss (RHEL/Rocky/Alma/Fedora path); deb keeps /usr/bin/ss (Debian usrmerge).
# Allowlist lines tagged '# deb-only' / '# rpm-only' are dropped from the other package's copy.
set -eu
export PATH="$PATH:/usr/sbin:/sbin" LC_ALL=C
cd "$(git rev-parse --show-toplevel)"
rm -rf stage
mkdir -p stage/deb stage/rpm
sed 's#/usr/bin/ss #/usr/sbin/ss #g' deploy/sudoers.botaudit > stage/rpm/sudoers.botaudit
sed -e 's#path: /usr/bin/ss,#path: /usr/sbin/ss,#' -e '/# deb-only$/d' allowlist.yaml > stage/rpm/allowlist.yaml
sed '/# rpm-only$/d' allowlist.yaml > stage/deb/allowlist.yaml
# sudoers is unpacked before postinst can run visudo -c: validate both variants here, before packaging.
command -v visudo >/dev/null 2>&1 || { echo "visudo not found (install sudo)" >&2; exit 1; }
visudo -cf deploy/sudoers.botaudit >&2
visudo -cf stage/rpm/sudoers.botaudit >&2
grep -q '/usr/sbin/ss -tlnp' stage/rpm/sudoers.botaudit || { echo "rpm sudoers ss rewrite failed" >&2; exit 1; }
if grep -q 'path: /usr/bin/dpkg-query,' stage/rpm/allowlist.yaml; then echo "rpm allowlist still has dpkg-query" >&2; exit 1; fi
if grep -q 'path: /usr/bin/rpm,' stage/deb/allowlist.yaml; then echo "deb allowlist still has rpm" >&2; exit 1; fi
