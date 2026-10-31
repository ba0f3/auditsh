#!/bin/sh
# deb preinst (install/upgrade) / rpm %pre (1/2): runs BEFORE any file is unpacked. No fixed uid/gid:
# a missing botaudit is created later by postinst with system-assigned ids. An EXISTING botaudit keeps
# its ids but must look sane, otherwise abort so sudoers/binary never go live for a suspicious account.
set -eu
case "${1:-}" in install|upgrade|1|2) ;; *) exit 0 ;; esac
fail() { echo "auditsh preinst: $*; nothing installed" >&2; exit 1; }
# Keep in sync with check_account_sane in install.sh.
lo=$(awk '$1=="SYS_UID_MIN"{print $2}' /etc/login.defs 2>/dev/null) || true
hi=$(awk '$1=="SYS_UID_MAX"{print $2}' /etc/login.defs 2>/dev/null) || true
case "$lo" in ''|*[!0-9]*) lo=100 ;; esac
case "$hi" in ''|*[!0-9]*) hi=999 ;; esac
num() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; }
gg=""
if bg=$(getent group botaudit); then
  gg=$(echo "$bg" | cut -d: -f3)
  num "$gg" || fail "group botaudit has bad gid '$gg'"
  [ "$gg" != 0 ] || fail "group botaudit has gid 0"
fi
if bu=$(getent passwd botaudit); then
  uu=$(echo "$bu" | cut -d: -f3); ug=$(echo "$bu" | cut -d: -f4)
  num "$uu" && num "$ug" || fail "user botaudit has bad uid/gid '$uu/$ug'"
  [ "$uu" != 0 ] || fail "user botaudit has uid 0"
  [ "$ug" != 0 ] || fail "user botaudit has primary gid 0"
  [ "$uu" -ge "$lo" ] && [ "$uu" -le "$hi" ] || fail "user botaudit uid $uu outside system range $lo..$hi"
  [ -n "$gg" ] && [ "$ug" = "$gg" ] || fail "user botaudit primary gid $ug is not group botaudit"
fi
exit 0
