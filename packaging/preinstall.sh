#!/bin/sh
# deb preinst (install/upgrade) / rpm %pre (1/2): runs BEFORE any file is unpacked. Abort unless
# uid/gid 990 are free or already belong to botaudit, so a squatted id never leaves sudoers/binary live.
set -e
case "${1:-}" in install|upgrade|1|2) ;; *) exit 0 ;; esac
fail() { echo "auditsh preinst: $*; nothing installed" >&2; exit 1; }
u=$(getent passwd 990 | cut -d: -f1) || true
g=$(getent group 990 | cut -d: -f1) || true
[ -z "$u" ] || [ "$u" = botaudit ] || fail "uid 990 is used by '$u'"
[ -z "$g" ] || [ "$g" = botaudit ] || fail "gid 990 is used by group '$g'"
if bu=$(getent passwd botaudit); then
  [ "$(echo "$bu" | cut -d: -f3)" = 990 ] || fail "user botaudit exists with uid $(echo "$bu" | cut -d: -f3), need 990"
fi
if bg=$(getent group botaudit); then
  [ "$(echo "$bg" | cut -d: -f3)" = 990 ] || fail "group botaudit exists with gid $(echo "$bg" | cut -d: -f3), need 990"
fi
exit 0
