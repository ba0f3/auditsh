#!/bin/sh
# deb preinst (install/upgrade) / rpm %pre (1/2): runs BEFORE any file is unpacked. No fixed uid/gid:
# a missing botaudit is created later by postinst with system-assigned ids. An EXISTING botaudit keeps
# its ids but must look sane, otherwise abort so sudoers/binary never go live for a suspicious account.
set -eu
case "${1:-}" in install|upgrade|1|2) ;; *) exit 0 ;; esac
fail() { echo "auditsh preinst: $*; nothing installed" >&2; exit 1; }
acfail() { fail "$*"; }
# BEGIN account-check (byte-identical in install.sh and packaging/preinstall.sh; tests/account-check-test.sh)
# account_check NAME [PIN]: an existing NAME account/group must be safe to grant; calls acfail MSG otherwise.
ac_defs() {
  ac_v=$(awk -v k="$1" '$1==k{v=$2} END{print v}' /etc/login.defs 2>/dev/null) || ac_v=
  case "$ac_v" in ''|*[!0-9]*) ac_v=$2 ;; esac
  printf '%s' "$ac_v"
}
account_check() {
  ac_n=$1; ac_pin=${2:-}
  ac_ulo=$(ac_defs SYS_UID_MIN 100); ac_uhi=$(ac_defs SYS_UID_MAX 999)
  ac_glo=$(ac_defs SYS_GID_MIN 100); ac_ghi=$(ac_defs SYS_GID_MAX 999)
  ac_gg=""
  if ac_e=$(getent group "$ac_n"); then
    ac_gg=$(printf '%s' "$ac_e" | cut -d: -f3)
    case "$ac_gg" in ''|*[!0-9]*|0) acfail "group $ac_n has gid '$ac_gg' (0 or invalid)" ;; esac
    if [ "$ac_gg" -lt "$ac_glo" ] || [ "$ac_gg" -gt "$ac_ghi" ]; then acfail "group $ac_n gid $ac_gg outside system range $ac_glo..$ac_ghi"; fi
    [ "$(getent group | awk -F: -v g="$ac_gg" '$3==g' | wc -l)" -eq 1 ] || acfail "gid $ac_gg of group $ac_n is shared with another group"
    if [ -n "$ac_pin" ] && [ "$ac_gg" != "$ac_pin" ]; then acfail "group $ac_n exists with gid $ac_gg, not --uid $ac_pin"; fi
  fi
  if ac_e=$(getent passwd "$ac_n"); then
    ac_uu=$(printf '%s' "$ac_e" | cut -d: -f3); ac_ug=$(printf '%s' "$ac_e" | cut -d: -f4)
    case "$ac_uu" in ''|*[!0-9]*|0) acfail "user $ac_n has uid '$ac_uu' (0 or invalid)" ;; esac
    case "$ac_ug" in ''|*[!0-9]*|0) acfail "user $ac_n has primary gid '$ac_ug' (0 or invalid)" ;; esac
    if [ "$ac_uu" -lt "$ac_ulo" ] || [ "$ac_uu" -gt "$ac_uhi" ]; then acfail "user $ac_n uid $ac_uu outside system range $ac_ulo..$ac_uhi"; fi
    [ "$(getent passwd | awk -F: -v u="$ac_uu" '$3==u' | wc -l)" -eq 1 ] || acfail "uid $ac_uu of user $ac_n is shared with another account"
    if [ -z "$ac_gg" ] || [ "$ac_ug" != "$ac_gg" ]; then acfail "user $ac_n primary gid $ac_ug is not group $ac_n"; fi
    [ "$(id -G "$ac_n" 2>/dev/null)" = "$ac_gg" ] || acfail "user $ac_n has supplementary groups ($(id -Gn "$ac_n" 2>/dev/null))"
    if [ -n "$ac_pin" ] && [ "$ac_uu" != "$ac_pin" ]; then acfail "user $ac_n exists with uid $ac_uu, not --uid $ac_pin"; fi
  fi
  return 0
}
# END account-check
account_check botaudit
exit 0
