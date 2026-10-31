#!/bin/sh
# deb postinst (configure) / rpm %post (1=install, 2=upgrade): create/refresh the botaudit account and
# validate sudoers (removed on failure). Opens NO SSH access: run `auditsh-setup --local --key ...` for that.
set -e
case "${1:-}" in
  configure|1|2)
    # rpm only warns on a failed %post (rpm -i still exits 0): make the failure impossible to miss.
    if ! /usr/sbin/auditsh-setup --account-only; then
      echo "auditsh postinst: ERROR: botaudit account setup FAILED; sudoers removed, auditsh is NOT usable." >&2
      echo "auditsh postinst: ERROR: fix the cause above, then run: auditsh-setup --account-only" >&2
      exit 1
    fi ;;
esac
