#!/bin/sh
# deb postinst (configure) / rpm %post (1=install, 2=upgrade): create/refresh the botaudit account and
# validate sudoers (removed on failure). Opens NO SSH access: run `auditsh-setup --local --key ...` for that.
set -e
case "${1:-}" in
  configure|1|2) /usr/sbin/auditsh-setup --account-only ;;
esac
