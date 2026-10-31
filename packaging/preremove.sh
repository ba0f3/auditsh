#!/bin/sh
# deb prerm (remove; not upgrade) / rpm %preun ($1=0 erase; not upgrade): drop SSH access, keys, account,
# and restore AcceptEnv while the setup script still exists. dpkg/rpm then remove the package files.
set -e
case "${1:-}" in
  remove|0) /usr/sbin/auditsh-setup --uninstall --package ;;
esac
