#!/bin/sh
# deb postrm / rpm %postun. dpkg deletes /usr/local/sbin when it becomes empty because the package
# shipped a file there and no package owns the dir (Debian base-files creates it in postinst); recreate it.
set -e
case "${1:-}" in
  remove|purge|0) [ ! -d /usr/local ] || [ -d /usr/local/sbin ] || install -d -o root -g root -m 0755 /usr/local/sbin ;;
esac
case "${1:-}" in
  purge) rmdir /etc/auditsh 2>/dev/null || true ;;
esac
