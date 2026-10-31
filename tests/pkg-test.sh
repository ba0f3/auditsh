#!/bin/sh
# Package test (deb or rpm). Runs INSIDE a throwaway Debian or Rocky/Alma/Fedora chroot only (never on a real host).
# Expects /src/dist/auditsh_*_amd64.deb or /src/dist/auditsh-*.x86_64.rpm and /src/sl (tiny /dev/log listener).
# shellcheck disable=SC2086  # $O/$ADD/$DEL/$PURGE are intentionally word-split
set -u
mkdir -p /run/sshd; rm -f /root/tk /root/tk.pub; ssh-keygen -q -t ed25519 -N '' -C test@x -f /root/tk </dev/null
snap() {
  find /etc /usr/local /usr/sbin /usr/share/auditsh /home -xdev \( -type f -o -type d \) ! -name '*-' 2>/dev/null \
    | sort | while read -r f; do if [ -f "$f" ]; then sha256sum "$f"; else echo "dir $f"; fi; done
  getent passwd | sort; getent group | sort
}
t() { printf '\n== %s\n' "$*"; }
if command -v dpkg >/dev/null 2>&1; then
  P=$(ls /src/dist/auditsh_*_amd64.deb); ADD="dpkg -i $P"; DEL="dpkg -r auditsh"; PURGE="dpkg --purge auditsh"
else
  P=$(ls /src/dist/auditsh-*.x86_64.rpm); ADD="rpm -i $P"; DEL="rpm -e auditsh"; PURGE=true
fi
snap > /tmp/s0

t "preinst refuses squatted uid/gid 990 before unpacking (deb preinst / rpm %pre)"
for case in "useradd -M -u 990 squat" "groupadd -g 990 squatg" "useradd -M -u 991 botaudit"; do
  $case; snap > /tmp/q0
  $ADD; echo "[$case] install rc=$?"
  left=""; for f in /usr/local/sbin/auditsh /etc/sudoers.d/botaudit /usr/sbin/auditsh-setup /etc/auditsh /usr/share/auditsh; do [ -e "$f" ] && left="$left $f"; done
  echo "leftover package paths:${left:- none}"
  if command -v dpkg >/dev/null 2>&1; then dpkg-query -W -f='status: ${db:Status-Abbrev}\n' auditsh 2>&1; else rpm -q auditsh; fi
  snap > /tmp/q1; diff /tmp/q0 /tmp/q1 && echo "unchanged"
  userdel squat 2>/dev/null; userdel botaudit 2>/dev/null; groupdel squatg 2>/dev/null; groupdel botaudit 2>/dev/null
done
snap > /tmp/q2; diff /tmp/s0 /tmp/q2 && echo "back to pre-test snapshot"

t "install (must not open SSH access)"
$ADD; echo "rc=$?"
id botaudit; getent passwd botaudit; passwd -S botaudit
grep -E "/usr/s?bin/ss" /etc/sudoers.d/botaudit /etc/auditsh/allowlist.yaml | cut -c1-90
stat -c '%U:%G %a %n' /usr/local/sbin/auditsh /etc/auditsh/allowlist.yaml /etc/sudoers.d/botaudit /home/botaudit /usr/share/auditsh/50-botaudit.conf
grep -x /usr/local/sbin/auditsh /etc/shells; grep -x botaudit /etc/cron.deny /etc/at.deny
ls /etc/ssh/sshd_config.d/50-botaudit.conf /etc/ssh/authorized_keys 2>&1
/usr/sbin/sshd -T -C user=botaudit,host=x,addr=127.0.0.1 | grep -Ei '^(forcecommand|acceptenv)' || echo "no forcecommand; AcceptEnv untouched"
visudo -c >/dev/null && echo visudo-ok

t "auditsh-setup --local without key fails, nothing changes"
snap > /tmp/s1; auditsh-setup --local; echo "rc=$?"; snap > /tmp/s1b; diff /tmp/s1 /tmp/s1b && echo unchanged

t "auditsh-setup --local --key (enable)"
auditsh-setup --local --key "$(cat /root/tk.pub)" >/dev/null; echo "rc=$?"
/usr/sbin/sshd -T -C user=botaudit,host=x,addr=127.0.0.1 | grep -Ei '^(forcecommand|acceptenv|permittty)'
grep -c '^# auditsh-disabled: AcceptEnv' /etc/ssh/sshd_config
cut -c1-60 /etc/ssh/authorized_keys/botaudit

t "e2e ssh"; /src/sl & sleep 0.3; /usr/sbin/sshd -o ListenAddress=127.0.0.1 -p 2222
O="-i /root/tk -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=error"
ssh $O botaudit@127.0.0.1 uptime; echo "rc=$?"; ssh $O botaudit@127.0.0.1 'ss -tlnp' | head -2; echo "ss rc=$?"; ssh $O botaudit@127.0.0.1 'sh -c id'; echo "rc=$?"; ssh $O -tt botaudit@127.0.0.1 </dev/null; echo "rc=$?"
pkill sshd; grep -o '"phase":"[a-z]*"\|"decision":"[a-z]*"\|"key_fp":"SHA256:[A-Za-z0-9]\{6\}' /tmp/syslog.txt | tr '\n' ' '; echo

t "remove: $DEL"
$DEL; echo "rc=$?"
id botaudit 2>&1; ls /etc/ssh/sshd_config.d/50-botaudit.conf /etc/sudoers.d/botaudit /usr/local/sbin/auditsh 2>&1; ls /etc/auditsh
grep -n AcceptEnv /etc/ssh/sshd_config; /usr/sbin/sshd -t && echo sshd-ok

t "purge: $PURGE"
$PURGE; echo "rc=$?"
snap > /tmp/s9; diff /tmp/s0 /tmp/s9 && echo "SNAPSHOT IDENTICAL TO PRE-INSTALL"

t "reinstall + purge directly"
$ADD >/dev/null; auditsh-setup --local --key "$(cat /root/tk.pub)" >/dev/null; $DEL >/dev/null; $PURGE >/dev/null; echo "rc=$?"
snap > /tmp/s10; diff /tmp/s0 /tmp/s10 && echo "SNAPSHOT IDENTICAL AFTER DIRECT PURGE"
