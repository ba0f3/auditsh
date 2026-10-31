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
grep -cE "path: /usr/bin/(dpkg-query|rpm)," /etc/auditsh/allowlist.yaml; grep -oE "path: /usr/bin/(dpkg-query|rpm)," /etc/auditsh/allowlist.yaml
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

t "--java-user validation (each must fail, nothing written)"
for u in root botaudit nosuchuser 'Bad;user' ''; do auditsh-setup --local --java-user "$u" >/dev/null 2>&1; echo "[$u] rc=$?"; done
ls /etc/sudoers.d/botaudit-jvm 2>&1
t "--java-user jvmapp (generated sudoers)"
useradd -M -s /usr/sbin/nologin jvmapp
auditsh-setup --local --java-user jvmapp --java-user jvmapp >/dev/null; echo "rc=$?"
stat -c '%U:%G %a %n' /usr/local/sbin/auditsh-jvm /etc/sudoers.d/botaudit-jvm /etc/auditsh/java-users; cat /etc/auditsh/java-users; grep -v '^#' /etc/sudoers.d/botaudit-jvm; visudo -c >/dev/null && echo visudo-ok
sudo -l -U botaudit | grep -E 'auditsh-jvm|ss -tlnp' | sed 's/^ *//'

t "e2e ssh"; /src/sl & sleep 0.3; /usr/sbin/sshd -o ListenAddress=127.0.0.1 -p 2222
O="-i /root/tk -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=error"
ssh $O botaudit@127.0.0.1 uptime; echo "rc=$?"; ssh $O botaudit@127.0.0.1 'ss -tlnp' | head -2; echo "ss rc=$?"; ssh $O botaudit@127.0.0.1 'sh -c id'; echo "rc=$?"; ssh $O -tt botaudit@127.0.0.1 </dev/null; echo "rc=$?"
for c in 'uname -a' 'getent group' 'sshd -T' 'dpkg-query -l' 'rpm -qa' 'who' 'crontab -l -u root' 'last -n 5' 'wtmpdb last -n 5'; do
  # shellcheck disable=SC2029  # $c is a fixed local test string
  ssh $O botaudit@127.0.0.1 "$c" >/tmp/o 2>&1; echo "[$c] rc=$? lines=$(wc -l </tmp/o) first=$(head -c 40 /tmp/o | head -1)"
done
ssh $O botaudit@127.0.0.1 'crontab -e -u root'; echo "crontab -e rc=$?"
# shellcheck disable=SC2029  # $c is a fixed local test string
for c in 'wtmpdb last' 'wtmpdb last -n 0' 'wtmpdb boot'; do ssh $O botaudit@127.0.0.1 "$c" >/dev/null 2>&1; echo "[$c] rc=$?"; done
ssh $O botaudit@127.0.0.1 'jcmd 1 VM.uptime' 2>&1 | tail -1
t "java: denied forms (rc=126 each, sudo/helper never reached for pid 1 = not java)"
for c in 'jcmd 1 VM.uptime' 'jcmd 1 GC.heap_dump /tmp/x' 'jcmd abc GC.heap_info' 'jcmd 1 GC.heap_info extra' 'jcmd 1 VM.command_line' 'jstat -gcutil 1 1000 11'; do
  # shellcheck disable=SC2029  # $c is meant to be sent verbatim
  ssh $O botaudit@127.0.0.1 "$c" >/dev/null 2>&1; echo "[$c] rc=$?"; done
t "java: botaudit cannot reach helper as root, only as jvmapp"
su -s /bin/sh botaudit -c 'sudo -n -u root /usr/local/sbin/auditsh-jvm jcmd 1 VM.uptime' 2>&1 | tail -1
su -s /bin/sh botaudit -c 'sudo -n -u jvmapp /usr/local/sbin/auditsh-jvm jcmd 1 GC.heap_dump /tmp/x' 2>&1 | tail -1
su -s /bin/sh botaudit -c 'sudo -n -u jvmapp /usr/local/sbin/auditsh-jvm jcmd 1 VM.uptime' 2>&1 | tail -1
su -s /bin/sh botaudit -c 'sudo -n -u jvmapp /usr/local/sbin/auditsh-jvm jcmd 1 GC.class_histogram' 2>&1 | tail -1
su -s /bin/sh botaudit -c 'sudo -n -u jvmapp /usr/local/sbin/auditsh-jvm jcmd 1 Thread.print' 2>&1 | tail -1
t "iptables (resolve: true) + OS identification"
for c in 'iptables -S' 'iptables -L -n -v' 'iptables-save' 'ip6tables -S' 'ip6tables -L -n -v' 'ip6tables-save' 'cat /etc/os-release' 'cat /etc/redhat-release' 'cat /etc/debian_version' 'cat /etc/lsb-release' 'lsb_release -a'; do
  # shellcheck disable=SC2029  # $c is a fixed local test string
  ssh $O botaudit@127.0.0.1 "$c" >/tmp/o 2>&1; echo "[$c] rc=$? lines=$(wc -l </tmp/o) first=$(head -1 /tmp/o | cut -c1-50)"
done
for c in 'iptables -F' 'iptables -L' 'iptables -L -n' 'iptables -t nat -S' 'iptables -L -n -v -x' 'iptables-save -f /tmp/x' 'ip6tables -S INPUT' 'cat /usr/lib/os-release' 'cat /etc/shadow' 'cat /etc/issue'; do
  # shellcheck disable=SC2029  # $c is a fixed local test string
  ssh $O botaudit@127.0.0.1 "$c" >/dev/null 2>&1; echo "[$c] rc=$?"
done
for c in '/usr/sbin/iptables -F' '/usr/sbin/iptables-save -f /tmp/x' '/usr/sbin/iptables -S -t nat' "$(readlink -f /usr/sbin/iptables) iptables -F"; do
  printf '[sudo %s] ' "$c"; su -s /bin/sh botaudit -c "sudo -n $c" 2>&1 | tail -1
done
su -s /bin/sh botaudit -c 'sudo -n /usr/sbin/iptables -S' >/dev/null 2>&1; echo "[sudo iptables -S direct] rc=$?"
t "iptables: chain through a non-root-safe dir is refused (126)"
a=$(readlink /etc/alternatives/iptables) && cp "$(readlink -f /usr/sbin/iptables)" /tmp/evil && ln -sfn /tmp/evil /etc/alternatives/iptables &&
  { ssh $O botaudit@127.0.0.1 'iptables -S' >/dev/null 2>&1; echo "tampered rc=$?"; ln -sfn "$a" /etc/alternatives/iptables; rm -f /tmp/evil; }
readlink /etc/alternatives/iptables
t "iptables: chain to a root-owned but non-xtables binary is refused (126)"
if [ -e /usr/bin/true ]; then a=$(readlink /etc/alternatives/iptables); ln -sfn /usr/bin/true /etc/alternatives/iptables
  ssh $O botaudit@127.0.0.1 'iptables -S' >/dev/null 2>&1; echo "true-target rc=$?"; ln -sfn "$a" /etc/alternatives/iptables; fi
if [ -x /usr/sbin/iptables-legacy ] && command -v update-alternatives >/dev/null; then
  t "iptables legacy backend"
  update-alternatives --set iptables /usr/sbin/iptables-legacy >/dev/null
  for c in 'iptables -S' 'iptables -L -n -v' 'iptables-save'; do
    # shellcheck disable=SC2029  # $c is a fixed local test string
    ssh $O botaudit@127.0.0.1 "$c" >/tmp/o 2>&1; echo "[legacy $c] rc=$? first=$(head -1 /tmp/o | cut -c1-50)"; done
  update-alternatives --set iptables /usr/sbin/iptables-nft >/dev/null; readlink /etc/alternatives/iptables
fi
t "L-3: --local without --java-user revokes JVM access"
auditsh-setup --local --key "$(cat /root/tk.pub)" >/dev/null; echo "rc=$?"; for f in /etc/sudoers.d/botaudit-jvm /etc/auditsh/java-users; do [ -e "$f" ] && echo "STILL $f" || echo "gone $f"; done
pkill sshd; grep -o '"phase":"[a-z]*"\|"decision":"[a-z]*"\|"key_fp":"SHA256:[A-Za-z0-9]\{6\}' /tmp/syslog.txt | tr '\n' ' '; echo

t "remove: $DEL"
$DEL; echo "rc=$?"
id botaudit 2>&1; ls /etc/ssh/sshd_config.d/50-botaudit.conf /etc/sudoers.d/botaudit /etc/sudoers.d/botaudit-jvm /usr/local/sbin/auditsh /usr/local/sbin/auditsh-jvm 2>&1; ls /etc/auditsh
userdel jvmapp
grep -n AcceptEnv /etc/ssh/sshd_config; /usr/sbin/sshd -t && echo sshd-ok

t "purge: $PURGE"
$PURGE; echo "rc=$?"
snap > /tmp/s9; diff /tmp/s0 /tmp/s9 && echo "SNAPSHOT IDENTICAL TO PRE-INSTALL"

t "reinstall + purge directly"
$ADD >/dev/null; auditsh-setup --local --key "$(cat /root/tk.pub)" >/dev/null; $DEL >/dev/null; $PURGE >/dev/null; echo "rc=$?"
snap > /tmp/s10; diff /tmp/s0 /tmp/s10 && echo "SNAPSHOT IDENTICAL AFTER DIRECT PURGE"
