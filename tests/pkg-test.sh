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

t "preinst refuses a bad pre-existing botaudit before unpacking (deb preinst / rpm %pre)"
for case in "useradd -M -o -u 0 -g 0 botaudit" "useradd -M -U -u 1500 botaudit" "useradd -M -u 991 -g 0 botaudit" "useradd -M -u 992 -g users botaudit" \
  "groupadd -r -g 985 botaudit;useradd -M -r -u 985 -g botaudit botaudit;useradd -M -o -u 985 -g botaudit aliasu" \
  "groupadd -r -g 985 botaudit;groupadd -o -g 985 aliasg;useradd -M -r -u 985 -g botaudit botaudit" \
  "groupadd -r -g 985 botaudit;useradd -M -r -u 985 -g botaudit -G adm botaudit" \
  "groupadd -g 1500 botaudit"; do
  (IFS=';'; for c in $case; do (IFS=' '; $c); done); snap > /tmp/q0
  $ADD; echo "[$case] install rc=$?"
  left=""; for f in /usr/local/sbin/auditsh /etc/sudoers.d/botaudit /usr/sbin/auditsh-setup /etc/auditsh /usr/share/auditsh; do [ -e "$f" ] && left="$left $f"; done
  echo "leftover package paths:${left:- none}"
  if command -v dpkg >/dev/null 2>&1; then dpkg-query -W -f='status: ${db:Status-Abbrev}\n' auditsh 2>&1; else rpm -q auditsh; fi
  snap > /tmp/q1; diff /tmp/q0 /tmp/q1 && echo "unchanged"
  userdel -f aliasu 2>/dev/null; userdel -f botaudit 2>/dev/null; groupdel aliasg 2>/dev/null; groupdel botaudit 2>/dev/null
done
snap > /tmp/q2; diff /tmp/s0 /tmp/q2 && echo "back to pre-test snapshot"

t "gid/uid 990 owned by others: install works with system-assigned ids, then remove"
groupadd -g 990 docker990; useradd -M -u 990 -g docker990 squat990
$ADD; echo "rc=$?"; getent passwd botaudit | cut -d: -f1,3,4; getent group botaudit | cut -d: -f1,3
$DEL >/dev/null; echo "remove rc=$?"; $PURGE >/dev/null 2>&1
userdel squat990; groupdel docker990
snap > /tmp/q3; diff /tmp/s0 /tmp/q3 && echo "back to pre-test snapshot"

t "N-1: postinst re-check fails on the account it just created -> sudoers removed, account removed, rc!=0"
# A stale member line makes the NEW botaudit a supplementary member: preinst (no botaudit yet) passes,
# the post-create re-check in auditsh-setup --account-only must fail closed.
groupadd staleg; sed -i 's/^\(staleg:[^:]*:[0-9]*:\)$/\1botaudit/' /etc/group; grep '^staleg:' /etc/group
$ADD; echo "rc=$?"
for f in /etc/sudoers.d/botaudit /etc/sudoers.d/botaudit-jvm; do if [ -e "$f" ]; then echo "sudoers: $f present"; else echo "sudoers: $f absent"; fi; done
getent passwd botaudit || echo "no botaudit user"; getent group botaudit || echo "no botaudit group"
if command -v dpkg >/dev/null 2>&1; then dpkg-query -W -f='status: ${db:Status-Abbrev}\n' auditsh 2>&1; else rpm -q auditsh; fi
$DEL >/dev/null 2>&1; $PURGE >/dev/null 2>&1; echo "cleanup rc=$?"
groupdel staleg; userdel botaudit 2>/dev/null; groupdel botaudit 2>/dev/null
snap > /tmp/q5; diff /tmp/s0 /tmp/q5 && echo "back to pre-test snapshot"

t "P-2: --account-only failing AFTER the re-check (test hook) -> sudoers removed first, created account removed"
$ADD >/dev/null 2>&1; echo "install rc=$?"; userdel botaudit; groupdel botaudit 2>/dev/null
getent passwd botaudit || echo "botaudit removed for the test"
AUDITSH_TEST_FAIL_AFTER=account_recheck auditsh-setup --account-only --test-hooks; echo "account-only rc=$?"
for f in /etc/sudoers.d/botaudit /etc/sudoers.d/botaudit-jvm; do if [ -e "$f" ]; then echo "sudoers: $f present"; else echo "sudoers: $f absent"; fi; done
getent passwd botaudit || echo "no botaudit user"; getent group botaudit || echo "no botaudit group"
$DEL >/dev/null 2>&1; $PURGE >/dev/null 2>&1; echo "cleanup rc=$?"; userdel botaudit 2>/dev/null; groupdel botaudit 2>/dev/null
snap > /tmp/q6; diff /tmp/s0 /tmp/q6 && echo "back to pre-test snapshot"

t "pre-existing sane botaudit keeps its ids"
groupadd --system -g 985 botaudit; useradd --system -M -u 985 -g botaudit botaudit
$ADD; echo "rc=$?"; getent passwd botaudit | cut -d: -f1,3,4
$DEL >/dev/null; echo "remove rc=$?"; $PURGE >/dev/null 2>&1
userdel botaudit 2>/dev/null; groupdel botaudit 2>/dev/null
snap > /tmp/q4; diff /tmp/s0 /tmp/q4 && echo "back to pre-test snapshot"

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
t "P2: failed --local on a PRE-EXISTING, modified botaudit rolls the account back exactly"
mkdir -p /var/lib/ba-alt /home/botaudit/.ssh; : > /home/botaudit/.ssh/authorized_keys
chown -R botaudit:botaudit /home/botaudit/.ssh; chmod 0700 /home/botaudit/.ssh; chmod 0600 /home/botaudit/.ssh/authorized_keys
acct() { getent passwd botaudit; getent shadow botaudit | sha256sum | cut -c1-16; stat -c '%u:%g %a %n' /home/botaudit /home/botaudit/.ssh /home/botaudit/.ssh/authorized_keys; }
# shellcheck disable=SC2016  # literal fake hashes
for pw in '$6$p2test$notarealhashbutanopaquevalue0123456789' '!$6$p2test$lockedhash' '!' '*' ''; do
  usermod -s /bin/sh -d /var/lib/ba-alt botaudit
  chown botaudit /home/botaudit; chmod 0750 /home/botaudit; chown -R botaudit:botaudit /home/botaudit/.ssh
  printf 'botaudit:%s\n' "$pw" | chpasswd -e
  acct > /tmp/a0; snap > /tmp/p0
  AUDITSH_TEST_FAIL_AFTER=setup_account auditsh-setup --local --test-hooks --key "$(cat /root/tk.pub)" >/tmp/f 2>&1; rc=$?
  acct > /tmp/a1; snap > /tmp/p1
  r=RESTORED; diff -q /tmp/a0 /tmp/a1 >/dev/null || r=CHANGED; diff -q /tmp/p0 /tmp/p1 >/dev/null || r="$r files-CHANGED"
  case $pw in '') k='empty' ;; '!$'*) k='locked-hash' ;; '$'*) k='hash' ;; *) k="'$pw'" ;; esac
  echo "[$k] forced-failure rc=$rc account $r; $(grep -c ERROR: /tmp/f) error line(s), hook=$(grep -c 'test hook' /tmp/f)"
  ! grep -q 'p2test' /tmp/f || echo "HASH LEAKED TO OUTPUT"
done
AUDITSH_TEST_FAIL_AFTER=setup_account auditsh-setup --local --key "$(cat /root/tk.pub)" >/dev/null 2>&1; echo "env without --test-hooks ignored rc=$?"
getent passwd botaudit | cut -d: -f6,7; passwd -S botaudit | cut -d' ' -f2; stat -c '%U:%G %a %n' /home/botaudit /home/botaudit/.ssh
t "H-1/M-1: hostile pre-existing botaudit (odd names, symlinks out of HOME) cannot steer the rollback"
H=/home/botaudit; S=$H/.ssh; ug="$(id -u botaudit):$(id -g botaudit)"
mkdir -p /tmp/h1; printf 'sentinel\n' > /root/sentinel; printf 'victim\n' > /tmp/h1/victim; chmod 0600 /root/sentinel /tmp/h1/victim
usermod -s /bin/sh -d /var/lib/ba-alt botaudit; chown botaudit:botaudit $H; chmod 0750 $H
# names cannot hold '/': the forged line targets ./victim in the installer's cwd (the reviewer's PoC)
for n in "a
$ug 777 victim" "b
$ug 4777 victim" "sp ace" "-rf x" "--" "-"; do : > "$S/$n"; : > "$H/$n"; done
ln -s /root/sentinel "$S/lnk"; ln -s /etc "$S/etc"; ln -s /root/sentinel "$H/lnk"; ln -s /etc "$H/etc"
chown -hR botaudit:botaudit $S; chmod 0700 $S; chmod 0600 $S/authorized_keys
xsnap() { snap | grep -v " $H"; find /etc /root /tmp/h1 /tmp/m2out -xdev ! -path "$H*" -printf '%U:%G %m %p\n' 2>/dev/null | sort; }
inner() { find $H -mindepth 1 ! -path $S ! -path $S/authorized_keys -printf '%U:%G %m %y %l\n' | sort | sha256sum; }
acct > /tmp/a0; xsnap > /tmp/x0; inner > /tmp/i0
(cd /tmp/h1 && AUDITSH_TEST_FAIL_AFTER=setup_account auditsh-setup --local --test-hooks --key "$(cat /root/tk.pub)" >/tmp/f 2>&1); rc=$?
acct > /tmp/a1; xsnap > /tmp/x1; inner > /tmp/i1
echo "forced-failure rc=$rc hook=$(grep -c 'test hook' /tmp/f) rolled-back=$(grep -c 'rolled back' /tmp/f)"
if diff /tmp/a0 /tmp/a1 >/dev/null; then echo "fixed paths RESTORED"; else echo "fixed paths CHANGED"; diff /tmp/a0 /tmp/a1; fi
if diff /tmp/x0 /tmp/x1 >/dev/null; then echo "OUTSIDE HOME UNCHANGED"; else echo "OUTSIDE HOME CHANGED"; diff /tmp/x0 /tmp/x1; fi
diff /tmp/i0 /tmp/i1 >/dev/null && echo "other HOME entries untouched" || echo "other HOME entries CHANGED"
stat -c '%u:%g %a sentinel' /root/sentinel; stat -c '%u:%g %a victim' /tmp/h1/victim
t "symlinked authorized_keys is refused before any change"
mv $S/authorized_keys $S/ak.real; ln -s /root/sentinel $S/authorized_keys; chown -h botaudit:botaudit $S/authorized_keys
xsnap > /tmp/x0; getent passwd botaudit > /tmp/a0
(cd /tmp/h1 && auditsh-setup --local --key "$(cat /root/tk.pub)" >/tmp/f 2>&1); rc=$?
xsnap > /tmp/x1; getent passwd botaudit > /tmp/a1
echo "rc=$rc refused=$(grep -c 'is a symlink; refusing' /tmp/f)"; diff /tmp/x0 /tmp/x1 >/dev/null && diff /tmp/a0 /tmp/a1 >/dev/null && echo "NOTHING CHANGED"
rm -f $S/authorized_keys; mv $S/ak.real $S/authorized_keys
auditsh-setup --local --key "$(cat /root/tk.pub)" >/dev/null 2>&1; echo "clean reinstall rc=$?"
find $H -mindepth 1 -maxdepth 1 ! -name .ssh -exec rm -rf {} +; rm -rf /tmp/h1 /root/sentinel
t "M-2: symlinked .ssh / hardlinked authorized_keys are refused on full install and --account-only"
mkdir -p /tmp/h1 /tmp/m2out; printf 'k\n' > /tmp/m2out/authorized_keys; printf 's\n' > /tmp/m2out/sentinel
chown 4242:4242 /tmp/m2out /tmp/m2out/authorized_keys; chmod 0600 /tmp/m2out/authorized_keys /tmp/m2out/sentinel
m2() { # $1 label; account made hostile-looking (HOME owned by it) before each run
  chown botaudit:botaudit $H; xsnap > /tmp/x0
  (cd /tmp/h1 && auditsh-setup --local --key "$(cat /root/tk.pub)" >/tmp/f 2>&1); r1=$?; xsnap > /tmp/x1
  (cd /tmp/h1 && auditsh-setup --account-only >/tmp/g 2>&1); r2=$?; xsnap > /tmp/x2
  o="OUTSIDE HOME UNCHANGED"; { diff -q /tmp/x0 /tmp/x1 && diff -q /tmp/x0 /tmp/x2; } >/dev/null || { o="OUTSIDE HOME CHANGED"; diff /tmp/x0 /tmp/x2; }
  echo "[$1] full rc=$r1 refused=$(grep -c 'refusing to touch' /tmp/f); account-only rc=$r2 refused=$(grep -c 'refusing to touch' /tmp/g); $o"
  stat -c '%u:%g %a %n' /tmp/m2out/authorized_keys /tmp/m2out/sentinel
}
mv $S $S.real; ln -s /tmp/m2out $S; chown -h botaudit:botaudit $S
m2 "symlinked .ssh"
rm -f $S; mv $S.real $S; mv $S/authorized_keys $S/ak.real; ln /tmp/m2out/authorized_keys $S/authorized_keys
m2 "hardlinked authorized_keys"
rm -f $S/authorized_keys; mv $S/ak.real $S/authorized_keys
auditsh-setup --local --key "$(cat /root/tk.pub)" >/dev/null 2>&1; echo "clean reinstall rc=$?"
rm -rf /tmp/h1 /tmp/m2out
rm -rf /home/botaudit/.ssh; rmdir /var/lib/ba-alt

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
