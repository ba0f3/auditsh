#!/bin/sh
# Test harness for install.sh. Runs INSIDE a throwaway Debian chroot only (never on a real host):
# it replaces /usr/bin/curl with a shim that serves a local fake release from $REL.
# shellcheck disable=SC2086  # $O / $I are intentionally word-split
# Expects /src = repo checkout, /src/dist/auditsh = locally built binary, /src/sl = tiny /dev/log listener.
set -u
REL=/tmp/rel; mkdir -p $REL
cp /src/dist/auditsh $REL/auditsh-linux-amd64; cp /src/allowlist.yaml /src/deploy/sudoers.botaudit /src/deploy/sshd_config.d/50-botaudit.conf $REL/
(cd $REL && sha256sum -- * > SHA256SUMS); SUMS=$(sha256sum $REL/SHA256SUMS | cut -d' ' -f1)
cat > /usr/bin/curl <<'SH'
#!/bin/sh
o=; u=; while [ $# -gt 0 ]; do case $1 in -o) o=$2; shift 2;; -*) shift;; *) u=$1; shift;; esac; done
case $u in https://github.com/ba0f3/auditsh/releases/download/v9.9.9/*) cp "/tmp/rel/${u##*/}" "$o";; *) exit 22;; esac
SH
chmod 755 /usr/bin/curl
mkdir -p /run/sshd; rm -f /root/tk /root/tk.pub; ssh-keygen -q -t ed25519 -N '' -C test@x -f /root/tk </dev/null
I="sh /src/install.sh --version v9.9.9 --sha256 $SUMS"
snap() { find /etc /usr/local /home -xdev -type f ! -name '*-' -exec sha256sum {} + 2>/dev/null | sort; getent passwd | sort; }
t() { printf '\n== %s\n' "$*"; }
snap > /tmp/s0
t "missing integrity pin"; sh /src/install.sh --version v9.9.9 --key-file /root/tk.pub 2>&1 | tail -n1
t "no version";  sh /src/install.sh --sha256 "$SUMS" --key-file /root/tk.pub 2>&1 | tail -n1
t "require-attestation without gh"; sh /src/install.sh --version v9.9.9 --require-attestation --key-file /root/tk.pub 2>&1 | tail -n1
t "wrong --sha256"; sh /src/install.sh --version v9.9.9 --sha256 "$(echo x | sha256sum | cut -c1-64)" --key-file /root/tk.pub 2>&1 | tail -n1
t "option-prefixed key"; $I --key 'command="/bin/sh" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA x' 2>&1 | tail -n1
t "junk key bytes (L-1)"; $I --key 'ssh-ed25519 AAAAAAAA junk' 2>&1 | tail -n1
t "tampered asset"; cp $REL/allowlist.yaml /tmp/al; echo '#x' >> $REL/allowlist.yaml; $I --key-file /root/tk.pub 2>&1 | tail -n1; cp /tmp/al $REL/allowlist.yaml
t "truncated script (M-1)"; head -c 4000 /src/install.sh | sh -s -- --version v9.9.9 --sha256 "$SUMS" --key-file /root/tk.pub; echo "rc=$?"
t "dry-run"; $I --dry-run --key-file /root/tk.pub 2>&1 | tail -n2
snap > /tmp/s1; cmp -s /tmp/s0 /tmp/s1 && echo "SNAPSHOT UNCHANGED after all failures + dry-run"
t "rollback (L-2): broken drop-in in release"; cp $REL/50-botaudit.conf /tmp/good; echo 'BogusDirective yes' >> $REL/50-botaudit.conf
(cd $REL && rm SHA256SUMS && sha256sum -- * > SHA256SUMS); S2=$(sha256sum $REL/SHA256SUMS | cut -d' ' -f1)
sh /src/install.sh --version v9.9.9 --sha256 "$S2" --key-file /root/tk.pub 2>&1 | tail -n3
snap > /tmp/s2; cmp -s /tmp/s0 /tmp/s2 && echo "SNAPSHOT UNCHANGED after rollback (binary/sudoers/user/shells/AcceptEnv)"; id botaudit 2>&1
cp /tmp/good $REL/50-botaudit.conf; (cd $REL && rm SHA256SUMS && sha256sum -- * > SHA256SUMS); SUMS=$(sha256sum $REL/SHA256SUMS | cut -d" " -f1); I="sh /src/install.sh --version v9.9.9 --sha256 $SUMS"
t "install"; $I --key-file /root/tk.pub --from 127.0.0.1 2>&1 | tail -n1
getent passwd botaudit; grep '^botaudit:' /etc/shadow | cut -d: -f2; getent group botaudit
stat -c '%U:%G %a %n' /usr/local/sbin/auditsh /etc/auditsh /etc/auditsh/allowlist.yaml /etc/ssh/authorized_keys /etc/ssh/authorized_keys/botaudit /etc/sudoers.d/botaudit /etc/ssh/sshd_config.d/50-botaudit.conf /home/botaudit
cut -c1-75 /etc/ssh/authorized_keys/botaudit; grep -n AcceptEnv /etc/ssh/sshd_config
/usr/sbin/sshd -T -C user=botaudit,host=x,addr=127.0.0.1 | grep -Ei '^(forcecommand|acceptenv|permittty|usepam|authorizedkeysfile)'
t "idempotent rerun (no key)"; snap > /tmp/s3; $I 2>&1 | tail -n1; snap > /tmp/s4; cmp -s /tmp/s3 /tmp/s4 && echo "STATE IDENTICAL"
t "e2e ssh"; /src/sl & sleep 0.3; /usr/sbin/sshd -o ListenAddress=127.0.0.1 -p 2222
O="-i /root/tk -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=error"
ssh $O botaudit@127.0.0.1 uptime; echo "rc=$?"; ssh $O botaudit@127.0.0.1 'sh -c id'; echo "rc=$?"; ssh $O -tt botaudit@127.0.0.1 </dev/null; echo "rc=$?"
pkill sshd; grep -o '"phase":"[a-z]*"\|"decision":"[a-z]*"\|"key_fp":"SHA256:[A-Za-z0-9]\{6\}' /tmp/syslog.txt | tr '\n' ' '; echo
t "uninstall"; sh /src/install.sh --uninstall 2>&1 | tail -n1; id botaudit 2>&1; ls -d /home/botaudit 2>&1
snap > /tmp/s5; diff /tmp/s0 /tmp/s5 && echo "SNAPSHOT IDENTICAL TO PRE-INSTALL (incl. AcceptEnv restored)"; grep -n AcceptEnv /etc/ssh/sshd_config; /usr/sbin/sshd -t && echo sshd-ok
