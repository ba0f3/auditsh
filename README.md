# auditsh

sshd `ForceCommand` that lets AI agents audit a Linux server over SSH **read-only**.
The `botaudit` account can run only the exact argv forms in `/etc/auditsh/allowlist.yaml`.

## How it works
1. auditsh is the login shell of `botaudit` as well as the ForceCommand, so sshd always runs
   `auditsh -c <string>`. The invocation is resolved as follows:
   - `-c /usr/local/sbin/auditsh` (the ForceCommand or `command=` path): the client command is `SSH_ORIGINAL_COMMAND`.
   - `-c X` with any other X (no ForceCommand applied, e.g. the Match block was lost): X is the client command.
     If `SSH_ORIGINAL_COMMAND` is also set, it has to equal X, otherwise the call is denied.
   - Any other argv (no args, meaning an interactive login; extra args; other flags) is denied and logged.
   An empty command prints the allowed forms and exits 126. There is never a shell.
2. Rejects anything over 1024 bytes, more than 16 args, any byte outside printable ASCII
   (NUL, newline, tabs, controls, all unicode), and any of ``;&|`$<>(){}*?[]!~\#``. Then splits with
   `google/shlex` (quotes only, no expansion). Rejects empty args and `--`.
3. Matches against rules: same name, same arity, each arg matched against `^(?:pattern)$`.
   Args that start with `-` only match a pattern that is a plain literal equal to the arg.
   Optional args are written as extra rules with the same name.
4. Runs the absolute binary with `exec.Command` (no PATH lookup, no `sh -c`), a clean env
   (`PATH=/usr/bin:/bin LANG=C LC_ALL=C PAGER=cat SYSTEMD_PAGER= SYSTEMD_LESS= LESSSECURE=1 SYSTEMD_COLORS=0`, no TERM),
   stdin `/dev/null`, its own process group, a 15 s timeout (SIGKILL to the group), and a 1 MiB
   cap on stdout+stderr combined. When the cap is hit the output is truncated, a note goes to stderr, and the command is killed.
   Before exec, the binary (and `/usr/bin/sudo` for sudo rules) and every parent directory have to be
   root-owned, not symlinks, and not group- or world-writable.
   `sudo: true` rules run `/usr/bin/sudo -n -- <abs path> <args>`.
5. `cat` is not executed. auditsh reads `/proc/meminfo`, `/proc/<pid>/status` and `/proc/<pid>/smaps_rollup` itself.
   The pid must be numeric, so `self` and `..` are rejected. The realpath has to equal the requested path,
   the file is opened with `O_NOFOLLOW`, and there is a hard denylist (shadow, gshadow, `*.key`, `.env`, `/root`, `/etc/ssh/*key*`).
6. A denial writes one `phase:"deny"` record. An allowed command writes a `phase:"start"` record
   **before** exec. If syslog rejects it, nothing runs (exit 125). After the command finishes, is
   killed, or times out, a `phase:"end"` record follows. SIGHUP/SIGPIPE are handled, not ignored,
   so a client disconnect doesn't kill auditsh before the end record. Each record is a JSON line to syslog (facility `local7`, tag `auditsh`). Fields: `ts, user, client_ip, ssh_conn, key_fp,
   raw` (Go-quoted, capped at 512 bytes), `argv, decision, rule|reason, exit, duration_ms, bytes, truncated, timed_out`.
   `key_fp` comes from sshd `ExposeAuthInfo`.
7. The config path is compiled in (`/etc/auditsh/allowlist.yaml`). The file and every parent directory have to be root-owned,
   not symlinks, and not group- or world-writable. If any of that fails, every command is denied.

## Default commands
`ps aux | ps -eo <fmt> [--sort=-rss|--sort=-%mem]` (fmt from pid,ppid,user,rss,vsz,%mem,%cpu,comm,etime,stat,nlwp),
`top -b -n1`, `free [-m|-h]`, `df [-h]`, `uptime`, `cat /proc/meminfo|/proc/<pid>/status|/proc/<pid>/smaps_rollup`,
`systemctl status <unit> --no-pager`, `journalctl -u <unit> --since <today|yesterday|N h ago|YYYY-MM-DD[ HH:MM[:SS]]> --no-pager [-n N]`,
sudo: `ss -tlnp`, `ss -ulnp`, `dmesg -T [--level=err|err,warn|emerg,alert,crit,err,warn]`.
JVM (as the JVM's user, needs `--java-user`): `jcmd`/`jstat` forms, see [Java/JVM diagnostics](#javajvm-diagnostics-opt-in-per-java-user).
Not available: less, more, vi, find, tar, awk, sed, sh, bash, env, xargs, tee, python, git, or anything else on GTFOBins.
**pmap was dropped.** It needs a PID under sudo, and fixed-argv sudoers can't express that (see design.md §4).
Use `cat /proc/<pid>/smaps_rollup` instead.

## Java/JVM diagnostics (opt-in per Java user)
Forms (block `BEGIN Java/JVM diagnostics` in allowlist.yaml): `jcmd <pid> GC.heap_info|Thread.print|VM.flags|VM.uptime|VM.version`,
`jcmd <pid> VM.native_memory summary` (needs `-XX:NativeMemoryTracking=summary` on the JVM), `jstat -gcutil <pid> [<100..1000 ms> <1..10>]`.
`GC.class_histogram` is shipped **commented out**: it forces a full, stop-the-world GC (seconds on big heaps). Uncomment it to opt in.
Never allowed, in the allowlist **and** in the helper's own table: `GC.heap_dump`, `JFR.*`, `VM.command_line` and
`VM.system_properties` (often contain secrets), `VM.set_flag`, `ManagementAgent.*`, `Compiler.*`, `JVMTI.agent_load`, `System.*`, `help`, `-J...`.

Enable: `auditsh-setup --local --java-user app [--java-user app2]` (or `install.sh ... --java-user app`). Each name must match
`^[a-z_][a-z0-9_-]{0,31}$`, exist, and not be root/uid 0/botaudit. This writes `/etc/sudoers.d/botaudit-jvm` (0440, generated, not
package-owned, removed on uninstall/package removal):
```
botaudit ALL=(app,app2) NOPASSWD: /usr/local/sbin/auditsh-jvm
```
Rerunning without `--java-user` keeps the existing file; to revoke, `rm /etc/sudoers.d/botaudit-jvm`.

**Privilege design.** HotSpot attach (jcmd) and hsperfdata (jstat) work only as the JVM's own uid, and the pid is a variable.
Rejected options:
- `jcmd [0-9]* GC.heap_info` in sudoers: sudoers `*` matches spaces, so `jcmd 1 GC.heap_dump /x GC.heap_info` passes.
- A root helper (`ALL=(root) auditsh-jvm *`): any helper bug becomes root.
- Granting jcmd itself as the Java user: jcmd takes any diagnostic command.

Chosen: sudo may only run one fixed program, `/usr/local/sbin/auditsh-jvm` (root:root 0755, ~60 lines of POSIX sh), and only **as a
configured, non-root Java user**, never as root. Sudoers cannot constrain its args without a wildcard, so the helper is the argv gate:
1. auditsh: the client argv matches a `jvm: true` rule (exactly one pid arg `[1-9][0-9]{0,9}`), then auditsh reads
   `/proc/<pid>/status`, requires `Name: java` and one non-root uid (real=effective=saved=fs), maps it to a user name and
   runs `/usr/bin/sudo -n -u <user> -- /usr/local/sbin/auditsh-jvm <jcmd|jstat> <args>` (same timeout, 1 MiB cap, clean env, audit log).
2. sudo refuses users not listed by `--java-user`.
3. The helper, as that user: refuses root; fixed table of forms (anything else exits 126); pid digits only; `/proc/<pid>/status`
   uids all equal its own uid; `/proc/<pid>/exe` is `/…/bin/java` (a deleted/replaced binary is refused); that `java` and the
   sibling `jcmd`/`jstat`, plus every parent dir, are root-owned, not symlinks, not group/world-writable; then
   `exec env -i PATH=/usr/bin:/bin LC_ALL=C <jdk>/bin/<tool> <validated args>`. The tool comes from the target JVM's own JDK
   (version-matched, never from PATH or the caller). A JRE without `jcmd`/`jstat`, or a JDK owned by the app user, is refused.

Not `NOEXEC`: the helper has to exec jcmd. Worst case for a helper bug is code running as the Java user, not root.

Caveats: jcmd's attach creates `.attach_pid<pid>` in the JVM's cwd or /tmp and sends SIGQUIT (that's why the exe must be java;
a JVM started with `-XX:+DisableAttachMechanism` or `-Xrs` will not answer). jcmd/jstat also write their own
`/tmp/hsperfdata_<user>/<pid>` while running. Thread dumps may show stack frames with app data in thread names. Pid reuse
between the check and the attach is possible but the new process must also be a java process of the same user. With
`hidepid=2`, botaudit cannot read other users' `/proc/<pid>/status`, so JVM rules are denied ("pid not visible") unless botaudit is in
the hidepid `gid=` group. User lookup is `/etc/passwd` only (static binary), so LDAP/SSSD-only Java users are not supported. JVMs in
containers (other pid/mount namespace) are out of scope.

## Reproducible build
The toolchain is pinned to go1.27.3 (the `toolchain` line in go.mod). Run `make build` (`./build.sh [rev]`):
it clones the repo into a temp dir, checks out the commit, and builds with
`GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath` (no `-s -w`, no strip) into `dist/auditsh`.
It then prints the `vcs.revision`/`vcs.modified` values from `go version -m` and the sha256.
Two builds of the same commit give identical hashes.

## Quick install (release binary, as root)
Releases (`v*` tags) are built by `.github/workflows/release.yml`: a read-only `build` job runs `build.sh` twice per arch
(linux/amd64, linux/arm64; go1.27.3 from a sha256-pinned tarball, `-trimpath`, CGO off) and compares the results. A separate `attest`
job adds GitHub build provenance, and a `publish` job (the only one with `contents: write`) creates the release with
`auditsh-linux-<arch>`, `auditsh-jvm`, `allowlist.yaml`, `50-botaudit.conf`, `sudoers.botaudit`, `install.sh` and `SHA256SUMS`.
**Maintainers:** protect tags with a repository ruleset on `refs/tags/v*` (restrict creation to maintainers, block update and deletion).

`install.sh` never installs "latest". It requires `--version` plus at least one trust anchor that does not come from the release itself:
- `--sha256 <sha256 of SHA256SUMS>`, published out of band (for example a signed announcement, or your own reproducible `build.sh` run), and/or
- `--require-attestation`: an authenticated `gh` must verify the provenance. If gh is missing, the install fails.

Every asset is then checked against SHA256SUMS. Key lines are checked with `ssh-keygen -lf` and get
`restrict,command="/usr/local/sbin/auditsh"` (plus `,from=` with `--from`). Before writing anything it validates sudoers (`visudo -cf`) and the existing sshd
config (`sshd -t`). After writing it checks `sshd -t`/`sshd -T`. On any failure it rolls back every file it touched and removes a user it created.
botaudit gets the fixed uid/gid 990 (`--uid N` to change). The installer is idempotent and supports `--dry-run`/`--uninstall`. Uninstall also
restores the `AcceptEnv` lines the installer commented out (marked `# auditsh-disabled:`).

Recommended (download, verify, read, then run):
```sh
V=vX.Y.Z; SUMS_SHA=<sha256 of SHA256SUMS, from a trusted channel>
curl --proto '=https' --tlsv1.2 -fsSLO https://github.com/ba0f3/auditsh/releases/download/$V/install.sh
curl --proto '=https' --tlsv1.2 -fsSLO https://github.com/ba0f3/auditsh/releases/download/$V/SHA256SUMS
echo "$SUMS_SHA  SHA256SUMS" | sha256sum -c - && sha256sum -c --ignore-missing SHA256SUMS
less install.sh
sudo sh install.sh --version "$V" --sha256 "$SUMS_SHA" --key 'ssh-ed25519 AAAA... agent@example' --from 192.0.2.10
```
One line (the script body is wrapped in `main`, so a truncated download runs nothing; still pin both values):
```sh
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/ba0f3/auditsh/releases/download/vX.Y.Z/install.sh | sudo sh -s -- --version vX.Y.Z --sha256 <sha256 of SHA256SUMS> --key 'ssh-ed25519 AAAA... agent@example'
```
`tests/chroot-test.sh` exercises the installer in a throwaway Debian chroot against a fake local release (it replaces curl there). Never run it on a real host.

## Packages (deb/rpm, as root)

Releases also carry `auditsh_<ver>-1_{amd64,arm64}.deb` and `auditsh-<ver>-1.{x86_64,aarch64}.rpm`, listed in
`SHA256SUMS` and covered by the build attestation. Verify them the same way as the binary
(`sha256sum -c --ignore-missing SHA256SUMS` after checking the SHA256SUMS hash, or `gh attestation verify`).
Build them locally with `./pkg.sh [rev]`: reproducible binaries from `build.sh`, nfpm pinned with a
sha256-checked tarball, `SOURCE_DATE_EPOCH` = commit time, so a rebuild is byte-identical.

Installing the package does **not** open SSH access. It installs:

| path | notes |
|---|---|
| `/usr/local/sbin/auditsh` | 0755 root (same path as ForceCommand, login shell, key `command=`) |
| `/etc/auditsh/allowlist.yaml` | config, noreplace (local edits kept on upgrade) |
| `/etc/sudoers.d/botaudit` | 0440, package-owned (replaced on upgrade, removed on remove) |
| `/usr/share/auditsh/50-botaudit.conf` | sshd drop-in, shipped **disabled** |
| `/usr/sbin/auditsh-setup` | this repo's `install.sh` |
| `/usr/local/sbin/auditsh-jvm` | 0755 root, JVM helper (unused until `--java-user`) |

The postinst runs `auditsh-setup --account-only`: user/group `botaudit` uid/gid 990, shell auditsh (added to
`/etc/shells`), locked password, root-owned home, cron/at deny. Then `visudo -c`; if that fails, the sudoers
file is removed and the postinst fails. To enable access:

```sh
apt install ./auditsh_X.Y.Z-1_amd64.deb        # or: dnf install ./auditsh-X.Y.Z-1.x86_64.rpm
auditsh-setup --local --key 'ssh-ed25519 AAAA... agent@x' [--from 192.0.2.10] [--dry-run]
```

`--local` uses the packaged files (no download). It installs the key and the drop-in, comments out
AcceptEnv, runs the `sshd -t`/`sshd -T` checks and reloads sshd. On any failure it rolls back.
`apt remove` / `dpkg -r` / `rpm -e` (not upgrade) runs `auditsh-setup --uninstall --package` first. That
removes the drop-in, the keys and the user, restores AcceptEnv and cleans `/etc/shells` and cron/at deny.
`dpkg --purge` also drops the allowlist. The package refuses to install (preinst/%pre, before
any file is placed) if uid/gid 990 belong to someone other than `botaudit`. After an upgrade, if you had
edited `/etc/auditsh/allowlist.yaml`, your copy is kept and the new default is written beside it as
`allowlist.yaml.dpkg-dist` (deb) or `allowlist.yaml.rpmnew` (rpm): diff and merge it by hand, then
delete it. Sudoers is always replaced by the packaged rules. On RHEL-family systems `ss` is `/usr/sbin/ss`, so the rpm ships
sudoers and allowlist with `/usr/sbin/ss`; the deb keeps Debian's `/usr/bin/ss`. Tested in chroots
(Debian 13, Rocky 9.8) with `tests/pkg-test.sh`.

## Install (manual, as root)
```sh
make build
install -o root -g root -m 0755 dist/auditsh /usr/local/sbin/auditsh
grep -qx /usr/local/sbin/auditsh /etc/shells || echo /usr/local/sbin/auditsh >> /etc/shells
install -d -o root -g root -m 0755 /etc/auditsh
install -o root -g root -m 0644 allowlist.yaml /etc/auditsh/allowlist.yaml
useradd --system --create-home --home-dir /home/botaudit --shell /usr/local/sbin/auditsh botaudit
usermod -L botaudit                      # = passwd -l: shadow "!" (locked), see "Account lock" below
chown root:root /home/botaudit && chmod 0755 /home/botaudit
install -d -o root -g root -m 0755 /etc/ssh/authorized_keys
install -o root -g root -m 0644 deploy/authorized_keys/botaudit /etc/ssh/authorized_keys/botaudit   # put the real key in
install -o root -g root -m 0440 deploy/sudoers.botaudit /etc/sudoers.d/botaudit && visudo -cf /etc/sudoers.d/botaudit
echo botaudit >> /etc/cron.deny; echo botaudit >> /etc/at.deny
sed -i 's/^\s*AcceptEnv/# &/' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf   # no AcceptEnv at all
install -o root -g root -m 0644 deploy/sshd_config.d/50-botaudit.conf /etc/ssh/sshd_config.d/50-botaudit.conf
sshd -t && sshd -T -C user=botaudit,host=x,addr=192.0.2.10 | grep -i forcecommand && systemctl reload ssh
mount -o remount,hidepid=2 /proc   # recommended, see below; persist in /etc/fstab
# optional: route local7 to a root-only file, e.g. rsyslog: local7.* /var/log/auditsh.log
```
If `PermitUserEnvironment` is set to anything other than `no`, set it back to `no` globally.
## Key lines
Every line in `/etc/ssh/authorized_keys/botaudit` **must** start with
`restrict,command="/usr/local/sbin/auditsh"` (optionally `,from="..."`). Without `command=`, losing the
Match block would let `Subsystem sftp internal-sftp` bypass auditsh. Alert on any key line that lacks it:
`grep -v '^#' /etc/ssh/authorized_keys/botaudit | grep -v '^restrict,command="/usr/local/sbin/auditsh"'` must print nothing.

## Account lock (verify on staging)
Tested target config: `UsePAM yes` (Debian default) with the account locked by `usermod -L` / `passwd -l`
(shadow `!`). Under `UsePAM yes`, sshd still allows publickey for a `!` account. With `UsePAM no`,
sshd treats `!` as locked and also refuses publickey. In that case, use `usermod -p '*' botaudit`
(`*` = no valid password, but not "locked"). Check: `ssh -i key botaudit@host uptime` works and password login fails.

## Uninstall
```sh
rm /etc/ssh/sshd_config.d/50-botaudit.conf /etc/ssh/authorized_keys/botaudit && sshd -t && systemctl reload ssh
pkill -u botaudit; userdel -r botaudit
rm /etc/sudoers.d/botaudit /usr/local/sbin/auditsh; rm -r /etc/auditsh
sed -i '\#^/usr/local/sbin/auditsh$#d' /etc/shells; sed -i '/^botaudit$/d' /etc/cron.deny /etc/at.deny
```

## Threat model
- Attacker: whoever holds the agent key, or a prompt-injected agent. The goal is that they can't write, exec arbitrary code, pivot, or keep access.
- Login shell = auditsh, listed in /etc/shells. sshd runs every command as `$SHELL -c ...`, so even
  with the Match block or `command=` lost, the user only ever reaches auditsh and never a real shell
  (`nologin` would break ForceCommand). `PermitUserRC no` and keys in root-owned `/etc/ssh/authorized_keys/`
  block `~/.ssh/rc`, `environment`, and key changes.
- The home directory and `~/.ssh` are root-owned and the account has no password, so it can't write dotfiles or keys. cron and at are denied.
- Binary: root 0755. Config: root 0644 in a root 0755 dir. Both are checked at runtime.
- sshd: no TTY, all forwarding off, publickey only, low `MaxSessions`, client-alive timeouts.
  In authorized_keys, `restrict,command=` is a second layer in case the Match block gets removed.
- sudo: fixed argv only, no wildcards or regex, `NOEXEC`, `env_reset`, `!setenv`, `secure_path`, `log_output`,
  `command_timeout=15s`. With `log_output`, sudo runs the command on its own pty/session as root, so
  auditsh's group kill can't reach it. `command_timeout` and auditsh's WaitDelay bound it instead.
  No sudo 1.9.10 features are used, so older sudo works too.

## Residual risks and limits
- **Information disclosure is in scope by design.** `ps aux` shows full command lines, journald, dmesg and systemctl status show logs,
  and `ss -p` shows process names. Any of these can include secrets that leaked into argv or logs. Treat agent output as sensitive.
- `/proc/<pid>/status` can be read for **every** pid (name, uids, memory) unless /proc is mounted with
  `hidepid=2` (on newer kernels, `hidepid=invisible`). That mount is recommended, but it hides processes from
  `ps`/`top` for botaudit too, which weakens the audit. Exempt botaudit with `gid=<group>` if you want full visibility.
  hidepid can also break some services (polkit, systemd-logind on older systems), so test it first.
- `/proc/<pid>/smaps_rollup` for other users' processes needs ptrace rights, so as `botaudit` it only works on its own processes
  (status works for all). This is a deliberate choice: no sudo for pid args.
- Running `systemctl status` and `journalctl` as non-root only shows what the user can see. Add `botaudit` to `systemd-journal`
  if you want full journal access (more disclosure).
- The binary paths assume usrmerge (`/usr/bin/ss`). On RHEL, ss lives in `/usr/sbin/ss`. Edit allowlist.yaml and sudoers to match.
- Load and DoS: each session runs one command, capped at 15 s and 1 MiB. sshd `MaxStartups`/`MaxSessions` limit concurrency.
- The timeout kills the process group. A sudo child runs as root, and sudo relays the kill to it.
- Attribution: when `SSH_CONNECTION` is set but the key fingerprint can't be read (ExposeAuthInfo file
  missing, empty or unparseable), auditsh denies with reason `no key_fp`. sshd deletes that file at session
  teardown, so a client that disconnects at once (e.g. `ssh -tt` with the PTY refused) can lose the race.
  auditsh now reads the file first thing in main, and the deny holds regardless.
- setsid'd descendants can outlive the timeout (none of the allowlisted binaries do this). A future option is
  to run each command in a transient cgroup (`systemd-run --scope -p RuntimeMaxSec=20`); it isn't done
  now because it adds a systemd dependency and privileges. On revocation, `pkill -u botaudit`.
- Kernel or sshd bugs are out of scope.
