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
Not available: less, more, vi, find, tar, awk, sed, sh, bash, env, xargs, tee, python, git, or anything else on GTFOBins.
**pmap was dropped.** It needs a PID under sudo, and fixed-argv sudoers can't express that (see design.md §4).
Use `cat /proc/<pid>/smaps_rollup` instead.

## Reproducible build
The toolchain is pinned to go1.27.3 (the `toolchain` line in go.mod). Run `make build` (`./build.sh [rev]`):
it clones the repo into a temp dir, checks out the commit, and builds with
`GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath` (no `-s -w`, no strip) into `dist/auditsh`.
It then prints the `vcs.revision`/`vcs.modified` values from `go version -m` and the sha256.
Two builds of the same commit give identical hashes.

## Install (as root)
```sh
make build
install -o root -g root -m 0755 dist/auditsh /usr/local/sbin/auditsh
grep -qx /usr/local/sbin/auditsh /etc/shells || echo /usr/local/sbin/auditsh >> /etc/shells
install -d -o root -g root -m 0755 /etc/auditsh
install -o root -g root -m 0644 allowlist.yaml /etc/auditsh/allowlist.yaml
useradd --system --create-home --home-dir /home/botaudit --shell /usr/local/sbin/auditsh botaudit
passwd -l botaudit                       # no password, locked
chown root:root /home/botaudit && chmod 0755 /home/botaudit
install -d -o root -g root -m 0755 /etc/ssh/authorized_keys
install -o root -g root -m 0644 deploy/authorized_keys/botaudit /etc/ssh/authorized_keys/botaudit   # put the real key in
install -o root -g root -m 0440 deploy/sudoers.botaudit /etc/sudoers.d/botaudit && visudo -cf /etc/sudoers.d/botaudit
echo botaudit >> /etc/cron.deny; echo botaudit >> /etc/at.deny
install -o root -g root -m 0644 deploy/sshd_config.d/50-botaudit.conf /etc/ssh/sshd_config.d/50-botaudit.conf
sshd -t && sshd -T -C user=botaudit,host=x,addr=192.0.2.10 | grep -i forcecommand && systemctl reload ssh
mount -o remount,hidepid=2 /proc   # recommended, see below; persist in /etc/fstab
# optional: route local7 to a root-only file, e.g. rsyslog: local7.* /var/log/auditsh.log
```
If `PermitUserEnvironment` is set to anything other than `no`, set it back to `no` globally.
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
- Kernel or sshd bugs are out of scope.
