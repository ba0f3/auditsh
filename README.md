# auditsh

sshd `ForceCommand` that lets AI agents audit a Linux server over SSH **read-only**.
The `botaudit` account can run only the exact argv forms in `/etc/auditsh/allowlist.yaml`.

## How it works
1. Reads `SSH_ORIGINAL_COMMAND`. Empty: prints the allowed forms and exits 126. There is never a shell.
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
   Before exec, the binary has to be root-owned and not group- or world-writable.
   `sudo: true` rules run `/usr/bin/sudo -n -- <abs path> <args>`.
5. `cat` is not executed. auditsh reads `/proc/meminfo`, `/proc/<pid>/status` and `/proc/<pid>/smaps_rollup` itself.
   The pid must be numeric, so `self` and `..` are rejected. The realpath has to equal the requested path,
   the file is opened with `O_NOFOLLOW`, and there is a hard denylist (shadow, gshadow, `*.key`, `.env`, `/root`, `/etc/ssh/*key*`).
6. Each call writes one JSON line to syslog (facility `local7`, tag `auditsh`). Fields: `ts, user, client_ip, ssh_conn, key_fp,
   raw` (Go-quoted, capped at 512 bytes), `argv, decision, rule|reason, exit, duration_ms, bytes, truncated, timed_out`.
   `key_fp` comes from sshd `ExposeAuthInfo`. If syslog is down, auditsh fails closed (exit 125).
7. The config path is compiled in (`/etc/auditsh/allowlist.yaml`). The file and its directory have to be root-owned,
   not symlinks, and not group- or world-writable. If any of that fails, every command is denied.

## Default commands
`ps aux | ps -eo <fmt> [--sort=-rss|--sort=-%mem]` (fmt from pid,ppid,user,rss,vsz,%mem,%cpu,comm,etime,stat,nlwp),
`top -b -n1`, `free [-m|-h]`, `df [-h]`, `uptime`, `cat /proc/meminfo|/proc/<pid>/status|/proc/<pid>/smaps_rollup`,
`systemctl status <unit> --no-pager`, `journalctl -u <unit> --since <today|yesterday|N h ago|YYYY-MM-DD[ HH:MM[:SS]]> --no-pager [-n N]`,
sudo: `ss -tlnp`, `ss -ulnp`, `dmesg -T [--level=err|err,warn|emerg,alert,crit,err,warn]`.
Not available: less, more, vi, find, tar, awk, sed, sh, bash, env, xargs, tee, python, git, or anything else on GTFOBins.
**pmap was dropped.** It needs a PID under sudo, and fixed-argv sudoers can't express that (see design.md §4).
Use `cat /proc/<pid>/smaps_rollup` instead.

## Install (as root)
```sh
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o auditsh .
install -o root -g root -m 0755 auditsh /usr/local/sbin/auditsh
install -d -o root -g root -m 0755 /etc/auditsh
install -o root -g root -m 0644 allowlist.yaml /etc/auditsh/allowlist.yaml
useradd --system --create-home --home-dir /home/botaudit --shell /bin/sh botaudit
passwd -l botaudit                       # no password, locked
chown root:root /home/botaudit && chmod 0755 /home/botaudit
install -d -o root -g root -m 0755 /home/botaudit/.ssh
install -o root -g root -m 0644 deploy/authorized_keys.example /home/botaudit/.ssh/authorized_keys   # put the real key in
install -o root -g root -m 0440 deploy/sudoers.botaudit /etc/sudoers.d/botaudit && visudo -cf /etc/sudoers.d/botaudit
echo botaudit >> /etc/cron.deny; echo botaudit >> /etc/at.deny
cat deploy/sshd_config.snippet >> /etc/ssh/sshd_config && sshd -t && systemctl reload ssh
# optional: route local7 to a root-only file, e.g. rsyslog: local7.* /var/log/auditsh.log
```
If `PermitUserEnvironment` is set to anything other than `no`, set it back to `no` globally.
## Uninstall
```sh
rm /etc/sudoers.d/botaudit /usr/local/sbin/auditsh; rm -r /etc/auditsh
# remove the Match User botaudit block from sshd_config; sshd -t && systemctl reload ssh
pkill -u botaudit; userdel -r botaudit; sed -i '/^botaudit$/d' /etc/cron.deny /etc/at.deny
```

## Threat model
- Attacker: whoever holds the agent key, or a prompt-injected agent. The goal is that they can't write, exec arbitrary code, pivot, or keep access.
- Login shell: sshd runs ForceCommand through the user's shell (`$SHELL -c ...`), so a real shell (`/bin/sh`) is
  needed. `nologin` would break ForceCommand. The shell only ever gets the fixed ForceCommand string.
  The client command arrives only through `SSH_ORIGINAL_COMMAND`. `PermitUserRC no` and root-owned `~/.ssh` stop `~/.ssh/rc`,
  `environment`, and changes to authorized_keys.
- The home directory and `~/.ssh` are root-owned and the account has no password, so it can't write dotfiles or keys. cron and at are denied.
- Binary: root 0755. Config: root 0644 in a root 0755 dir. Both are checked at runtime.
- sshd: no TTY, all forwarding off, publickey only, low `MaxSessions`, client-alive timeouts.
  In authorized_keys, `restrict,command=` is a second layer in case the Match block gets removed.
- sudo: fixed argv only, no wildcards or regex, `NOEXEC`, `env_reset`, `!setenv`, `secure_path`, `log_output`.
  No sudo 1.9.10 features are used, so older sudo works too.

## Residual risks and limits
- **Information disclosure is in scope by design.** `ps aux` shows full command lines, journald, dmesg and systemctl status show logs,
  and `ss -p` shows process names. Any of these can include secrets that leaked into argv or logs. Treat agent output as sensitive.
- `/proc/<pid>/smaps_rollup` for other users' processes needs ptrace rights, so as `botaudit` it only works on its own processes
  (status works for all). This is a deliberate choice: no sudo for pid args.
- Running `systemctl status` and `journalctl` as non-root only shows what the user can see. Add `botaudit` to `systemd-journal`
  if you want full journal access (more disclosure).
- The binary paths assume usrmerge (`/usr/bin/ss`). On RHEL, ss lives in `/usr/sbin/ss`. Edit allowlist.yaml and sudoers to match.
- Load and DoS: each session runs one command, capped at 15 s and 1 MiB. sshd `MaxStartups`/`MaxSessions` limit concurrency.
- The timeout kills the process group. A sudo child runs as root, and sudo relays the kill to it.
- Kernel or sshd bugs are out of scope.
