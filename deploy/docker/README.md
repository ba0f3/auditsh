# auditsh docker diagnostics (optional, manual install)

Read-only docker diagnostics for `botaudit`. **Not** installed by the deb/rpm or `install.sh`:
access to the docker socket is root-equivalent, so turning it on is a separate, explicit decision.

## Design

- `botaudit` is **never** added to group `docker`.
- auditsh's allowlist has `docker: true` rules (name `docker`). auditsh runs them as
  `sudo -n -- /usr/local/sbin/auditsh-docker <args>`.
- The sudoers drop-in grants exactly that helper path. Any argv reaches the helper, so the helper is
  the policy gate. It does not trust auditsh: `internal/dockerpolicy.Validate` re-checks argv against
  a fixed table and **builds** the docker argv itself.
- It runs `/usr/bin/docker` by absolute path. The path and its parents must be root-owned, not symlinks
  and not group/world-writable. There is no shell and stdin is `/dev/null`.
- The same check covers the CLI plugin dirs, `/usr/libexec/docker/cli-plugins` and `/usr/local/lib/docker/cli-plugins`,
  when they exist. Each dir, its parents and every entry must pass, because the CLI may exec plugins as root to read
  their metadata. If any of them fails, the helper refuses with exit 126.
- Concurrency cap: at most 2 runs at once. Each run takes a non-blocking `flock` on one of
  `/run/auditsh-docker.{0,1}.lock`. The lock files are root 0600, opened with O_NOFOLLOW, and must be regular
  files with a single link. When both are held, the helper exits 75 right away.
- The docker child gets `Pdeathsig=SIGKILL`, so it dies if the helper itself is killed.
- The child gets a complete, fixed environment: `DOCKER_HOST=unix:///var/run/docker.sock`,
  `DOCKER_CONFIG=/nonexistent/...` (so no config.json, contexts, credential helpers, aliases or
  proxies) and `PATH=/usr/bin:/bin`.
- Runs are bounded: a 12s timeout kills the process group (sudo's `command_timeout=15s` is the backstop).
  Text output is capped at 8 MiB and JSON at 16 MiB. Truncated JSON is never printed.
- Exit codes: 126 = refused (argv or an unsafe filesystem), 75 = busy, 124 = timeout. Any other code is docker's own.

| client types (via auditsh)                     | helper runs                                                         |
|------------------------------------------------|---------------------------------------------------------------------|
| `docker ps` / `docker ps -a`                   | `ps [-a] --format "table ID Image Status Names Ports"` (no Command) |
| `docker images`                                | `images --format "table Repository Tag ID CreatedSince Size"`       |
| `docker info`                                  | `info --format '{{json .}}'`, then proxies dropped and label values masked |
| `docker version`                               | `version`                                                           |
| `docker stats --no-stream`                     | `stats --no-stream --format "table Name CPU Mem Net Block PIDs"`    |
| `docker network ls` / `docker volume ls`       | same                                                                |
| `docker inspect NAME`                          | `container inspect -- NAME`, then the allowlist redaction below      |
| `docker network inspect NAME`                  | `network inspect -- NAME`, then redaction (label values masked)      |
| `docker logs --tail N [--since T] NAME`        | `logs --tail N [--since <unix>] -- NAME`; N is 1..1000, T is within the last 7d |
| `docker events --since T1 --until T2`          | `events --since <unix> --until <unix> --format '<time type action id name>'`; requires T1 < T2 <= now and a window <= 24h |

- **NAME** must match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`, so it can never start with `-`.
- **T** is unix seconds, RFC3339 or `<N>s|m|h` (ago). It is converted to unix seconds before docker sees it.
- **Refused:** everything else. That includes exec/run/cp/rm/kill/restart/pull/build/system prune,
  `-H`/`--host`, `--context`, `--config`, caller-supplied `-f`/`--format`, `-f`/`--follow` and
  `--details`. A caller env such as `DOCKER_HOST` is ignored: sudo resets it and the helper replaces it.
- **Container inspect redaction** is an allowlist. Unknown fields are dropped.
  - **Kept:** Id, Created, Path, State (with Health.Log removed), Image, Name, RestartCount, Driver,
    Platform, AppArmorProfile, Mounts (including sources), NetworkSettings and SizeRw/RootFs.
  - **HostConfig:** only its security/resource subset is kept, and LogConfig keeps `Type` only.
  - **Config:** only Hostname, User, Image, WorkingDir, ExposedPorts, Volumes, StopSignal, Tty and
    OpenStdin are kept, plus Labels with values masked.
  - **Never emitted:** Env, Cmd, Entrypoint, Args, Healthcheck, OnBuild and log-driver options.

## Install (on a host that already runs auditsh)

```sh
# 1. helper: from the release (verify SHA256SUMS + attestation first) or `go build ./cmd/auditsh-docker`
install -o root -g root -m 0755 auditsh-docker-linux-amd64 /usr/local/sbin/auditsh-docker
# 2. sudoers drop-in
install -o root -g root -m 0440 sudoers.botaudit-docker /etc/sudoers.d/botaudit-docker
visudo -cf /etc/sudoers.d/botaudit-docker && visudo -c
# 3. docker CLI must be at /usr/bin/docker (root-owned); daemon socket /var/run/docker.sock
# 4. allowlist: /etc/auditsh/allowlist.yaml from this release already has the docker rules
#    (they fail cleanly with "sudo: a password is required" until steps 1-2 are done)
# check:
sudo -u botaudit sudo -n /usr/local/sbin/auditsh-docker ps        # works
sudo -u botaudit sudo -n /usr/local/sbin/auditsh-docker exec x sh # exit 126
id botaudit                                                       # must NOT list group docker
```

To disable, remove `/etc/sudoers.d/botaudit-docker` (and optionally the helper).

## Alternative: a socket proxy

You can avoid giving any root helper the real socket. Run a filtering proxy such as
`tecnativa/docker-socket-proxy` (HAProxy) with `CONTAINERS=1 IMAGES=1 INFO=1 NETWORKS=1 VOLUMES=1 EVENTS=1 POST=0`
and point the helper's `DOCKER_HOST` at it.

That moves the read-only enforcement into the proxy. It is **not** a replacement for the redaction:
`GET /containers/{id}/json` still returns Env. Exec also needs `EXEC=0` and `POST=0`.

This is documentation only. auditsh does not ship or configure a proxy.
