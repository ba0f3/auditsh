#!/bin/sh
# install.sh: install/upgrade/uninstall auditsh + the botaudit account on a Linux host (run as root).
# Mirrors the README "Install (as root)" steps. Idempotent: re-running converges to the same state.
#
#   sh install.sh --key 'ssh-ed25519 AAAA... agent@x' [--from 192.0.2.10] [--version v1.2.3]
#   sh install.sh --key-file /path/agent.pub
#   sh install.sh --uninstall
#   sh install.sh --dry-run ...      (download + verify, print what would change, touch nothing)
#
# Env: AUDITSH_VERSION (tag, default: latest release), AUDITSH_KEY, AUDITSH_KEY_FILE, AUDITSH_FROM,
#      AUDITSH_REQUIRE_ATTESTATION=1 (fail unless `gh attestation verify` succeeds),
#      AUDITSH_LOCAL_BIN + AUDITSH_SRC_DIR (testing only: use a local binary and repo checkout,
#      skips download and checksum).
set -eu
umask 022

REPO=ba0f3/auditsh
BIN=/usr/local/sbin/auditsh
CONF_DIR=/etc/auditsh
KEYS_DIR=/etc/ssh/authorized_keys
KEYS_FILE=$KEYS_DIR/botaudit
SSHD_DROPIN=/etc/ssh/sshd_config.d/50-botaudit.conf
SUDOERS=/etc/sudoers.d/botaudit
USER_NAME=botaudit
HOME_DIR=/home/botaudit

VERSION=${AUDITSH_VERSION:-}
KEY=${AUDITSH_KEY:-}
KEY_FILE=${AUDITSH_KEY_FILE:-}
FROM=${AUDITSH_FROM:-}
REQ_ATTEST=${AUDITSH_REQUIRE_ATTESTATION:-0}
DRY=0
MODE=install

say()  { printf '%s\n' "auditsh-install: $*" >&2; }
warn() { printf '%s\n' "auditsh-install: WARNING: $*" >&2; }
die()  { printf '%s\n' "auditsh-install: ERROR: $*" >&2; exit 1; }
# run: execute, or only print in --dry-run. Never pass key material through run (it is printed).
run() { if [ "$DRY" = 1 ]; then say "would run: $*"; else "$@"; fi; }

usage() { sed -n '2,15p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case $1 in
    --key) [ $# -ge 2 ] || die "--key needs a value"; KEY=$2; shift 2 ;;
    --key-file) [ $# -ge 2 ] || die "--key-file needs a value"; KEY_FILE=$2; shift 2 ;;
    --from) [ $# -ge 2 ] || die "--from needs a value"; FROM=$2; shift 2 ;;
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION=$2; shift 2 ;;
    --require-attestation) REQ_ATTEST=1; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[ "$(uname -s)" = Linux ] || die "Linux only"
if [ "$(id -u)" != 0 ]; then
  if [ "$DRY" = 1 ]; then warn "not root: dry-run only"; else die "must run as root"; fi
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT INT TERM

reload_sshd() {
  if [ "$DRY" = 1 ]; then say "would reload sshd"; return 0; fi
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd || die "sshd reload failed"
  elif command -v service >/dev/null 2>&1 && service ssh reload >/dev/null 2>&1; then :
  else warn "could not reload sshd automatically; reload it yourself"; fi
}

sshd_bin() { command -v sshd 2>/dev/null || { [ -x /usr/sbin/sshd ] && echo /usr/sbin/sshd; } || die "sshd not found"; }

# ---------------------------------------------------------------- uninstall
if [ "$MODE" = uninstall ]; then
  SSHD=$(sshd_bin)
  run rm -f "$SSHD_DROPIN" "$KEYS_FILE"
  [ "$DRY" = 1 ] || "$SSHD" -t || die "sshd -t failed after removing drop-in; fix sshd_config"
  reload_sshd
  if id "$USER_NAME" >/dev/null 2>&1; then
    run pkill -KILL -u "$USER_NAME" || true
    run userdel -r "$USER_NAME" 2>/dev/null || true   # nonzero if e.g. no mail spool
    if [ "$DRY" = 0 ] && id "$USER_NAME" >/dev/null 2>&1; then die "userdel $USER_NAME failed"; fi
  fi
  run rm -f "$SUDOERS" "$BIN"
  run rm -rf "$CONF_DIR"
  [ -f /etc/shells ] && run sed -i '\#^/usr/local/sbin/auditsh$#d' /etc/shells
  for f in /etc/cron.deny /etc/at.deny; do [ -f "$f" ] && run sed -i '/^botaudit$/d' "$f"; done
  say "uninstalled"
  exit 0
fi

# ---------------------------------------------------------------- key lines
# Each accepted line becomes: restrict,command="/usr/local/sbin/auditsh"[,from="..."] <type> <base64> [comment]
# Input must be a bare public key (no options); anything else is rejected.
[ -n "$FROM" ] && { printf '%s' "$FROM" | grep -Eq '^[0-9A-Za-z.:/*?!,-]+$' || die "--from has invalid characters"; }
KEYS_OUT=$TMP/authorized_keys
: > "$KEYS_OUT"
if [ -n "$KEY_FILE" ]; then [ -r "$KEY_FILE" ] || die "cannot read key file"; cat -- "$KEY_FILE" > "$TMP/keys.in"
else printf '%s\n' "$KEY" > "$TMP/keys.in"; fi
opts='restrict,command="/usr/local/sbin/auditsh"'
[ -n "$FROM" ] && opts="$opts,from=\"$FROM\""
n=0
while IFS= read -r line || [ -n "$line" ]; do
  case $line in ''|'#'*) continue ;; esac
  printf '%s' "$line" | LC_ALL=C grep -Eq '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+={0,3}( [ -~]*)?$' \
    || die "key line $((n+1)) is not a bare OpenSSH public key (no options, single line)"
  case $line in *'"'*|*\\*) die "key comment must not contain quotes or backslashes" ;; esac
  printf '%s %s\n' "$opts" "$line" >> "$KEYS_OUT"; n=$((n+1))
done < "$TMP/keys.in"
if [ "$n" = 0 ]; then
  [ -s "$KEYS_FILE" ] || die "no key given (--key / --key-file) and $KEYS_FILE does not exist"
  say "no key given: keeping existing $KEYS_FILE"; KEYS_OUT=
fi

# ---------------------------------------------------------------- fetch + verify
case $(uname -m) in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported arch $(uname -m)" ;;
esac
ASSET=auditsh-linux-$ARCH

fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only --secure-protocol=TLSv1_2 -O "$2" "$1"
  else die "need curl or wget"; fi
}

SRC=$TMP/src; mkdir -p "$SRC"
if [ -n "${AUDITSH_LOCAL_BIN:-}" ]; then
  warn "AUDITSH_LOCAL_BIN set: using local files, NO download/checksum (testing only)"
  [ -n "${AUDITSH_SRC_DIR:-}" ] || die "AUDITSH_SRC_DIR (repo checkout) required with AUDITSH_LOCAL_BIN"
  cp "$AUDITSH_LOCAL_BIN" "$SRC/$ASSET"
  cp "$AUDITSH_SRC_DIR/allowlist.yaml" "$AUDITSH_SRC_DIR/deploy/sshd_config.d/50-botaudit.conf" \
     "$AUDITSH_SRC_DIR/deploy/sudoers.botaudit" "$SRC/"
else
  if [ -z "$VERSION" ]; then
    fetch "https://api.github.com/repos/$REPO/releases/latest" "$TMP/latest.json"
    VERSION=$(sed -n 's/^ *"tag_name": *"\([^"]*\)".*/\1/p' "$TMP/latest.json" | head -n1)
  fi
  printf '%s' "$VERSION" | grep -Eq '^v[0-9A-Za-z.+-]+$' || die "bad version '$VERSION'"
  say "version $VERSION ($ARCH)"
  base="https://github.com/$REPO/releases/download/$VERSION"
  for f in "$ASSET" allowlist.yaml 50-botaudit.conf sudoers.botaudit SHA256SUMS; do
    fetch "$base/$f" "$SRC/$f" || die "download failed: $f"
  done
  ( cd "$SRC"
    for f in "$ASSET" allowlist.yaml 50-botaudit.conf sudoers.botaudit; do
      want=$(awk -v f="$f" '$2==f || $2=="*"f {print $1}' SHA256SUMS)
      [ -n "$want" ] || die "$f missing from SHA256SUMS"
      have=$(sha256sum "$f" | awk '{print $1}')
      [ "$want" = "$have" ] || die "sha256 mismatch for $f"
    done ) || exit 1
  say "sha256 verified"
  if command -v gh >/dev/null 2>&1 && gh attestation verify "$SRC/$ASSET" --repo "$REPO" >/dev/null 2>&1 \
     && gh attestation verify "$SRC/SHA256SUMS" --repo "$REPO" >/dev/null 2>&1; then
    say "build provenance attestation verified (gh)"
  elif [ "$REQ_ATTEST" = 1 ]; then
    die "attestation verification failed or gh unavailable/unauthenticated"
  else
    warn "attestation not verified (needs authenticated gh); relying on sha256 over https"
  fi
fi
chmod 0755 "$SRC/$ASSET"

# ---------------------------------------------------------------- preflight sshd
SSHD=$(sshd_bin)
if [ "$DRY" = 0 ]; then "$SSHD" -t || die "sshd -t fails before any change; fix sshd config first"; fi
grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config \
  || die "/etc/ssh/sshd_config lacks 'Include /etc/ssh/sshd_config.d/*.conf'; add it at the top first"
command -v visudo >/dev/null 2>&1 || die "visudo not found (install sudo)"
visudo -cf "$SRC/sudoers.botaudit" >/dev/null || die "sudoers file fails visudo -cf"

# ---------------------------------------------------------------- install files
inst() { run install -o root -g root -m "$1" "$2" "$3"; }
run install -d -o root -g root -m 0755 /usr/local/sbin "$CONF_DIR" "$KEYS_DIR"
inst 0755 "$SRC/$ASSET" "$BIN"
inst 0644 "$SRC/allowlist.yaml" "$CONF_DIR/allowlist.yaml"
grep -qx "$BIN" /etc/shells 2>/dev/null || { [ "$DRY" = 1 ] && say "would add $BIN to /etc/shells" || echo "$BIN" >> /etc/shells; }

# ---------------------------------------------------------------- user
if id "$USER_NAME" >/dev/null 2>&1; then
  run usermod --shell "$BIN" --home "$HOME_DIR" "$USER_NAME"
else
  run useradd --system --create-home --home-dir "$HOME_DIR" --shell "$BIN" "$USER_NAME"
fi
if [ "$("$SSHD" -T -C user=$USER_NAME,host=x,addr=192.0.2.10 2>/dev/null | awk '$1=="usepam"{print $2}')" = no ]; then
  warn "UsePAM no: setting password field to '*' instead of '!' (see README Account lock)"
  run usermod -p '*' "$USER_NAME"
else
  run usermod -L "$USER_NAME"
fi
run install -d -o root -g root -m 0755 "$HOME_DIR"
[ -e "$HOME_DIR/.ssh" ] && run chown -R root:root "$HOME_DIR/.ssh"
for f in /etc/cron.deny /etc/at.deny; do
  grep -qx "$USER_NAME" "$f" 2>/dev/null || { [ "$DRY" = 1 ] && say "would add $USER_NAME to $f" || echo "$USER_NAME" >> "$f"; }
done

# ---------------------------------------------------------------- sudoers (validated before activation)
if [ "$DRY" = 1 ]; then say "would install $SUDOERS (0440)"; else
  install -o root -g root -m 0440 "$SRC/sudoers.botaudit" "$SUDOERS.new"   # '.' in name: ignored by includedir
  visudo -cf "$SUDOERS.new" >/dev/null || { rm -f "$SUDOERS.new"; die "visudo rejected sudoers"; }
  [ -f "$SUDOERS" ] && cp -p "$SUDOERS" "$TMP/sudoers.bak"
  mv -f "$SUDOERS.new" "$SUDOERS"
  if ! visudo -c >/dev/null; then
    if [ -f "$TMP/sudoers.bak" ]; then cp -p "$TMP/sudoers.bak" "$SUDOERS"; else rm -f "$SUDOERS"; fi
    die "visudo -c failed after install; rolled back"
  fi
fi

# ---------------------------------------------------------------- sshd (validated before reload, rollback)
if [ "$DRY" = 1 ]; then
  say "would install $SSHD_DROPIN, $KEYS_FILE (${n} key line(s)), comment out AcceptEnv, sshd -t, reload"
else
  BAK=$TMP/bak; mkdir -p "$BAK"
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf "$KEYS_FILE"; do
    [ -f "$f" ] && { mkdir -p "$BAK$(dirname "$f")"; cp -p "$f" "$BAK$f"; }
  done
  had_dropin=0; [ -f "$SSHD_DROPIN" ] && had_dropin=1
  had_keys=0; [ -f "$KEYS_FILE" ] && had_keys=1
  rollback() {
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf "$KEYS_FILE"; do
      [ -f "$BAK$f" ] && cp -p "$BAK$f" "$f"
    done
    [ "$had_dropin" = 0 ] && rm -f "$SSHD_DROPIN"
    [ "$had_keys" = 0 ] && rm -f "$KEYS_FILE"
    die "$1; sshd config rolled back"
  }
  # No AcceptEnv anywhere (cumulative, cannot be undone inside Match).
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    [ -f "$f" ] && grep -Eq '^[[:space:]]*AcceptEnv' "$f" && sed -i 's/^\s*AcceptEnv/# &/' "$f"
  done
  install -o root -g root -m 0644 "$SRC/50-botaudit.conf" "$SSHD_DROPIN"
  if [ -n "$KEYS_OUT" ]; then install -o root -g root -m 0644 "$KEYS_OUT" "$KEYS_FILE"; fi
  "$SSHD" -t || rollback "sshd -t failed"
  T=$("$SSHD" -T -C user=$USER_NAME,host=x,addr=192.0.2.10) || rollback "sshd -T failed"
  printf '%s\n' "$T" | grep -qx "forcecommand $BIN" || rollback "ForceCommand not effective for $USER_NAME"
  printf '%s\n' "$T" | grep -qi '^acceptenv' && rollback "AcceptEnv still set"
  pue=$(printf '%s\n' "$T" | awk '$1=="permituserenvironment"{print $2}')
  [ -z "$pue" ] || [ "$pue" = no ] || rollback "PermitUserEnvironment=$pue; set it to no globally"
  grep -v '^#' "$KEYS_FILE" | grep -v '^restrict,command="/usr/local/sbin/auditsh"' | grep -q . \
    && rollback "$KEYS_FILE has a line without restrict,command=; fix it"
  reload_sshd
fi

# ---------------------------------------------------------------- post-install notes
grep -Eq '^[^ ]+ /proc proc [^ ]*hidepid=' /proc/mounts 2>/dev/null \
  || warn "/proc not mounted with hidepid=2/invisible (recommended, test first; see README Residual risks)"
command -v auditctl >/dev/null 2>&1 || warn "auditd not installed; consider it for exec auditing"
warn "auditsh logs JSON to syslog local7 (tag auditsh) and fails closed if syslog is down;"
warn "  route it to a root-only file, e.g. rsyslog: local7.* /var/log/auditsh.log"
warn "verify login (UsePAM caveat, README 'Account lock'): ssh -i KEY $USER_NAME@HOST uptime"
if [ "$DRY" = 1 ]; then say "dry-run done, nothing changed"; else say "done"; fi
