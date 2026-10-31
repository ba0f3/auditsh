#!/bin/sh
# install.sh: install/upgrade/uninstall auditsh + the botaudit account on a Linux host (run as root).
# Mirrors the README "Install (manual, as root)" steps. Idempotent.
#
#   sh install.sh --version vX.Y.Z --sha256 <sha256 of the release SHA256SUMS> --key 'ssh-ed25519 AAAA... agent@x'
#   sh install.sh --version vX.Y.Z --require-attestation --key-file /path/agent.pub [--from 192.0.2.10]
#   sh install.sh --uninstall
#   add --dry-run to download + verify and print what would change without touching anything.
#
# Integrity: --version is mandatory (no "latest"). Either --sha256 (hash of SHA256SUMS, obtained out of
# band) or --require-attestation (authenticated `gh` must verify the GitHub build provenance) is
# required; both may be given. Every asset is then checked against SHA256SUMS; any mismatch aborts.
# Env equivalents: AUDITSH_VERSION, AUDITSH_SHA256, AUDITSH_REQUIRE_ATTESTATION=1, AUDITSH_KEY,
# AUDITSH_KEY_FILE, AUDITSH_FROM, AUDITSH_UID (default 990).
# Package mode (deb/rpm ship this script as /usr/sbin/auditsh-setup):
#   auditsh-setup --local --key '...'   use the packaged binary/allowlist/sudoers, enable SSH (no download)
#   auditsh-setup --account-only        postinst: create/refresh the botaudit account only (no SSH access)
#   --java-user U (repeatable, with install or --local): allow jcmd/jstat diagnostics of JVMs owned by U via
#   /usr/local/sbin/auditsh-jvm; writes /etc/sudoers.d/botaudit-jvm (U must exist, not root, not uid 0).
#   auditsh-setup --uninstall --package prerm: undo account/SSH, leave package-owned files to dpkg/rpm
# The whole script is a function called on the last line, so a truncated download runs nothing.
set -eu

main() {
umask 022
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C

REPO=ba0f3/auditsh
BIN=/usr/local/sbin/auditsh
CONF_DIR=/etc/auditsh
KEYS_DIR=/etc/ssh/authorized_keys
KEYS_FILE=$KEYS_DIR/botaudit
SSHD_DROPIN=/etc/ssh/sshd_config.d/50-botaudit.conf
SUDOERS=/etc/sudoers.d/botaudit
SUDOERS_JVM=/etc/sudoers.d/botaudit-jvm
JVM_HELPER=/usr/local/sbin/auditsh-jvm
JAVA_USERS=
USER_NAME=botaudit
HOME_DIR=/home/botaudit
MARK='# auditsh-disabled: '

VERSION=${AUDITSH_VERSION:-}
SUMS_SHA=${AUDITSH_SHA256:-}
KEY=${AUDITSH_KEY:-}
KEY_FILE=${AUDITSH_KEY_FILE:-}
FROM=${AUDITSH_FROM:-}
REQ_ATTEST=${AUDITSH_REQUIRE_ATTESTATION:-0}
FIXED_UID=${AUDITSH_UID:-990}
DRY=0
MODE=install
STAGED=0

PKG_SHARE=/usr/share/auditsh
PKG=0

while [ $# -gt 0 ]; do
  case $1 in
    --key) need "$@"; KEY=$2; shift 2 ;;
    --key-file) need "$@"; KEY_FILE=$2; shift 2 ;;
    --from) need "$@"; FROM=$2; shift 2 ;;
    --version) need "$@"; VERSION=$2; shift 2 ;;
    --sha256) need "$@"; SUMS_SHA=$2; shift 2 ;;
    --java-user) need "$@"; add_java_user "$2"; shift 2 ;;
    --uid) need "$@"; FIXED_UID=$2; shift 2 ;;
    --require-attestation) REQ_ATTEST=1; shift ;;
    --local) MODE=local; shift ;;
    --account-only) MODE=account; shift ;;
    --package) PKG=1; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,30p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

[ "$(uname -s)" = Linux ] || die "Linux only"
if [ "$(id -u)" != 0 ]; then
  if [ "$DRY" = 1 ]; then warn "not root: dry-run only"; else die "must run as root"; fi
fi
TMP=$(mktemp -d)
trap 'on_exit $?' EXIT
trap 'exit 130' INT TERM HUP
printf '%s' "$FIXED_UID" | grep -Eq '^[0-9]{2,5}$' || die "bad --uid"

if [ "$MODE" = uninstall ]; then uninstall; exit 0; fi
if [ "$MODE" = account ]; then
  # Package postinst: account + sudoers check only. Opens no SSH access (no key, no drop-in).
  [ "$DRY" = 0 ] || die "--account-only has no dry-run"
  check_uid_free
  setup_account
  if ! visudo -c >/dev/null; then rm -f "$SUDOERS"; die "visudo -c failed; removed $SUDOERS"; fi
  say "account $USER_NAME ready; SSH access stays disabled until: auditsh-setup --local --key '...'"
  exit 0
fi

# ---------------------------------------------------------------- inputs (validated before any write)
[ -z "$FROM" ] || printf '%s' "$FROM" | grep -Eq '^[0-9A-Za-z.:/*?!,-]+$' || die "--from has invalid characters"
command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen not found (install openssh-client)"
command -v visudo >/dev/null 2>&1 || die "visudo not found (install sudo)"
SSHD=$(sshd_bin)
parse_keys

if [ "$MODE" = local ]; then
  # Package mode: binary, allowlist and sudoers are owned by the deb/rpm; only the drop-in comes from $PKG_SHARE.
  SRC=$PKG_SHARE
  for f in "$BIN" "$JVM_HELPER" "$CONF_DIR/allowlist.yaml" "$SUDOERS" "$SRC/50-botaudit.conf"; do
    [ -f "$f" ] && [ "$(stat -c %u "$f")" = 0 ] || die "$f missing or not root-owned (is the auditsh package installed?)"
  done
  cp "$SUDOERS" "$TMP/sudoers.check"; SUDOERS_SRC=$TMP/sudoers.check
else
  printf '%s' "$VERSION" | grep -Eq '^v[0-9A-Za-z.+-]+$' || die "--version vX.Y.Z is required (no 'latest')"
  [ -z "$SUMS_SHA" ] || printf '%s' "$SUMS_SHA" | grep -Eq '^[0-9a-f]{64}$' || die "--sha256 must be 64 lowercase hex"
  [ -n "$SUMS_SHA" ] || [ "$REQ_ATTEST" = 1 ] || die "give --sha256 <sha256 of SHA256SUMS> or --require-attestation"
  case $(uname -m) in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported arch $(uname -m)" ;;
  esac
  ASSET=auditsh-linux-$ARCH
  download_verify
  SUDOERS_SRC=$SRC/sudoers.botaudit
fi

grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config \
  || die "/etc/ssh/sshd_config lacks 'Include /etc/ssh/sshd_config.d/*.conf'; add it at the top first"
visudo -cf "$SUDOERS_SRC" >/dev/null || die "sudoers file fails visudo -cf"
if [ -n "$JAVA_USERS" ]; then
  # Runas list only; the helper is the argv gate (sudoers cannot pin a pid without a wildcard).
  { echo "# generated by auditsh-setup --java-user; do not edit. Policy gate: $JVM_HELPER (see README Java)."
    echo "botaudit ALL=($JAVA_USERS) NOPASSWD: $JVM_HELPER"; } > "$TMP/sudoers.jvm"
  visudo -cf "$TMP/sudoers.jvm" >/dev/null || die "generated java sudoers fails visudo -cf"
fi
if [ "$DRY" = 0 ]; then "$SSHD" -t || die "sshd -t fails before any change; fix sshd config first"; fi
check_uid_free

if [ "$DRY" = 1 ]; then
  [ "$MODE" = local ] || say "would install $BIN, $JVM_HELPER, $CONF_DIR/allowlist.yaml, $SUDOERS"
  [ -z "$JAVA_USERS" ] || say "would write $SUDOERS_JVM for java user(s) $JAVA_USERS"
  say "would install $SSHD_DROPIN, $KEYS_FILE ($NKEYS key line(s))"
  id "$USER_NAME" >/dev/null 2>&1 || say "would create user $USER_NAME uid/gid $FIXED_UID home $HOME_DIR shell $BIN"
  say "would comment out AcceptEnv, run sshd -t/-T checks, reload sshd"
  notes; say "dry-run done, nothing changed"; exit 0
fi

# ---------------------------------------------------------------- apply (any failure from here rolls back)
backup
STAGED=1
[ -d "$KEYS_DIR" ] || NEW_KEYS_DIR=1
install -d -o root -g root -m 0755 /usr/local/sbin "$CONF_DIR" "$KEYS_DIR"
# marker so uninstall removes the keys dir only if we created it
if [ "${NEW_KEYS_DIR:-0}" = 1 ]; then : > "$KEYS_DIR/.auditsh-created"; fi
if [ "$MODE" != local ]; then
  install -o root -g root -m 0755 "$SRC/$ASSET" "$BIN"
  install -o root -g root -m 0755 "$SRC/auditsh-jvm" "$JVM_HELPER"
  install -o root -g root -m 0644 "$SRC/allowlist.yaml" "$CONF_DIR/allowlist.yaml"
  install -o root -g root -m 0440 "$SRC/sudoers.botaudit" "$SUDOERS"
fi
setup_account
if [ -n "$JAVA_USERS" ]; then install -o root -g root -m 0440 "$TMP/sudoers.jvm" "$SUDOERS_JVM"; fi
visudo -c >/dev/null || die "visudo -c failed after install"
enable_ssh
STAGED=0
notes
say "done"
}

check_uid_free() {
  if ! id "$USER_NAME" >/dev/null 2>&1; then
    if getent passwd "$FIXED_UID" >/dev/null; then die "uid $FIXED_UID in use; pass --uid N"; fi
    if getent group "$FIXED_UID" >/dev/null; then die "gid $FIXED_UID in use; pass --uid N"; fi
  fi
}

# botaudit: fixed uid/gid, shell auditsh (listed in /etc/shells), locked, root-owned home, no cron/at.
setup_account() {
  grep -qx "$BIN" /etc/shells 2>/dev/null || echo "$BIN" >> /etc/shells
  if id "$USER_NAME" >/dev/null 2>&1; then
    usermod --shell "$BIN" --home "$HOME_DIR" "$USER_NAME"
  else
    getent group "$USER_NAME" >/dev/null || groupadd --system --gid "$FIXED_UID" "$USER_NAME"
    useradd --system --uid "$FIXED_UID" --gid "$USER_NAME" --no-create-home --home-dir "$HOME_DIR" --shell "$BIN" "$USER_NAME"
    CREATED_USER=1
  fi
  pam=yes
  if command -v sshd >/dev/null 2>&1; then
    pam=$(sshd -T -C "user=$USER_NAME,host=x,addr=192.0.2.10" 2>/dev/null | awk '$1=="usepam"{print $2}')
  fi
  if [ "$pam" = no ]; then
    warn "UsePAM no: setting password field to '*' instead of '!' (see README Account lock)"
    usermod -p '*' "$USER_NAME"
  else
    usermod -L "$USER_NAME"
  fi
  install -d -o root -g root -m 0755 "$HOME_DIR"
  if [ -e "$HOME_DIR/.ssh" ]; then chown -R root:root "$HOME_DIR/.ssh"; fi
  for f in /etc/cron.deny /etc/at.deny; do grep -qx "$USER_NAME" "$f" 2>/dev/null || echo "$USER_NAME" >> "$f"; done
}

# Drop-in + keys + AcceptEnv off, then sshd -t / -T checks, then reload. Caller handles rollback.
enable_ssh() {
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    if [ -f "$f" ] && grep -Eq '^[[:space:]]*AcceptEnv' "$f"; then sed -i "s/^[[:space:]]*AcceptEnv/$MARK&/" "$f"; fi
  done
  install -o root -g root -m 0644 "$SRC/50-botaudit.conf" "$SSHD_DROPIN"
  if [ -n "$KEYS_OUT" ]; then install -o root -g root -m 0644 "$KEYS_OUT" "$KEYS_FILE"; fi
  "$SSHD" -t || die "sshd -t failed"
  T=$("$SSHD" -T -C "user=$USER_NAME,host=x,addr=192.0.2.10") || die "sshd -T failed"
  printf '%s\n' "$T" | grep -qx "forcecommand $BIN" || die "ForceCommand not effective for $USER_NAME"
  if printf '%s\n' "$T" | grep -qi '^acceptenv'; then die "AcceptEnv still set"; fi
  pue=$(printf '%s\n' "$T" | awk '$1=="permituserenvironment"{print $2}')
  [ -z "$pue" ] || [ "$pue" = no ] || die "PermitUserEnvironment=$pue; set it to no globally"
  if grep -v '^#' "$KEYS_FILE" | grep -v '^restrict,command="/usr/local/sbin/auditsh"' | grep -q .; then
    die "$KEYS_FILE has a line without restrict,command="
  fi
  reload_sshd
}

# ================================================================ helpers
say()  { printf '%s\n' "auditsh-install: $*" >&2; }
warn() { printf '%s\n' "auditsh-install: WARNING: $*" >&2; }
die()  { printf '%s\n' "auditsh-install: ERROR: $*" >&2; exit 1; }
need() { [ $# -ge 2 ] || die "$1 needs a value"; }
# add_java_user NAME: validated before any write; JAVA_USERS becomes a sudoers Runas list "a,b".
add_java_user() {
  printf '%s' "$1" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || die "--java-user: bad user name"
  case $1 in root|botaudit) die "--java-user: $1 not allowed" ;; esac
  ju=$(getent passwd "$1") || die "--java-user: no such user $1"
  [ "$(printf '%s' "$ju" | cut -d: -f3)" != 0 ] || die "--java-user: $1 has uid 0"
  case ",$JAVA_USERS," in *",$1,"*) ;; *) JAVA_USERS=${JAVA_USERS:+$JAVA_USERS,}$1 ;; esac
}
run()  { if [ "$DRY" = 1 ]; then say "would run: $*"; else "$@"; fi; }
sshd_bin() { if command -v sshd >/dev/null 2>&1; then command -v sshd; else die "sshd not found"; fi; }

on_exit() {
  if [ "$1" != 0 ] && [ "${STAGED:-0}" = 1 ]; then rollback; fi
  rm -rf "${TMP:-/nonexistent}"
}

reload_sshd() {
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd || die "sshd reload failed"
  elif command -v service >/dev/null 2>&1 && service ssh reload >/dev/null 2>&1; then :
  else warn "could not reload sshd automatically; reload it yourself"; fi
}

# Files the install touches. Each is saved, or recorded as absent, before the first write.
tracked() {
  printf '%s\n' "$BIN" "$JVM_HELPER" "$CONF_DIR/allowlist.yaml" "$SUDOERS" "$SUDOERS_JVM" "$SSHD_DROPIN" "$KEYS_FILE" \
    /etc/shells /etc/cron.deny /etc/at.deny /etc/ssh/sshd_config
  for f in /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] && printf '%s\n' "$f"; done
  return 0
}
backup() {
  BAK=$TMP/bak; mkdir -p "$BAK"; : > "$TMP/absent"; CREATED_USER=0
  HOME_EXISTED=0; if [ -e "$HOME_DIR" ]; then HOME_EXISTED=1; fi
  : > "$TMP/newdirs"
  for d in /usr/local/sbin "$CONF_DIR" "$KEYS_DIR"; do [ -d "$d" ] || echo "$d" >> "$TMP/newdirs"; done
  tracked | while IFS= read -r f; do
    if [ -f "$f" ]; then mkdir -p "$BAK$(dirname "$f")"; cp -p "$f" "$BAK$f"; else echo "$f" >> "$TMP/absent"; fi
  done
}
rollback() {
  say "rolling back"
  tracked | while IFS= read -r f; do
    if [ -f "$BAK$f" ]; then cp -p "$BAK$f" "$f"; elif grep -qxF "$f" "$TMP/absent"; then rm -f "$f"; fi
  done
  if [ "${CREATED_USER:-0}" = 1 ]; then
    userdel "$USER_NAME" 2>/dev/null || true; groupdel "$USER_NAME" 2>/dev/null || true
    if [ "$HOME_EXISTED" = 0 ]; then rm -rf -- "$HOME_DIR"; fi
  fi
  while IFS= read -r d; do rm -f -- "$d/.auditsh-created"; rmdir -- "$d" 2>/dev/null || true; done < "$TMP/newdirs"
  say "rolled back (sshd not reloaded)"
}

parse_keys() {
  KEYS_OUT=$TMP/authorized_keys; : > "$KEYS_OUT"
  if [ -n "$KEY_FILE" ]; then [ -r "$KEY_FILE" ] || die "cannot read key file"; cat -- "$KEY_FILE" > "$TMP/keys.in"
  else printf '%s\n' "$KEY" > "$TMP/keys.in"; fi
  opts='restrict,command="/usr/local/sbin/auditsh"'
  [ -z "$FROM" ] || opts="$opts,from=\"$FROM\""
  NKEYS=0
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in ''|'#'*) continue ;; esac
    NKEYS=$((NKEYS+1))
    printf '%s' "$line" | grep -Eq '^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+={0,3}( [ -~]*)?$' \
      || die "key line $NKEYS is not a bare OpenSSH public key (no options, single line)"
    case $line in *'"'*|*\\*) die "key comment must not contain quotes or backslashes" ;; esac
    printf '%s\n' "$line" > "$TMP/one.pub"
    ssh-keygen -lf "$TMP/one.pub" >/dev/null 2>&1 || die "key line $NKEYS is not a valid public key (ssh-keygen -lf)"
    printf '%s %s\n' "$opts" "$line" >> "$KEYS_OUT"
  done < "$TMP/keys.in"
  if [ "$NKEYS" = 0 ]; then
    [ -s "$KEYS_FILE" ] || die "no key given (--key / --key-file) and $KEYS_FILE does not exist"
    say "no key given: keeping existing $KEYS_FILE"; KEYS_OUT=
  fi
}

fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only --secure-protocol=TLSv1_2 -O "$2" "$1"
  else die "need curl or wget"; fi
}

download_verify() {
  SRC=$TMP/src; mkdir -p "$SRC"
  say "version $VERSION ($ARCH)"
  base="https://github.com/$REPO/releases/download/$VERSION"
  for f in SHA256SUMS "$ASSET" auditsh-jvm allowlist.yaml 50-botaudit.conf sudoers.botaudit; do
    fetch "$base/$f" "$SRC/$f" || die "download failed: $f"
  done
  if [ -n "$SUMS_SHA" ]; then
    [ "$(sha256sum "$SRC/SHA256SUMS" | cut -d' ' -f1)" = "$SUMS_SHA" ] || die "SHA256SUMS does not match --sha256"
    say "SHA256SUMS matches pinned --sha256"
  fi
  if [ "$REQ_ATTEST" = 1 ]; then
    command -v gh >/dev/null 2>&1 || die "--require-attestation: gh not installed"
    gh attestation verify "$SRC/SHA256SUMS" --repo "$REPO" >/dev/null 2>&1 \
      || die "--require-attestation: gh attestation verify failed (is gh authenticated?)"
    say "SHA256SUMS build provenance attestation verified"
  fi
  for f in "$ASSET" auditsh-jvm allowlist.yaml 50-botaudit.conf sudoers.botaudit; do
    want=$(awk -v f="$f" '$2==f || $2=="*"f {print $1}' "$SRC/SHA256SUMS")
    [ -n "$want" ] || die "$f missing from SHA256SUMS"
    [ "$(sha256sum "$SRC/$f" | cut -d' ' -f1)" = "$want" ] || die "sha256 mismatch for $f"
  done
  chmod 0755 "$SRC/$ASSET"
  say "all assets verified"
}

notes() {
  grep -Eq '^[^ ]+ /proc proc [^ ]*hidepid=' /proc/mounts 2>/dev/null \
    || warn "/proc not mounted with hidepid=2/invisible (recommended, test first; see README Residual risks)"
  command -v auditctl >/dev/null 2>&1 || warn "auditd not installed; consider it for exec auditing"
  warn "auditsh logs JSON to syslog local7 (tag auditsh) and fails closed if syslog is down;"
  warn "  route it to a root-only file, e.g. rsyslog: local7.* /var/log/auditsh.log"
  warn "verify login (UsePAM caveat, README 'Account lock'): ssh -i KEY $USER_NAME@HOST uptime"
}

uninstall() {
  SSHD=$(sshd_bin)
  run rm -f "$SSHD_DROPIN" "$KEYS_FILE"
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    if [ -f "$f" ] && grep -q "^$MARK" "$f"; then run sed -i "s/^$MARK//" "$f"; fi
  done
  if [ "$DRY" = 0 ]; then "$SSHD" -t || die "sshd -t failed after uninstall; fix sshd_config"; reload_sshd; fi
  if id "$USER_NAME" >/dev/null 2>&1; then
    run pkill -KILL -u "$USER_NAME" || true
    run userdel "$USER_NAME"
    if [ "$DRY" = 0 ] && getent group "$USER_NAME" >/dev/null; then groupdel "$USER_NAME" || true; fi
  fi
  run rm -rf -- "$HOME_DIR"
  run rm -f "$SUDOERS_JVM"   # generated, never package-owned
  if [ "$PKG" = 0 ]; then run rm -f "$SUDOERS" "$BIN" "$JVM_HELPER"; run rm -rf -- "$CONF_DIR"; fi
  if [ -f "$KEYS_DIR/.auditsh-created" ]; then run rm -f "$KEYS_DIR/.auditsh-created"; run rmdir "$KEYS_DIR" || true; fi
  if [ -f /etc/shells ]; then run sed -i '\#^/usr/local/sbin/auditsh$#d' /etc/shells; fi
  for f in /etc/cron.deny /etc/at.deny; do
    if [ -f "$f" ]; then run sed -i '/^botaudit$/d' "$f"; if [ "$DRY" = 0 ] && [ ! -s "$f" ]; then rm -f "$f"; fi; fi
  done
  say "uninstalled"
}

main "$@"
