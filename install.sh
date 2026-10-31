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
# AUDITSH_KEY_FILE, AUDITSH_FROM, AUDITSH_UID (optional pin; default: system-assigned).
# Package mode (deb/rpm ship this script as /usr/sbin/auditsh-setup):
#   auditsh-setup --local --key '...'   use the packaged binary/allowlist/sudoers, enable SSH (no download)
#   auditsh-setup --account-only        postinst: create/refresh the botaudit account only (no SSH access)
#   --java-user U (repeatable, with install or --local): allow jcmd/jstat diagnostics of JVMs owned by U via
#   /usr/local/sbin/auditsh-jvm; writes /etc/sudoers.d/botaudit-jvm + /etc/auditsh/java-users (U must exist,
#   not root, not uid 0). Regenerated every run: install/--local WITHOUT --java-user removes both (revoke).
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
JAVA_USERS_FILE=/etc/auditsh/java-users
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
FIXED_UID=${AUDITSH_UID:-}
DRY=0
TEST_HOOKS=0
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
    --test-hooks) TEST_HOOKS=1; shift ;;  # test-only, undocumented: enables AUDITSH_TEST_FAIL_AFTER
    --check-account) MODE=check; shift ;;  # test-only, undocumented: run the account checks and exit
    -h|--help) sed -n '2,30p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

if [ "$MODE" = check ]; then check_account_sane; exit 0; fi  # test-only, read-only
[ "$(uname -s)" = Linux ] || die "Linux only"
if [ "$(id -u)" != 0 ]; then
  if [ "$DRY" = 1 ]; then warn "not root: dry-run only"; else die "must run as root"; fi
fi
TMP=$(mktemp -d)
trap 'on_exit $?' EXIT
trap 'exit 130' INT TERM HUP
[ -z "$FIXED_UID" ] || printf '%s' "$FIXED_UID" | grep -Eq '^[0-9]{2,5}$' || die "bad --uid"

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
  if [ -n "$JAVA_USERS" ]; then say "would write $SUDOERS_JVM and $JAVA_USERS_FILE for java user(s) $JAVA_USERS"
  else say "would remove $SUDOERS_JVM and $JAVA_USERS_FILE if present (no --java-user = revoke)"; fi
  say "would install $SSHD_DROPIN, $KEYS_FILE ($NKEYS key line(s))"
  id "$USER_NAME" >/dev/null 2>&1 || say "would create user $USER_NAME uid/gid ${FIXED_UID:-system-assigned} home $HOME_DIR shell $BIN"
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
test_fail_after setup_account
# Regenerated from the flags on every install/--local run; no --java-user revokes JVM access.
if [ -n "$JAVA_USERS" ]; then
  install -o root -g root -m 0440 "$TMP/sudoers.jvm" "$SUDOERS_JVM"
  printf '%s\n' "$JAVA_USERS" | tr ',' '\n' > "$TMP/java-users"
  install -o root -g root -m 0644 "$TMP/java-users" "$JAVA_USERS_FILE"
else
  rm -f "$SUDOERS_JVM" "$JAVA_USERS_FILE"
fi
visudo -c >/dev/null || die "visudo -c failed after install"
enable_ssh
STAGED=0
rm -f "$BAK/account.shadow"
notes
say "done"
}

check_uid_free() {
  check_account_sane
  [ -n "$FIXED_UID" ] || return 0
  if ! id "$USER_NAME" >/dev/null 2>&1; then
    if getent passwd "$FIXED_UID" >/dev/null; then die "uid $FIXED_UID in use; pass --uid N"; fi
    if getent group "$FIXED_UID" >/dev/null; then die "gid $FIXED_UID in use; pass --uid N"; fi
  fi
}

acfail() { die "$*"; }
# BEGIN account-check (byte-identical in install.sh and packaging/preinstall.sh; tests/account-check-test.sh)
# account_check NAME [PIN]: an existing NAME account/group must be safe to grant; calls acfail MSG otherwise.
ac_defs() {
  ac_v=$(awk -v k="$1" '$1==k{v=$2} END{print v}' /etc/login.defs 2>/dev/null) || ac_v=
  case "$ac_v" in ''|*[!0-9]*) ac_v=$2 ;; esac
  printf '%s' "$ac_v"
}
account_check() {
  ac_n=$1; ac_pin=${2:-}
  ac_ulo=$(ac_defs SYS_UID_MIN 100); ac_uhi=$(ac_defs SYS_UID_MAX 999)
  ac_glo=$(ac_defs SYS_GID_MIN 100); ac_ghi=$(ac_defs SYS_GID_MAX 999)
  ac_gg=""
  if ac_e=$(getent group "$ac_n"); then
    ac_gg=$(printf '%s' "$ac_e" | cut -d: -f3)
    case "$ac_gg" in ''|*[!0-9]*|0) acfail "group $ac_n has gid '$ac_gg' (0 or invalid)" ;; esac
    if [ "$ac_gg" -lt "$ac_glo" ] || [ "$ac_gg" -gt "$ac_ghi" ]; then acfail "group $ac_n gid $ac_gg outside system range $ac_glo..$ac_ghi"; fi
    [ "$(getent group | awk -F: -v g="$ac_gg" '$3==g' | wc -l)" -eq 1 ] || acfail "gid $ac_gg of group $ac_n is shared with another group"
    if [ -n "$ac_pin" ] && [ "$ac_gg" != "$ac_pin" ]; then acfail "group $ac_n exists with gid $ac_gg, not --uid $ac_pin"; fi
  fi
  if ac_e=$(getent passwd "$ac_n"); then
    ac_uu=$(printf '%s' "$ac_e" | cut -d: -f3); ac_ug=$(printf '%s' "$ac_e" | cut -d: -f4)
    case "$ac_uu" in ''|*[!0-9]*|0) acfail "user $ac_n has uid '$ac_uu' (0 or invalid)" ;; esac
    case "$ac_ug" in ''|*[!0-9]*|0) acfail "user $ac_n has primary gid '$ac_ug' (0 or invalid)" ;; esac
    if [ "$ac_uu" -lt "$ac_ulo" ] || [ "$ac_uu" -gt "$ac_uhi" ]; then acfail "user $ac_n uid $ac_uu outside system range $ac_ulo..$ac_uhi"; fi
    [ "$(getent passwd | awk -F: -v u="$ac_uu" '$3==u' | wc -l)" -eq 1 ] || acfail "uid $ac_uu of user $ac_n is shared with another account"
    if [ -z "$ac_gg" ] || [ "$ac_ug" != "$ac_gg" ]; then acfail "user $ac_n primary gid $ac_ug is not group $ac_n"; fi
    [ "$(id -G "$ac_n" 2>/dev/null)" = "$ac_gg" ] || acfail "user $ac_n has supplementary groups ($(id -Gn "$ac_n" 2>/dev/null))"
    if [ -n "$ac_pin" ] && [ "$ac_uu" != "$ac_pin" ]; then acfail "user $ac_n exists with uid $ac_uu, not --uid $ac_pin"; fi
  fi
  return 0
}
# END account-check
check_account_sane() {
  account_check "$USER_NAME" "$FIXED_UID"
  # A Java user must never alias botaudit (sudo/kernel would treat them as one identity).
  if [ -n "$JAVA_USERS" ] && ac_bu=$(id -u "$USER_NAME" 2>/dev/null); then
    for ac_j in $(printf '%s' "$JAVA_USERS" | tr , ' '); do
      [ "$(id -u "$ac_j")" != "$ac_bu" ] || die "--java-user: $ac_j shares uid $ac_bu with $USER_NAME"
    done
  fi
}

# botaudit: system uid/gid (system-assigned unless --uid), shell auditsh (listed in /etc/shells), locked, root-owned home, no cron/at.
setup_account() {
  command -v pkill >/dev/null 2>&1 || die "pkill not found: cannot stop $USER_NAME processes before touching its home"
  # Early refusal (before any change); the authoritative checks follow once HOME is root-owned.
  check_home_paths
  grep -qx "$BIN" /etc/shells 2>/dev/null || echo "$BIN" >> /etc/shells
  if id "$USER_NAME" >/dev/null 2>&1; then
    usermod --shell "$BIN" --home "$HOME_DIR" "$USER_NAME"
  else
    if [ -n "$FIXED_UID" ]; then
      getent group "$USER_NAME" >/dev/null || groupadd --system --gid "$FIXED_UID" "$USER_NAME"
      set -- --uid "$FIXED_UID"
    else
      getent group "$USER_NAME" >/dev/null || groupadd --system "$USER_NAME"
      set --
    fi
    useradd --system "$@" --gid "$USER_NAME" --no-create-home --home-dir "$HOME_DIR" --shell "$BIN" "$USER_NAME"
    CREATED_USER=1
  fi
  # Re-check what the system actually assigned (unique uid/gid, system range, no supplementary groups).
  check_account_sane
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
  # Locked and on auditsh: stop whatever the account still runs so nothing can swap paths below.
  pkill -KILL -u "$USER_NAME" 2>/dev/null || true
  # HOME: /home is root-owned, so the account cannot replace HOME itself; refuse a symlink before install -d.
  if [ -L "$HOME_DIR" ]; then die "$HOME_DIR is a symlink; refusing to touch it"; fi
  install -d -o root -g root -m 0755 "$HOME_DIR"
  # From here HOME is root-owned, so .ssh can no longer be renamed or replaced by the account.
  # Fixed paths only, never recursive, .ssh first; other .ssh entries are left as they are.
  if [ -L "$HOME_DIR/.ssh" ]; then die "$HOME_DIR/.ssh is a symlink; refusing to touch it"; fi
  if [ -e "$HOME_DIR/.ssh" ]; then
    [ -d "$HOME_DIR/.ssh" ] || die "$HOME_DIR/.ssh is not a directory"
    chown -h root:root -- "$HOME_DIR/.ssh"
    # .ssh is root-owned now: authorized_keys can no longer be swapped; check it, then chown it.
    ak=$HOME_DIR/.ssh/authorized_keys
    if [ -L "$ak" ]; then die "$ak is a symlink; refusing to touch it"; fi
    if [ -e "$ak" ]; then
      [ -f "$ak" ] || die "$ak is not a regular file"
      [ "$(stat -c %h -- "$ak")" = 1 ] || die "$ak has more than one hard link; refusing to touch it"
      chown -h root:root -- "$ak"
    fi
  fi
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
  printf '%s\n' "$BIN" "$JVM_HELPER" "$CONF_DIR/allowlist.yaml" "$SUDOERS" "$SUDOERS_JVM" "$JAVA_USERS_FILE" "$SSHD_DROPIN" "$KEYS_FILE" \
    /etc/shells /etc/cron.deny /etc/at.deny /etc/ssh/sshd_config
  for f in /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] && printf '%s\n' "$f"; done
  return 0
}
backup() {
  BAK=$TMP/bak; mkdir -p "$BAK"; : > "$TMP/absent"; CREATED_USER=0
  HOME_EXISTED=0; if [ -e "$HOME_DIR" ]; then HOME_EXISTED=1; fi
  : > "$TMP/newdirs"
  for d in /usr/local/sbin "$CONF_DIR" "$KEYS_DIR"; do [ -d "$d" ] || echo "$d" >> "$TMP/newdirs"; done
  backup_account
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
  else
    restore_account
  fi
  while IFS= read -r d; do rm -f -- "$d/.auditsh-created"; rmdir -- "$d" 2>/dev/null || true; done < "$TMP/newdirs"
  say "rolled back (sshd not reloaded)"
}

# Pre-existing account: setup_account rewrites shell, home, password field and the owner of the fixed paths
# HOME_DIR, HOME_DIR/.ssh, HOME_DIR/.ssh/authorized_keys. Only those three are recorded (owner:group mode in
# shell variables, no file names are ever read back or parsed). The password field (a hash) goes only into a
# root-only 0600 file under $BAK (inside the 0700 mktemp dir); it is never printed and is removed after use.
backup_account() {
  ACCT_EXISTED=0; PERM_HOME=; PERM_SSH=; PERM_AK=
  check_home_paths
  command -v pkill >/dev/null 2>&1 || die "pkill not found: cannot stop $USER_NAME processes before a rollback"
  if [ -d "$HOME_DIR" ]; then PERM_HOME=$(stat -c '%u:%g %a' -- "$HOME_DIR"); fi
  if [ -d "$HOME_DIR/.ssh" ]; then PERM_SSH=$(stat -c '%u:%g %a' -- "$HOME_DIR/.ssh"); fi
  if [ -f "$HOME_DIR/.ssh/authorized_keys" ]; then PERM_AK=$(stat -c '%u:%g %a' -- "$HOME_DIR/.ssh/authorized_keys"); fi
  pw=$(getent passwd "$USER_NAME") || return 0
  ACCT_EXISTED=1
  command -v chpasswd >/dev/null 2>&1 || die "chpasswd not found: cannot guarantee a password-field rollback for $USER_NAME"
  ACCT_HOME=$(printf '%s' "$pw" | cut -d: -f6); ACCT_SHELL=$(printf '%s' "$pw" | cut -d: -f7)
  # getent's status is checked on its own (a pipe would report cut's), and an empty answer is refused too,
  # so a missing entry can never be "restored" as an empty password.
  sp=$(getent shadow "$USER_NAME") || die "cannot read shadow entry for $USER_NAME"
  [ -n "$sp" ] || die "empty shadow entry for $USER_NAME"
  (umask 077; printf '%s\n' "$sp" | cut -d: -f2 > "$BAK/account.shadow") || die "cannot save shadow field for $USER_NAME"
  unset sp
  chmod 0600 "$BAK/account.shadow"
}
# check_home_paths: refuse (before any change) a symlink or wrong type at the fixed paths, and a hardlinked
# authorized_keys. Used by backup_account and setup_account (so also on the --account-only path).
check_home_paths() {
  for f in "$HOME_DIR" "$HOME_DIR/.ssh" "$HOME_DIR/.ssh/authorized_keys"; do
    if [ -L "$f" ]; then die "$f is a symlink; refusing to touch it"; fi
  done
  if [ -e "$HOME_DIR" ] && [ ! -d "$HOME_DIR" ]; then die "$HOME_DIR exists and is not a directory"; fi
  if [ -e "$HOME_DIR/.ssh" ] && [ ! -d "$HOME_DIR/.ssh" ]; then die "$HOME_DIR/.ssh exists and is not a directory"; fi
  f=$HOME_DIR/.ssh/authorized_keys
  if [ -e "$f" ]; then
    [ -f "$f" ] || die "$f exists and is not a regular file"
    [ "$(stat -c %h -- "$f")" = 1 ] || die "$f has more than one hard link; refusing to touch it"
  fi
}
# restore_perm PATH TYPE(d|f) "UID:GID MODE": put one fixed path back, only if it differs. The target must be
# a non-symlink of the expected type and its parent a root-owned non-symlink directory, so a live account
# cannot swap anything under us (callers go deepest-first while the parents are still root-owned).
restore_perm() {
  [ -n "$3" ] || return 0
  if [ "$(stat -c '%u:%g %a' -- "$1" 2>/dev/null)" = "$3" ]; then return 0; fi
  par=$(dirname -- "$1")
  if [ -L "$par" ] || [ ! -d "$par" ] || [ "$(stat -c %u -- "$par")" != 0 ]; then
    warn "not restoring $1: parent is not a root-owned directory"; return 0
  fi
  ok=0; case $2 in d) [ -d "$1" ] && ok=1 ;; f) [ -f "$1" ] && ok=1 ;; esac
  if [ -L "$1" ] || [ "$ok" = 0 ]; then warn "not restoring $1: no longer the expected type"; return 0; fi
  chown -h "${3% *}" -- "$1" || warn "could not restore owner of $1"
  if [ ! -L "$1" ]; then chmod "${3#* }" -- "$1" || warn "could not restore mode of $1"; fi
}
restore_account() {
  [ "${ACCT_EXISTED:-0}" = 1 ] || return 0
  # No process of the account may race the restore. If the failure came after setup_account the account is
  # locked and on auditsh; if before, nothing under HOME was changed and restore_perm skips (parents not root).
  pkill -KILL -u "$USER_NAME" 2>/dev/null || true
  restore_perm "$HOME_DIR/.ssh/authorized_keys" f "$PERM_AK"
  restore_perm "$HOME_DIR/.ssh" d "$PERM_SSH"
  restore_perm "$HOME_DIR" d "$PERM_HOME"
  usermod --shell "$ACCT_SHELL" --home "$ACCT_HOME" "$USER_NAME" || warn "could not restore shell/home of $USER_NAME (left on auditsh)"
  if [ -f "$BAK/account.shadow" ]; then
    # chpasswd -e writes the saved field verbatim from stdin ('!'/'*'/'!!' lock prefixes and an empty field
    # included), so the hash never appears in argv. No argv fallback: if it fails, say so loudly.
    if ! command -v chpasswd >/dev/null 2>&1; then
      say "ERROR: chpasswd not found; password field of $USER_NAME NOT restored "
    elif ! { printf '%s:' "$USER_NAME"; cat "$BAK/account.shadow"; } | chpasswd -e >/dev/null 2>&1 \
      || [ "$(getent shadow "$USER_NAME" | cut -d: -f2)" != "$(cat "$BAK/account.shadow")" ]; then
      say "ERROR: chpasswd -e failed; password field of $USER_NAME NOT restored, fix it by hand"
    fi
    rm -f "$BAK/account.shadow"
  fi
  if [ "$HOME_EXISTED" = 0 ] && [ "$HOME_DIR" != "$ACCT_HOME" ]; then rmdir -- "$HOME_DIR" 2>/dev/null || true; fi
}
# Test-only fault injection: needs both --test-hooks and AUDITSH_TEST_FAIL_AFTER=<step>.
test_fail_after() {
  if [ "$TEST_HOOKS" = 1 ] && [ "${AUDITSH_TEST_FAIL_AFTER:-}" = "$1" ]; then die "test hook: forced failure after $1"; fi
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
  run rm -f "$SUDOERS_JVM" "$JAVA_USERS_FILE"   # generated, never package-owned
  if [ "$PKG" = 0 ]; then run rm -f "$SUDOERS" "$BIN" "$JVM_HELPER"; run rm -rf -- "$CONF_DIR"; fi
  if [ -f "$KEYS_DIR/.auditsh-created" ]; then run rm -f "$KEYS_DIR/.auditsh-created"; run rmdir "$KEYS_DIR" || true; fi
  if [ -f /etc/shells ]; then run sed -i '\#^/usr/local/sbin/auditsh$#d' /etc/shells; fi
  for f in /etc/cron.deny /etc/at.deny; do
    if [ -f "$f" ]; then run sed -i '/^botaudit$/d' "$f"; if [ "$DRY" = 0 ] && [ ! -s "$f" ]; then rm -f "$f"; fi; fi
  done
  say "uninstalled"
}

main "$@"
