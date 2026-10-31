#!/bin/sh
# Same account-check fixtures through packaging/preinstall.sh and install.sh --check-account:
# both must agree, match the expected verdict, and carry a byte-identical account-check block.
# Uses stub getent/id over fixture files; touches nothing on the host. Run by `make test`.
set -eu
cd "$(dirname "$0")/.."
blk() { sed -n '/^# BEGIN account-check/,/^# END account-check/p' "$1"; }
[ -n "$(blk install.sh)" ] && [ "$(blk install.sh)" = "$(blk packaging/preinstall.sh)" ] \
  || { echo "account-check block differs between install.sh and packaging/preinstall.sh" >&2; exit 1; }
# Q-1: cleanup state is initialised at top level (before any use), never taken from the environment.
first=$(grep -nE '(CREATED_USER|CREATED_GROUP|AC_POST)' install.sh | head -1)
case $first in *"CREATED_USER=0 CREATED_GROUP=0 AC_POST=0") ;; *) echo "install.sh must init CREATED_USER/CREATED_GROUP/AC_POST=0 before any use: $first" >&2; exit 1 ;; esac
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
mkdir "$D/bin"
cat > "$D/bin/getent" <<'EOF'
#!/bin/sh
# Enumeration may differ from keyed lookups (sssd/LDAP enumerate=false): $FX/<db>.enum overrides it.
f=$FX/$1; [ -n "${2:-}" ] || { if [ -f "$f.enum" ]; then cat "$f.enum"; else cat "$f"; fi; exit 0; }
awk -F: -v k="$2" '$1==k || $3==k {print; found=1; exit} END{exit !found}' "$f" || exit 2
EOF
cat > "$D/bin/id" <<'EOF'
#!/bin/sh
o=$1; n=$2; export o
e=$(awk -F: -v k="$n" '$1==k' "$FX/passwd"); [ -n "$e" ] || exit 1
u=$(echo "$e" | cut -d: -f3); g=$(echo "$e" | cut -d: -f4)
sup=$(awk -F: -v n="$n" -v g="$g" '$3!=g { split($4,m,","); for (i in m) if (m[i]==n) printf " %s", (ENVIRON["o"]=="-Gn") ? $1 : $3 }' "$FX/group")
case $o in -u) echo "$u" ;; -G) echo "$g$sup" ;; -Gn) echo "$n$sup" ;; esac
EOF
chmod +x "$D/bin/getent" "$D/bin/id"
# install.sh pins PATH; the test copy puts the stubs first (the only edit).
sed "s#^PATH=/usr/sbin:#PATH=$D/bin:/usr/sbin:#" install.sh > "$D/install.sh"
grep -q "^PATH=$D/bin:" "$D/install.sh" || { echo "PATH rewrite failed" >&2; exit 1; }
base_p='root:x:0:0::/root:/bin/sh
squat:x:500:500::/:/bin/false'
base_g='root:x:0:
docker:x:990:
squat:x:500:'
fails=0
# case NAME EXPECT(ok|fail) PASSWD_EXTRA GROUP_EXTRA [PIN] [KEYED_ONLY_PASSWD] [KEYED_ONLY_GROUP]
case_() {
  name=$1 want=$2; FX=$D/$name; export FX; mkdir -p "$FX"
  printf '%s\n%s' "$base_p" "$3" | sed '/^$/d' > "$FX/passwd"; printf '%s\n%s' "$base_g" "$4" | sed '/^$/d' > "$FX/group"
  if [ -n "${6:-}" ]; then cp "$FX/passwd" "$FX/passwd.enum"; printf '%s\n' "$6" | cat - "$FX/passwd.enum" > "$FX/passwd"; fi
  if [ -n "${7:-}" ]; then cp "$FX/group" "$FX/group.enum"; printf '%s\n' "$7" | cat - "$FX/group.enum" > "$FX/group"; fi
  if PATH="$D/bin:$PATH" sh packaging/preinstall.sh install 2>"$FX/err.p"; then p=ok; else p=fail; fi
  if PATH="$D/bin:$PATH" sh "$D/install.sh" --check-account ${5:+--uid "$5"} 2>"$FX/err.i"; then i=ok; else i=fail; fi
  [ -n "${5:-}" ] && p=$want  # preinst has no --uid
  if [ "$p" = "$want" ] && [ "$i" = "$want" ]; then echo "ok   $name ($want) $(cat "$FX/err.i")"
  else echo "FAIL $name: want $want, preinst $p, install.sh $i"; fails=$((fails+1)); fi
}
case_ absent ok '' ''
case_ sane ok 'botaudit:x:985:985::/home/botaudit:/x' 'botaudit:x:985:'
case_ group-only ok '' 'botaudit:x:985:'
case_ uid0 fail 'botaudit:x:0:0::/:/x' 'botaudit:x:985:'
case_ gid0-group fail '' 'botaudit:x:0:'
case_ uid-nonsystem fail 'botaudit:x:1500:985::/:/x' 'botaudit:x:985:'
case_ primary-not-botaudit fail 'botaudit:x:985:500::/:/x' 'botaudit:x:985:'
case_ no-botaudit-group fail 'botaudit:x:985:985::/:/x' ''
case_ shared-uid fail 'botaudit:x:985:985::/:/x
alias:x:985:500::/:/x' 'botaudit:x:985:'
case_ shared-gid fail 'botaudit:x:985:985::/:/x' 'botaudit:x:985:
other:x:985:'
case_ group-gid-nonsystem fail '' 'botaudit:x:1500:'
case_ supplementary fail 'botaudit:x:985:985::/:/x' 'botaudit:x:985:
docker2:x:986:botaudit'
case_ pin-match ok 'botaudit:x:985:985::/:/x' 'botaudit:x:985:' 985
case_ pin-uid-mismatch fail 'botaudit:x:985:985::/:/x' 'botaudit:x:985:' 984
case_ pin-uid-mismatch-only fail 'botaudit:x:985:984::/:/x' 'botaudit:x:984:' 984
case_ keyed-uid-alias fail 'botaudit:x:985:985::/:/x' 'botaudit:x:985:' '' 'remote:x:985:500::/:/x'
case_ keyed-gid-alias fail 'botaudit:x:985:985::/:/x' 'botaudit:x:985:' '' '' 'rgroup:x:985:'
case_ pin-group-mismatch fail '' 'botaudit:x:985:' 984
[ "$fails" = 0 ] || { echo "$fails account-check case(s) failed" >&2; exit 1; }
echo "account-check: preinst and install.sh agree on all cases"
