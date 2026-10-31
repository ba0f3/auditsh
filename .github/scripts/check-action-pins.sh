#!/bin/sh
# Every `uses: owner/repo[/path]@<40-hex> # <tag>` in .github/workflows/*.y*ml and in every
# action.yml/action.yaml must name the commit that <tag> points to in owner/repo (anonymous git
# ls-remote, annotated tags dereferenced). Local (./) uses are skipped. docker:// uses must be pinned
# by @sha256:<64-hex>. Inline-map forms ({uses: ...}) and any other form fail.
set -eu
cd "$(git rev-parse --show-toplevel)"
fail=0; n=0
Q="[\"']?"   # optional YAML key quotes: uses / "uses" / 'uses'
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
{ ls .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null || true
  git ls-files -- '*action.yml' '*action.yaml'; } | sort -u > "$tmp/files"
[ -s "$tmp/files" ] || { echo "FAIL no workflow files"; exit 1; }
# Inline maps (`- {uses: x}` / `{ name: a, uses: x }`) are not parsed here: refuse them.
if xargs grep -nE '\{[^}]*'"$Q"'uses'"$Q"'[[:space:]]*:' < "$tmp/files"; then echo "FAIL inline-map uses: above; use block style"; fail=1; fi
xargs grep -hE '^[[:space:]]*-?[[:space:]]*'"$Q"'uses'"$Q"'[[:space:]]*:' < "$tmp/files" | sort -u > "$tmp/uses" || true
while IFS= read -r line; do
  ref=$(printf '%s' "$line" | sed -E 's/^[[:space:]]*-?[[:space:]]*'"$Q"'uses'"$Q"'[[:space:]]*:[[:space:]]*//; s/^["'\'']//; s/["'\'']([[:space:]]+#.*)?$/\1/')
  case $ref in
    ./*) continue ;;
    docker://*)
      if printf '%s' "$ref" | grep -Eq '^docker://[^[:space:]@]+@sha256:[0-9a-f]{64}([[:space:]]+#.*)?$'; then
        n=$((n+1)); echo "ok   $ref"
      else echo "FAIL docker image not pinned by @sha256:<digest>: $ref"; fail=1; fi
      continue ;;
  esac
  spec=$(printf '%s' "$ref" | sed -nE 's/^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(\/[^@ ]*)?@([0-9a-f]{40})[[:space:]]+#[[:space:]]*([A-Za-z0-9_.+-]+)[[:space:]]*$/\1 \3 \4/p')
  if [ -z "$spec" ]; then echo "FAIL not pinned as owner/repo@sha # tag: $ref"; fail=1; continue; fi
  read -r repo sha tag <<EOS
$spec
EOS
  n=$((n+1))
  out=$(git ls-remote "https://github.com/$repo" "refs/tags/$tag" "refs/tags/$tag^{}") || { echo "FAIL ls-remote $repo"; fail=1; continue; }
  want=$(printf '%s\n' "$out" | awk -v t="refs/tags/$tag^{}" '$2==t{print $1}')
  [ -n "$want" ] || want=$(printf '%s\n' "$out" | awk -v t="refs/tags/$tag" '$2==t{print $1}')
  if [ "$want" = "$sha" ]; then echo "ok   $repo@$sha # $tag"
  else echo "FAIL $repo@$sha # $tag (tag resolves to ${want:-<missing>})"; fail=1; fi
done < "$tmp/uses"
[ "$n" -gt 0 ] || { echo "FAIL no pinned uses found"; exit 1; }
exit "$fail"
