#!/bin/sh
# Every `uses: owner/repo[/path]@<40-hex> # <tag>` in .github/workflows must name the commit that
# <tag> points to in owner/repo (anonymous git ls-remote, annotated tags dereferenced). Local
# (./) and docker:// uses are skipped; any other form (no SHA or no tag comment) fails.
set -eu
cd "$(git rev-parse --show-toplevel)"
fail=0; n=0
grep -hE '^[[:space:]]*-?[[:space:]]*uses:' .github/workflows/*.yml .github/workflows/*.yaml 2>/dev/null | sort -u > /tmp/uses.$$ || true
while IFS= read -r line; do
  ref=$(printf '%s' "$line" | sed -E 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*//')
  case $ref in ./*|docker://*) continue ;; esac
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
done < /tmp/uses.$$
rm -f /tmp/uses.$$
[ "$n" -gt 0 ] || { echo "FAIL no pinned uses found"; exit 1; }
exit "$fail"
