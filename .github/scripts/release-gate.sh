#!/bin/sh
# Gate for `make release` (local publishing). All of these must hold:
# GITHUB_TOKEN set; clean tree; go1.27.3; HEAD carries exactly one v* tag, which is annotated;
# that tag is already on origin and points (peeled) at HEAD.
set -eu
die() { echo "release gate: $*" >&2; exit 1; }
[ -n "${GITHUB_TOKEN:-}" ] || die "GITHUB_TOKEN is not set"
[ -z "$(git status --porcelain)" ] || die "working tree is not clean"
[ "$(go env GOVERSION)" = go1.27.3 ] || die "need go1.27.3, have $(go env GOVERSION)"
tags=$(git tag --points-at HEAD --list 'v[0-9]*')
[ -n "$tags" ] || die "HEAD has no v* tag"
[ "$(printf '%s\n' "$tags" | wc -l)" -eq 1 ] || die "HEAD has several v* tags: $tags"
tag=$tags
[ "$(git cat-file -t "refs/tags/$tag")" = tag ] || die "$tag is a lightweight tag; use git tag -a"
head=$(git rev-parse HEAD)
[ "$(git rev-parse "refs/tags/$tag^{commit}")" = "$head" ] || die "$tag does not point at HEAD"
remote=$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}") || die "git ls-remote origin failed"
robj=$(printf '%s\n' "$remote" | awk -v r="refs/tags/$tag" '$2==r{print $1}')
rcommit=$(printf '%s\n' "$remote" | awk -v r="refs/tags/$tag^{}" '$2==r{print $1}')
[ -n "$robj" ] || die "$tag is not pushed to origin (git push origin $tag)"
[ -n "$rcommit" ] || die "origin's $tag is not an annotated tag"
[ "$robj" = "$(git rev-parse "refs/tags/$tag")" ] || die "origin's $tag object differs from the local tag"
[ "$rcommit" = "$head" ] || die "origin's $tag points at $rcommit, not HEAD $head"
echo "release gate: OK ($tag = $head, annotated, on origin)"
