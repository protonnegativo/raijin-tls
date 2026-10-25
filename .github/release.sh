#!/usr/bin/env bash
# Tags HEAD with the next release and creates its GitHub Release.
# Usage: release.sh [patch|minor|major]   (default patch)
# With BEFORE set (the commit before a push), it skips a push that only touched files the binary does
# not use. It skips HEAD when it already has a tag. Needs GH_TOKEN for gh.
set -euo pipefail

bump=${1:-patch}
case "$bump" in patch|minor|major) ;; *) echo "bump must be patch, minor or major, not $bump" >&2; exit 1 ;; esac

if [ -n "$(git tag --points-at HEAD 'v*')" ]; then
  echo "HEAD is already tagged $(git tag --points-at HEAD 'v*' | head -1); nothing to release"
  exit 0
fi

# engines.json is embedded in the binary, so it releases; fixtures, docs and CI do not
if [ -n "${BEFORE:-}" ] && ! [[ "$BEFORE" =~ ^0+$ ]] && git cat-file -e "$BEFORE^{commit}" 2>/dev/null; then
  changed=$(git diff --name-only "$BEFORE" HEAD | grep -vE '^bench/fixtures/|\.md$|^docs/|^\.github/' || true)
  if [ -z "$changed" ]; then
    echo "only fixtures, docs or CI changed; nothing to release"
    exit 0
  fi
fi

latest=$(git tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1 || true)
if [ -z "$latest" ]; then
  tag=v0.1.0
else
  IFS=. read -r major minor patch <<< "${latest#v}"
  case "$bump" in
    major) tag="v$((major + 1)).0.0" ;;
    minor) tag="v$major.$((minor + 1)).0" ;;
    patch) tag="v$major.$minor.$((patch + 1))" ;;
  esac
fi

git config user.name >/dev/null || git config user.name "github-actions[bot]"
git config user.email >/dev/null || git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git tag -a "$tag" -m "$tag"
git push origin "$tag"
gh release create "$tag" --generate-notes --verify-tag
echo "released $tag"
