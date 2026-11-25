#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: ./scripts/release.sh <version>   (e.g. ./scripts/release.sh 0.2.0)" >&2
  exit 1
fi

VERSION="${1#v}"
TAG="v${VERSION}"

if ! echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  echo "Invalid semver: $VERSION" >&2
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree is not clean. Commit or stash changes before releasing." >&2
  exit 1
fi

python3 - "$VERSION" <<'PY'
import re, sys
version = sys.argv[1]
with open("Cargo.toml", "r") as f:
    text = f.read()
updated, n = re.subn(r'(?m)^version = "[^"]+"', f'version = "{version}"', text, count=1)
assert n == 1, "Could not find version in Cargo.toml"
with open("Cargo.toml", "w") as f:
    f.write(updated)
PY

cargo check --quiet
cargo test --quiet

git add Cargo.toml Cargo.lock
git commit -m "Release ${TAG}"
git tag -a "${TAG}" -m "bottledeck ${TAG}"
git push origin main "${TAG}"

echo ""
echo "Pushed ${TAG}! GitHub Actions is now building binaries for macOS & Linux:"
echo "  https://github.com/timuric/bottledeck/actions"
echo ""
echo "Once published, users upgrade with:"
echo "  bottledeck update"
