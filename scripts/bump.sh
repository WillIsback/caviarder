#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <new-version>"
  echo "Example: $0 0.3.1"
  exit 1
fi

NEW_VER="$1"

# Validate semver
if ! echo "$NEW_VER" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "error: '$NEW_VER' is not a valid semver (expected X.Y.Z)"
  exit 1
fi

cd "$(git rev-parse --show-toplevel)"

# Read current version
CUR_VER="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml)"
echo "Bumping: $CUR_VER → $NEW_VER"

# 1. Update Cargo.toml
sed -i "s/^version = \"$CUR_VER\"/version = \"$NEW_VER\"/" Cargo.toml

# 2. Sync Cargo.lock
cargo generate-lockfile

# 3. Commit both
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to $NEW_VER"

# 4. Tag
git tag "v$NEW_VER"

# 5. Push
echo ""
echo "Commit and tag created. Push with:"
echo "  git push && git push origin v$NEW_VER"
