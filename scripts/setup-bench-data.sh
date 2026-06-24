#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCH_DATA="$PROJECT_DIR/bench-data"

for cmd in git python3; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: $cmd is required but not found"; exit 1; }
done

if [ -d "$BENCH_DATA" ] && [ -f "$BENCH_DATA/META_README.md" ]; then
    echo "✓ CredData already downloaded in $BENCH_DATA"
    echo "  (delete it and re-run to refresh)"
    exit 0
fi

echo "==> Cloning Samsung/CredData..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
git clone --depth 1 https://github.com/Samsung/CredData.git "$TMP_DIR/creddata"

echo "==> Setting up Python venv..."
python3 -m venv "$TMP_DIR/venv"
PYTHON="$TMP_DIR/venv/bin/python3"
PIP="$TMP_DIR/venv/bin/pip3"
echo "==> Installing Python deps..."
cd "$TMP_DIR/creddata"
"$PIP" install -q -r requirements.txt 2>&1 | tail -5

echo "==> Downloading dataset..."
"$PYTHON" download_data.py

echo "==> Moving dataset to $BENCH_DATA..."
mkdir -p "$BENCH_DATA"
mv data "$BENCH_DATA/data"
mv meta "$BENCH_DATA/meta"
cp README.md "$BENCH_DATA/META_README.md"

echo ""
echo "✓ CredData ready in $BENCH_DATA"
echo "  Meta files:    $(find "$BENCH_DATA/meta" -name '*.csv' | wc -l)"
echo "  Data files:    $(find "$BENCH_DATA/data" -type f | wc -l)"
