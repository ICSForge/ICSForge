#!/usr/bin/env bash
# ICSForge release builder — produces a clean .tar.gz with executable bits preserved.
# Usage: bash scripts/release.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=$(python3 -c "import sys; sys.path.insert(0,'$REPO_ROOT'); from icsforge import __version__; print(__version__)")
DIST_NAME="ICSForge-v${VERSION}"
DIST_DIR="/tmp/${DIST_NAME}"
OUT="${REPO_ROOT}/dist/${DIST_NAME}.tar.gz"

echo "Building $DIST_NAME"
echo "  Source: $REPO_ROOT"
echo "  Output: $OUT"

# Clean
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR" "$(dirname "$OUT")"

# Copy source, excluding build artifacts
rsync -a --exclude='.git' \
         --exclude='__pycache__' \
         --exclude='*.pyc' \
         --exclude='.pytest_cache' \
         --exclude='*.egg-info' \
         --exclude='out/runs.db' \
         --exclude='out/reports' \
         --exclude='out/events' \
         --exclude='out/pcaps' \
         --exclude='.venv' \
         --exclude='dist' \
         --exclude='build' \
         --exclude='*.original' \
         --exclude='node_modules' \
         --exclude='.ruff_cache' \
         "$REPO_ROOT/" "$DIST_DIR/"

# Ensure executable bits
chmod +x "$DIST_DIR/bin/icsforge" 2>/dev/null || true
chmod +x "$DIST_DIR/icsforge.sh" 2>/dev/null || true
chmod +x "$DIST_DIR/scripts/"*.py 2>/dev/null || true

# Build tar.gz (preserves permissions)
cd /tmp
tar czf "$OUT" "$DIST_NAME"

# Verify
echo ""
echo "Release artifact: $OUT"
echo "Size: $(du -h "$OUT" | cut -f1)"
echo ""
echo "Contents:"
tar tf "$OUT" | head -20
echo "  ..."
echo ""

# Verify executable bit
tar tf "$OUT" --verbose | grep "bin/icsforge" | head -1

# Clean up
rm -rf "$DIST_DIR"

echo ""
echo "Done. Distribute: $OUT"
