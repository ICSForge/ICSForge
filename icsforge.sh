#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# ZIP extraction may drop executable bits; auto-fix.
if [ ! -x "$DIR/bin/icsforge" ]; then
  chmod +x "$DIR/bin/icsforge" 2>/dev/null || true
fi
exec "$DIR/bin/icsforge" "$@"
