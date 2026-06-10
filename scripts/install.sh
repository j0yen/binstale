#!/usr/bin/env bash
# install.sh — build and install binstale to ~/.local/bin/binstale
#
# Usage: bash scripts/install.sh
#
# Builds a release binary via cargo and copies it to ~/.local/bin/.
# Requires cargo in PATH or the cloudbuild.sh helper for remote builds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEST="${HOME}/.local/bin/binstale"

echo "binstale install: building release binary..."

# Prefer the cloud builder if available; fall back to local cargo.
CLOUDBUILD="${HOME}/.claude/skills/cloudbuild/cloudbuild.sh"

if [[ -x "$CLOUDBUILD" ]]; then
  echo "binstale install: using cloud builder..."
  bash "$CLOUDBUILD" sync "$REPO_ROOT"
  bash "$CLOUDBUILD" ssh 'cd /root/build/binstale && . ~/.cargo/env && cargo build --release 2>&1'
  bash "$CLOUDBUILD" ssh 'cat /root/build/binstale/target/release/binstale' > /tmp/binstale-release
  chmod +x /tmp/binstale-release
  cp /tmp/binstale-release "$DEST"
else
  # Local build fallback.
  cd "$REPO_ROOT"
  cargo build --release
  cp target/release/binstale "$DEST"
fi

chmod +x "$DEST"
echo "binstale install: installed to $DEST"
"$DEST" --version
