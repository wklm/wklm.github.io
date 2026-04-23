#!/usr/bin/env bash
# setup-hooks.sh -- one-shot per-clone install.
# Points git at the tracked .githooks/ directory so the pre-commit
# encryption hook is active for every commit on this worktree.
set -euo pipefail
repo="$(git rev-parse --show-toplevel)"
cd "$repo"
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit scripts/*.sh scripts/*.py 2>/dev/null || true
echo "git hooks -> .githooks/"
