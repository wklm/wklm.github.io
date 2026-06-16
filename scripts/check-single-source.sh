#!/usr/bin/env bash
# R8 — single-source contract guard (pre-commit + CI).
#
# crane_blog's contract: every behavioral decision (bytes produced, control flow,
# accept/reject) lives in a ROCQ .v file, Crane-extracted to C++ -> native/WASM.
# The ONLY permitted non-.v artifacts are thin FFI-shim headers realizing declared
# ROCQ axioms, build/ops config, docs, the e2e test harness, and data.  This guard
# fails if any tracked file falls outside that allowlist — e.g. a .js / .ml / .py /
# committed .cpp creeping back in, which would mean behavioral logic living outside
# ROCQ.  It is a FILE-TYPE allowlist; shim *thinness* is governed by TRUSTED.md +
# review, not here.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

rc=0
while IFS= read -r f; do
  case "$f" in
    *.v) ;;                                                  # ROCQ — the source of truth
    *.h|*.md|*.yml|*.yaml|*.json|*.sh|*.eml) ;;              # FFI-shim headers, docs, CI/ops config, data
    dune|*/dune|dune-project|Dockerfile|*/Dockerfile) ;;    # dune + container build config
    .dockerignore|.gitignore|.gitkeep|*/.gitkeep) ;;        # vcs/keep markers
    .githooks/*|.vscode/*|.devcontainer/*) ;;               # hook / editor / devcontainer config
    tests/e2e/*.ts|tests/e2e/*.mjs|playwright.config.ts) ;; # Playwright e2e harness (TS/MJS required)
    static/*.mjs|static/*.wasm) ;;                          # WASM build artifacts (Crane-extracted, em++-linked)
    static/ratex-wasm/*) ;;                                 # RaTeX WASM library for KaTeX rendering
    *)
      [ "$rc" = 0 ] && echo "R8 single-source contract violation — non-.v file(s) outside the allowlist:" >&2
      echo "  $f" >&2
      rc=1 ;;
  esac
done < <(git ls-files)

if [ "$rc" != 0 ]; then
  echo "Behavioral logic must live in ROCQ (.v); permitted non-.v categories are documented in TRUSTED.md." >&2
  exit 1
fi
echo "R8: OK — all $(git ls-files | wc -l | tr -d ' ') tracked files are .v or within the single-source allowlist."
