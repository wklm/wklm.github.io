#!/usr/bin/env bash
# check-dom-coherence.sh — static checker: every dom_* DOM target is a PageModel constant.
#
# Phase 2 of the crane_blog verification pipeline ensures every DOM target
# exists on the page that loads the app.  This pre-commit guard enforces the
# prerequisite: that DecryptApp.v and EnrollApp.v use the shared id_* constants
# from PageModel.v (the single source of truth), never raw string literals.
#
# Fails if:
#   1. A dom_* call uses a raw string literal ("foo") instead of an id_* constant.
#   2. A dom_* call references an identifier not defined in PageModel.v.
#
# Design:
#   1. Strips Coq (* ... *) comments (including nested) from the app sources.
#   2. Extracts the first string argument from every dom_get_text, dom_set_text,
#      dom_set_html, dom_show, dom_hide call in the comment-free code.
#   3. Checks each target is an id_* constant defined in PageModel.v.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

APPS=(src/DecryptApp.v src/EnrollApp.v)
MODEL=src/PageModel.v

# ---- helpers ---------------------------------------------------------------
fail() { echo "check-dom-coherence: FAIL — $*" >&2; exit 1; }
warn() { echo "check-dom-coherence: $*" >&2; }

# ---- extract PageModel ID constants ----------------------------------------
readarray -t MODEL_IDS < <(
  grep -oE '^Definition id_[a-z0-9_]+' "$MODEL" | sed 's/^Definition //'
)

if [[ ${#MODEL_IDS[@]} -eq 0 ]]; then
  fail "no id_* constants found in $MODEL"
fi

is_page_model_id() {
  local id="$1"
  for mid in "${MODEL_IDS[@]}"; do
    [[ "$id" == "$mid" ]] && return 0
  done
  return 1
}

# ---- strip Coq comments (handles nested (* ... *)) -------------------------
# Output format: ORIGINAL_FILENAME:LINE_NUMBER:STRIPPED_CODE
strip_comments() {
  awk '
  BEGIN { depth = 0 }
  {
    code = ""
    for (i = 1; i <= length($0); i++) {
      c2 = substr($0, i, 2)
      if (c2 == "(*") { depth++; i++; continue }
      if (c2 == "*)") { if (depth > 0) depth--; i++; continue }
      if (depth == 0) code = code substr($0, i, 1)
    }
    printf "%s:%d:%s\n", FILENAME, FNR, code
  }' "$@"
}

# ---- scan ------------------------------------------------------------------
warn "scanning ${APPS[*]} ..."

rc=0  seen=0

while IFS=: read -r file line code; do
  target=$(echo "$code" | sed -nE \
    's/.*dom_(get_text|set_text|set_html|show|hide)[[:space:]]+(id_[a-zA-Z0-9_]+|"[^"]*").*/\2/p')
  [[ -z "$target" ]] && continue

  seen=$((seen + 1))

  if [[ "$target" == \"* ]]; then
    warn "  $file:$line: raw string literal $target"
    warn "    Replace with a PageModel constant (id_*) from $MODEL"
    rc=1
  elif ! is_page_model_id "$target"; then
    warn "  $file:$line: undefined identifier $target (not a PageModel constant from $MODEL)"
    rc=1
  fi
done < <(strip_comments "${APPS[@]}")

# ---- report ----------------------------------------------------------------
if [[ "$rc" != 0 ]]; then
  warn ""
  warn "All DOM target arguments must use shared PageModel constants (id_*)."
  warn "Raw string literals are forbidden — they break the single source of truth."
  exit 1
fi

echo "check-dom-coherence: PASS — all $seen DOM arguments use shared PageModel constants"
echo "check-dom-coherence: no raw string literals or undefined IDs found"
