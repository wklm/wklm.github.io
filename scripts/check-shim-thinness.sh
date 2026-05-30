#!/usr/bin/env bash
# check-shim-thinness.sh — prevention guard for the WebAuthn/crypto FFI-shim
# CONTRACT VIOLATION class (the residentKey:'required' enroll bug + the
# Asyncify "Decrypting never finishes" hangs).
#
# TRUSTED.md says the browser FFI shims (C2/C3) may do platform delegation +
# byte marshalling ONLY — never domain branching, protocol construction, or
# POLICY.  A WebAuthn ceremony policy literal baked into an EM_ASM body (which
# COSE algorithms to offer, residentKey / userVerification requirements,
# timeouts) is exactly such a violation, and it is invisible to every ROCQ
# proof and to the single-source guard (which only checks file TYPES).  This
# script lints the EM_ASM / JS bodies of the shim headers (src/*helpers*.h) and
# FAILS if it finds:
#
#   * a COSE / WebAuthn ALGORITHM literal              (alg: , bare -7/-257/-8)
#   * a WebAuthn CEREMONY keyword                      (residentKey,
#       requireResidentKey, userVerification, allowCredentials, timeout:<N>)
#   * a PROTOCOL / ALGORITHM NAME string               ('ECDH','P-256',
#       'AES-GCM','SHA-256','public-key')
#   * an IndexedDB SCHEMA / POLICY token               (indexedDB.open,
#       createObjectStore, keyPath)
#   * an `Asyncify.handleAsync` body with NO `try`     (a crypto.subtle / IDB /
#       WebAuthn rejection in an unresolved async body parks the WASM stack
#       forever — fail CLOSED with try/catch instead).
#
# Each LEGITIMATE hit (the algorithm name that IS the crypto.subtle parameter;
# the WebAuthn options now marshalled from caller-passed BrowserPolicy values;
# the IndexedDB storage schema) is silenced ONLY by an inline, same-line
# attestation comment of the form:
#
#     // TRUSTED-OK(Cn): <reason>
#
# where Cn is the TRUSTED.md boundary (C2 crypto/auth, C3 DOM, ...).  An
# UN-attested hit — e.g. a freshly planted `residentKey:'required'`, or a new
# async body missing its try/catch — fails the build.
#
# Comment-only prose (text after `//` that merely MENTIONS these tokens) is not
# a violation: only the code portion of each line (everything before `//`) is
# matched.  The attestation marker is detected on the whole line.
#
# Wired into .githooks/pre-commit and both deploy workflows (after the R8 step).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The shim headers under audit: src/*helpers*.h (browser_helpers.h,
# browser_helpers_stub.h, crypto_helpers.h, blog_helpers.h, net_helpers.h,
# proc_helpers.h).  The stub is pure no-ops so it never trips, but auditing it
# keeps the set honest.
shopt -s nullglob
headers=(src/*helpers*.h)
if [ ${#headers[@]} -eq 0 ]; then
  echo "check-shim-thinness: no src/*helpers*.h found (nothing to lint)."
  exit 0
fi

marker='TRUSTED-OK('

# Forbidden patterns matched against the CODE portion of a line (pre-comment).
# Name | extended-regex.
pat_names=(
  "COSE alg literal (alg:)"
  "bare COSE algorithm id (-7 / -257 / -8)"
  "WebAuthn ceremony keyword (residentKey/requireResidentKey/userVerification/allowCredentials)"
  "hard-coded timeout literal (timeout:<N>)"
  "protocol/algorithm name string ('ECDH'/'P-256'/'AES-GCM'/'SHA-256'/'public-key')"
  "IndexedDB schema/policy (indexedDB.open / createObjectStore / keyPath)"
)
pat_res=(
  'alg:'
  '(^|[^0-9A-Za-z_])-(7|8|257)([^0-9]|$)'
  '(residentKey|requireResidentKey|userVerification|allowCredentials)'
  'timeout:[[:space:]]*[0-9]'
  "'(ECDH|P-256|AES-GCM|SHA-256|public-key)'"
  '(indexedDB\.open|createObjectStore|keyPath)'
)

rc=0
emit() { # file line message
  [ "$rc" = 0 ] && echo "check-shim-thinness: shim CONTRACT VIOLATION(S) — policy/protocol literals or un-try/catch'd async in an FFI shim:" >&2
  echo "  $1:$2: $3" >&2
  rc=1
}

for h in "${headers[@]}"; do
  lineno=0
  # Track Asyncify.handleAsync bodies.  The safety property is precise: a `try`
  # must guard the body BEFORE its first `await` (an await reachable before any
  # try is the rejection-parks-the-stack hang).  So when a body opens, scan
  # forward — `try` first => OK; `await` (in code) first => violation.  This is
  # robust to comment blocks between the opener and the try (a comment cannot
  # await), unlike a fixed line window.
  async_scan=0      # 1 while inside an open handleAsync body still seeking try
  async_line=0      # line where the handleAsync opened
  async_attested=0
  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))

    # The attestation marker silences EVERYTHING on its line.
    has_marker=0
    case "$line" in *"$marker"*) has_marker=1 ;; esac

    # Code portion = everything before the first `//` (so prose comments that
    # merely mention a keyword are exempt; trailing `// TRUSTED-OK` attestations
    # are stripped here but still detected via has_marker above).
    code="${line%%//*}"

    # ---- pattern checks (skipped if attested) ----
    if [ "$has_marker" = 0 ]; then
      i=0
      while [ $i -lt ${#pat_res[@]} ]; do
        if printf '%s' "$code" | grep -Eq "${pat_res[$i]}"; then
          emit "$h" "$lineno" "${pat_names[$i]} — move it to ROCQ (BrowserPolicy.v) or attest it inline with // ${marker}Cn): <reason>"
        fi
        i=$((i + 1))
      done
    fi

    # ---- Asyncify.handleAsync must wrap its body in try/catch BEFORE await ----
    if [ "$async_scan" = 1 ]; then
      [ "$has_marker" = 1 ] && async_attested=1
      case "$code" in
        *"try"*) async_scan=0 ;;                    # guarded — good
        *"await"*)
          async_scan=0
          if [ "$async_attested" = 0 ]; then
            emit "$h" "$async_line" "Asyncify.handleAsync body reaches 'await' with no enclosing try/catch — a rejected await parks the WASM stack forever; wrap it and return a fail-closed sentinel (or attest with // ${marker}Cn): <reason>)"
          fi
          ;;
      esac
    fi
    # Open a new scan when we see handleAsync in CODE.  First inspect the SAME
    # line after the handleAsync token (a single-line body must not slip
    # through): if a `try` precedes any `await` there, it's already guarded; if
    # an `await` appears first on this line, flag it now; otherwise fall through
    # to the multi-line scan on subsequent lines.
    case "$code" in
      *Asyncify.handleAsync*)
        rest_same="${code#*Asyncify.handleAsync}"
        # Truncate at the first `try` so a later `await` (inside the try) is fine.
        before_try="${rest_same%%try*}"
        if [ "$has_marker" = 0 ] && [ "$before_try" != "$rest_same" ]; then
          : # a `try` appears on this same line, ahead of anything after it — guarded
        elif [ "$has_marker" = 0 ] && case "$rest_same" in *await*) true ;; *) false ;; esac; then
          emit "$h" "$lineno" "Asyncify.handleAsync body reaches 'await' with no enclosing try/catch — a rejected await parks the WASM stack forever; wrap it and return a fail-closed sentinel (or attest with // ${marker}Cn): <reason>)"
          async_scan=0
        elif case "$rest_same" in *try*) true ;; *) false ;; esac; then
          async_scan=0   # guarded on the same line
        else
          async_scan=1   # seek try/await on following lines
          async_line=$lineno
          async_attested=$has_marker
        fi
        ;;
    esac
  done < "$h"
done

if [ "$rc" != 0 ]; then
  echo "" >&2
  echo "Ceremony/protocol POLICY belongs in ROCQ (src/BrowserPolicy.v), passed to the shim as arguments." >&2
  echo "Algorithm names that ARE the crypto.subtle parameter, options marshalled from caller-passed" >&2
  echo "policy values, and the IndexedDB storage schema are legitimate — attest each inline:" >&2
  echo "    // ${marker}C2): <why this is platform marshalling, not policy>" >&2
  exit 1
fi
echo "check-shim-thinness: OK — ${#headers[@]} shim header(s) carry no un-attested policy/protocol literals and every Asyncify.handleAsync body fails closed."
