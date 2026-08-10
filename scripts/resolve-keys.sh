#!/usr/bin/env bash
# resolve-keys.sh -- fetch missing reader public keys by their short ID from
# the crane-blog key directory.
#
# The key directory is a public Cloudflare Worker + KV (crane-blog-keydir);
# registration is self-authenticating (kid == sha256(compress(pubkey))[:12]),
# so a 12-hex kid resolves to exactly one public key, and public keys are
# public.  This script is the read side: given the short IDs readers send,
# it materializes keys/<kid>.pub (gitignored) automatically — the author
# never saves a key file by hand.
#
# Usage: scripts/resolve-keys.sh <kid> [<kid> ...]
#   For each kid not already present as keys/<kid>.pub, GET
#   $KEYDIR_URL/keys/<kid> and write the 130-hex uncompressed SEC1 pubkey
#   to keys/<kid>.pub.  Exits non-zero if any kid is unknown or unreachable.
set -euo pipefail

KEYDIR_URL="${KEYDIR_URL:-https://crane-blog-keydir.wojtekkulma.workers.dev}"

repo="$(git rev-parse --show-toplevel)"
cd "$repo"
mkdir -p keys

status=0
for kid in "$@"; do
    if [[ ! "$kid" =~ ^[0-9a-f]{12}$ ]]; then
        echo "resolve-keys: invalid kid '$kid'" >&2
        exit 1
    fi
    if [[ -f "keys/$kid.pub" ]]; then
        continue
    fi
    if out="$(curl -fsS --max-time 10 "$KEYDIR_URL/keys/$kid" 2>/dev/null)"; then
        if [[ "$out" =~ ^[0-9a-f]{130}$ ]]; then
            printf '%s' "$out" > "keys/$kid.pub"
            echo "resolve-keys: resolved $kid -> keys/$kid.pub"
        else
            echo "resolve-keys: $kid: unexpected response from directory" >&2
            status=1
        fi
    else
        echo "resolve-keys: $kid: unknown or unreachable in key directory" >&2
        status=1
    fi
done
exit "$status"
