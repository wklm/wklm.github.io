#!/usr/bin/env bash
# test-roundtrip.sh -- end-to-end check of the encryption pipeline.
# Creates an ephemeral GPG home, an author key, encrypts a fixture
# post + image via tools/encrypt_post, decrypts via
# tools/decrypt_post, and diffs the round-tripped bytes against the
# originals.  Also lint-checks the output page HTML for metadata
# leaks.
set -euo pipefail

repo="$(git rev-parse --show-toplevel)"
cd "$repo"

scratch="$(mktemp -d)"
old_email="$(git config --get user.email || true)"
cleanup() {
    rm -rf "$scratch"
    rm -f posts/fixture.md posts/fixture.bin posts-encrypted/fixture.eml
    if [[ -n "$old_email" ]]; then
        git config user.email "$old_email"
    else
        git config --unset user.email || true
    fi
}
trap cleanup EXIT

export GNUPGHOME="$scratch/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

author="roundtrip@example.com"
cat > "$scratch/keyparams" <<EOF
%no-protection
Key-Type: EDDSA
Key-Curve: ed25519
Key-Usage: sign
Subkey-Type: ECDH
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: Roundtrip Tester
Name-Email: $author
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key "$scratch/keyparams" 2>/dev/null
git config user.email "$author"

# Build the tools.
if ! command -v dune >/dev/null 2>&1; then
    echo "dune not on PATH; run 'eval \$(opam env)' first" >&2
    exit 1
fi
dune build tools/encrypt_post.exe tools/decrypt_post.exe
enc="./_build/default/tools/encrypt_post.exe"
dec="./_build/default/tools/decrypt_post.exe"

# Fixture
mkdir -p posts
cat > posts/fixture.md <<'EOF'
---
title: Round-trip fixture
date: 2026-04-23
slug: fixture
---

Hello inside the ciphertext. ![alt](fixture.bin)
EOF
# Deterministic 32-byte "binary" blob.
printf '\x89PNG\r\n\x1a\n\x00\x01\x02\x03binary-image-bytes-xyz' > posts/fixture.bin

orig_md="$(cat posts/fixture.md)"
orig_img_sha="$(sha256sum posts/fixture.bin | awk '{print $1}')"

"$enc" posts/fixture.md

test -f posts-encrypted/fixture.eml

# The envelope must carry the advertised protocol parameter.
grep -q 'application/pgp-encrypted' posts-encrypted/fixture.eml
grep -q 'BEGIN PGP MESSAGE' posts-encrypted/fixture.eml
# Outer Subject is literally the placeholder.
grep -E '^Subject: \.\.\.' posts-encrypted/fixture.eml > /dev/null

# PKESK inspection -- ask gpg directly.
awk '/BEGIN PGP MESSAGE/,/END PGP MESSAGE/' posts-encrypted/fixture.eml \
  | gpg --list-packets 2>&1 \
  | grep -q 'pubkey enc packet'

# Decrypt via the OCaml tool (writes to posts/).
rm -f posts/fixture.md posts/fixture.bin
"$dec" posts-encrypted/fixture.eml
roundtripped_md="$(cat posts/fixture.md)"
roundtripped_img_sha="$(sha256sum posts/fixture.bin | awk '{print $1}')"

if [[ "$orig_md" != "$roundtripped_md" ]]; then
    echo "FAIL: markdown mismatch after round-trip" >&2
    diff <(printf '%s' "$orig_md") <(printf '%s' "$roundtripped_md") || true
    exit 1
fi
if [[ "$orig_img_sha" != "$roundtripped_img_sha" ]]; then
    echo "FAIL: image mismatch after round-trip" >&2
    exit 1
fi
echo "round-trip OK"

# Build the site and lint the HTML for leaks.
dune build src/blog_generator.exe
rm -rf _site
./_build/default/src/blog_generator.exe
if grep -R -l '<img' _site >/dev/null 2>&1; then
    echo "FAIL: <img tag present in site" >&2
    exit 1
fi
if ! grep -q 'BEGIN PGP MESSAGE' _site/fixture/index.html; then
    echo "FAIL: post page missing PGP MESSAGE armor" >&2
    exit 1
fi
if grep -E '>Subject: [^.<]' _site/index.html >/dev/null 2>&1; then
    echo "FAIL: non-placeholder Subject on inbox" >&2
    exit 1
fi
echo "site lint OK"

echo "round-trip test passed"
