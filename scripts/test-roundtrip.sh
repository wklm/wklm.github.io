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
container=""
docker_step() {
    local seconds="$1"
    shift
    "$@" &
    local pid="$!"
    local elapsed=0
    while kill -0 "$pid" 2>/dev/null; do
        if (( elapsed >= seconds )); then
            echo "FAIL: timed out after ${seconds}s: $*" >&2
            kill "$pid" 2>/dev/null || true
            sleep 2
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    wait "$pid"
}

cleanup() {
    if [[ -n "${container:-}" ]]; then
        docker_step 20 docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    rm -rf "$scratch"
    rm -f posts/fixture.md posts/fixture.bin posts-encrypted/fixture.eml
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
export CRANE_BLOG_AUTHOR_EMAIL="$author"

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
orig_img_sha="$(shasum -a 256 posts/fixture.bin | cut -d ' ' -f 1)"

"$enc" posts/fixture.md

test -f posts-encrypted/fixture.eml

# The envelope must carry the advertised protocol parameter.
grep -q 'application/pgp-encrypted' posts-encrypted/fixture.eml
grep -q 'BEGIN PGP MESSAGE' posts-encrypted/fixture.eml
# Outer Subject is literally the placeholder.
grep -E '^Subject: \.\.\.' posts-encrypted/fixture.eml > /dev/null
if grep -E '^(From|To|Date): ' posts-encrypted/fixture.eml >/dev/null; then
    echo "FAIL: outer envelope exposes sender, recipient, or date metadata" >&2
    exit 1
fi

# PKESK inspection -- ask gpg directly.
awk '/BEGIN PGP MESSAGE/,/END PGP MESSAGE/' posts-encrypted/fixture.eml \
  | gpg --list-packets 2>&1 \
  | grep -q 'pubkey enc packet'

# Decrypt via the OCaml tool (writes to posts/).
rm -f posts/fixture.md posts/fixture.bin
"$dec" posts-encrypted/fixture.eml
roundtripped_md="$(cat posts/fixture.md)"
roundtripped_img_sha="$(shasum -a 256 posts/fixture.bin | cut -d ' ' -f 1)"

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

# Build the Rocq/Crane generator and site in Docker only. The host does not
# need Rocq, Crane, or coqc installed.
if ! command -v docker >/dev/null 2>&1; then
    echo "docker not on PATH; the Rocq/Crane generator is container-only" >&2
    exit 1
fi
image="${CRANE_BLOG_DOCKER_IMAGE:-crane-blog-roundtrip}"
published_image="${CRANE_BLOG_GENERATOR_IMAGE:-ghcr.io/wklm/crane-blog-generator:latest}"
build_timeout="${CRANE_BLOG_DOCKER_BUILD_TIMEOUT:-1800}"
pull_timeout="${CRANE_BLOG_DOCKER_PULL_TIMEOUT:-300}"
run_timeout="${CRANE_BLOG_DOCKER_RUN_TIMEOUT:-120}"
inspect_timeout="${CRANE_BLOG_DOCKER_INSPECT_TIMEOUT:-20}"
container="crane-blog-roundtrip-$$"
if [[ "${CRANE_BLOG_BUILD_GENERATOR:-0}" == "1" ]]; then
    docker_step "$build_timeout" docker build --target runtime -t "$image" .
else
    image="$published_image"
    if ! docker_step "$inspect_timeout" docker image inspect "$image" >/dev/null 2>&1; then
        docker_step "$pull_timeout" docker pull "$image"
    fi
fi
rm -rf _site
mkdir -p _site
docker_step "$run_timeout" docker run --name "$container" --rm \
    -v "$PWD/posts-encrypted:/site/posts-encrypted:ro" \
    -v "$PWD/_site:/site/_site" \
    "$image"
container=""
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
if grep -q 'Round-trip fixture' _site/fixture/index.html _site/index.html; then
    echo "FAIL: plaintext title leaked into rendered HTML" >&2
    exit 1
fi
if grep -q '<dt>Subject</dt>' _site/fixture/index.html; then
    echo "FAIL: Subject header row rendered on post page" >&2
    exit 1
fi
if ! grep -q 'Subject: ...' _site/fixture/index.html; then
    echo "FAIL: post page missing placeholder subject" >&2
    exit 1
fi
echo "site lint OK"

echo "round-trip test passed"
