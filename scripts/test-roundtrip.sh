#!/usr/bin/env bash
# test-roundtrip.sh -- end-to-end check of the HPKE encryption pipeline.
# Generates a test ECDH P-256 keypair via openssl, encrypts a fixture
# post with encrypt_post, decrypts with decrypt_post, and diffs the
# round-tripped bytes against the originals.  Also lint-checks the
# generated HTML for metadata leaks.
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
    rm -f posts/fixture-noaad.md posts-encrypted/fixture-noaad.eml
    rm -f "keys/${key_id:-}.pub"
}
trap cleanup EXIT

# ---- Generate test ECDH P-256 keypair ----
if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl required for test key generation" >&2
    exit 1
fi

openssl ecparam -name prime256v1 -genkey -noout -out "$scratch/key.pem" 2>/dev/null

# Extract uncompressed public key (65 bytes: 04 || x || y)
pub_hex=$(openssl ec -in "$scratch/key.pem" -pubout -conv_form uncompressed 2>/dev/null |
  openssl pkey -pubin -outform DER 2>/dev/null |
  tail -c 65 | xxd -p -c 999 | tr -d '\n')

# Extract private key scalar (32 bytes)
priv_hex=$(openssl ec -in "$scratch/key.pem" -text -noout 2>/dev/null |
  awk '/priv:/{getline; gsub(/[ :]/,""); print}' | tr -d '\n')

# Compute key ID = first 12 chars of SHA-256(pubkey)
key_id=$(printf '%s' "$pub_hex" | xxd -r -p | shasum -a 256 | cut -c 1-12)

mkdir -p keys
printf '%s' "$pub_hex" > "keys/$key_id.pub"

export CRANE_BLOG_AUTHOR_KEY_ID="$key_id"
export CRANE_BLOG_AUTHOR_EMAIL="test@crane.blog"
export CRANE_BLOG_PRIVATE_KEY="$priv_hex"

# ---- Build the tools ----
if ! command -v dune >/dev/null 2>&1; then
    echo "dune not on PATH; run 'eval \$(opam env)' first" >&2
    exit 1
fi
dune build tools/encrypt_post.exe tools/decrypt_post.exe
enc="./_build/default/tools/encrypt_post.exe"
dec="./_build/default/tools/decrypt_post.exe"

# ---- Fixture ----
mkdir -p posts
cat > posts/fixture.md <<'EOF'
---
title: Round-trip fixture
date: 2026-04-23
slug: fixture
---
Hello inside the ciphertext. ![alt](fixture.bin)
EOF
# Deterministic 32-byte "binary" blob
printf '\x89PNG\r\n\x1a\n\x00\x01\x02\x03binary-image-bytes-xyz' > posts/fixture.bin

orig_md="$(cat posts/fixture.md)"
orig_img_sha="$(shasum -a 256 posts/fixture.bin | cut -d ' ' -f 1)"

# ---- Encrypt ----
"$enc" posts/fixture.md
test -f posts-encrypted/fixture.eml

# ---- Validate envelope ----
grep -q 'multipart/hpke+wrapped' posts-encrypted/fixture.eml \
  || { echo "FAIL: envelope missing multipart/hpke+wrapped"; exit 1; }
grep -q 'application/wrapped-keys' posts-encrypted/fixture.eml \
  || { echo "FAIL: envelope missing wrapped-keys part"; exit 1; }
grep -q 'application/aes-gcm' posts-encrypted/fixture.eml \
  || { echo "FAIL: envelope missing aes-gcm part"; exit 1; }
grep -E '^Subject: \.\.\.' posts-encrypted/fixture.eml > /dev/null \
  || { echo "FAIL: outer Subject not placeholder"; exit 1; }
if grep -E '^(From|To|Date): ' posts-encrypted/fixture.eml >/dev/null; then
    echo "FAIL: outer envelope exposes sender, recipient, or date metadata" >&2
    exit 1
fi
grep -q "Public-Keys: $key_id" posts-encrypted/fixture.eml \
  || { echo "FAIL: envelope missing Public-Keys header"; exit 1; }

# ---- Decrypt ----
rm -f posts/fixture.md posts/fixture.bin
"$dec" posts-encrypted/fixture.eml
roundtripped_md="$(cat posts/fixture.md)"
roundtripped_img_sha="$(shasum -a 256 posts/fixture.bin 2>/dev/null | cut -d ' ' -f 1 || echo "")"

if [[ "$orig_md" != "$roundtripped_md" ]]; then
    echo "FAIL: markdown mismatch after round-trip" >&2
    diff <(printf '%s' "$orig_md") <(printf '%s' "$roundtripped_md") || true
    exit 1
fi
if [[ -n "$roundtripped_img_sha" && "$orig_img_sha" != "$roundtripped_img_sha" ]]; then
    echo "FAIL: image mismatch after round-trip" >&2
    exit 1
fi
echo "round-trip OK"

# ---- AAD backward-compat fallback test ----
# Builds a second .eml encrypted with empty AAD (old format before the
# key_id + slug AAD binding was added) and verifies decrypt_post's
# fallback path handles it correctly.
echo "Testing AAD backward-compat fallback..."

# SPKI DER prefix for P-256 so openssl pkeyutl -derive can read the
# raw uncompressed public key as a valid SubjectPublicKeyInfo.
spki_prefix="3059301306072a8648ce3d020106082a8648ce3d030107034200"
printf '%s%s' "$spki_prefix" "$pub_hex" | xxd -r -p > "$scratch/recipient.der"
openssl pkey -pubin -inform DER -in "$scratch/recipient.der" \
  -out "$scratch/recipient.pem" 2>/dev/null

# Ephemeral keypair for the no-AAD wrap
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$scratch/eph-noaad.pem" 2>/dev/null
eph_pub_noaad_hex=$(openssl ec -in "$scratch/eph-noaad.pem" \
  -pubout -conv_form uncompressed 2>/dev/null |
  openssl pkey -pubin -outform DER 2>/dev/null |
  tail -c 65 | xxd -p -c 999 | tr -d '\n')

# Derive wrapping key via custom KDF (matches custom_kdf_sha256 in crane_crypto.ml)
openssl pkeyutl -derive -inkey "$scratch/eph-noaad.pem" \
  -peerkey "$scratch/recipient.pem" -out "$scratch/noaad-shared.bin" 2>/dev/null

custom_kdf_hex() {
  local info="$1"
  local prk info_hex
  prk=$( (printf '\x00%.0s' {1..32}; cat "$scratch/noaad-shared.bin") |
    shasum -a 256 | cut -d' ' -f1)
  info_hex=$(printf '%s' "$info" | xxd -p)
  (printf '%s' "$prk" | xxd -r -p;
   printf '%s' "$info_hex" | xxd -r -p;
   printf '\x01') | shasum -a 256 | cut -d' ' -f1
}

wrap_key_hex=$(custom_kdf_hex "crane-blog-wrap-v1")

# Wrap a random CEK with empty AAD
cek_noaad_hex=$(openssl rand -hex 32)
wrap_nonce_hex=$(openssl rand -hex 12)
wrapped_pkg_hex="${wrap_nonce_hex}$(
  printf '%s' "$cek_noaad_hex" | xxd -r -p |
  openssl enc -aes-256-gcm -K "$wrap_key_hex" -iv "$wrap_nonce_hex" \
    -nosalt 2>/dev/null | xxd -p -c 999 | tr -d '\n')"

# Encrypt body with empty AAD
noaad_body="Fallback AAD test body"
body_nonce_hex=$(openssl rand -hex 12)
ct_package_hex="${body_nonce_hex}$(
  printf '%s' "$noaad_body" |
  openssl enc -aes-256-gcm -K "$cek_noaad_hex" -iv "$body_nonce_hex" \
    -nosalt 2>/dev/null | xxd -p -c 999 | tr -d '\n')"
ct_b64=$(printf '%s' "$ct_package_hex" | xxd -r -p | base64 | tr -d '\n')

noaad_key_id=$(printf '%s' "$pub_hex" | xxd -r -p | shasum -a 256 | cut -c 1-12)
cat > "posts-encrypted/fixture-noaad.eml" <<EOF
Content-Type: multipart/hpke+wrapped; boundary="---noaad"
Public-Keys: $noaad_key_id

-----noaad
Content-Type: application/wrapped-keys
Wraps: $noaad_key_id:$eph_pub_noaad_hex:$wrapped_pkg_hex

-----noaad
Content-Type: application/aes-gcm
Content-Transfer-Encoding: base64

$ct_b64
-----noaad--
EOF

rm -f posts/fixture-noaad.md
"$dec" "posts-encrypted/fixture-noaad.eml"
noaad_result=$(cat posts/fixture-noaad.md)
if [[ "$noaad_result" != "$noaad_body" ]]; then
    echo "FAIL: AAD backward-compat fallback decryption produced wrong output" >&2
    echo "expected: '$noaad_body'" >&2
    echo "got:      '$noaad_result'" >&2
    exit 1
fi
echo "AAD fallback OK"

# ---- Docker: build Rocq/Crane generator and site ----
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
if grep -E '>Subject: [^.<]' _site/index.html >/dev/null 2>&1; then
    echo "FAIL: non-placeholder Subject on inbox" >&2
    exit 1
fi
if grep -q 'Round-trip fixture' _site/fixture/index.html _site/index.html 2>/dev/null; then
    echo "FAIL: plaintext title leaked into rendered HTML" >&2
    exit 1
fi
if grep -q '<dt>Subject</dt>' _site/fixture/index.html 2>/dev/null; then
    echo "FAIL: Subject header row rendered on post page" >&2
    exit 1
fi
if ! grep -q 'Subject: ...' _site/fixture/index.html 2>/dev/null; then
    echo "FAIL: post page missing placeholder subject" >&2
    exit 1
fi
echo "site lint OK"
echo "round-trip test passed"
