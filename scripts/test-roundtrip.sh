#!/usr/bin/env bash
# test-roundtrip.sh -- end-to-end check of the HPKE encryption pipeline.
# Generates a test ECDH P-256 keypair via openssl, encrypts a fixture
# post with encrypt_post, decrypts with decrypt_post, and diffs the
# round-tripped bytes against the originals.  Also lint-checks the
# generated HTML for metadata leaks.
#
# The encrypt_post/decrypt_post tools are now Crane-extracted C++ built
# from src/EncryptPost.v + src/DecryptPost.v (+ CryptoSpec.v / MimeBuild.v).
# Building them needs Coq + the Crane plugin, which live only inside the
# `crane-blog:builder` image -- this host (fuji) has no opam/coq/dune.  So
# the tool build + the encrypt/decrypt round-trip + the AAD-fallback fixture
# all run INSIDE that image with the worktree bind-mounted; the Docker
# site-gen + HTML lint runs on the host (it drives `docker build`/`docker run`).
set -euo pipefail

repo="$(git rev-parse --show-toplevel)"
cd "$repo"

# Image holding the Coq/Crane toolchain used to build the C++ CLI tools.
builder_image="${CRANE_BLOG_BUILDER_IMAGE:-crane-blog:builder}"

scratch="$(mktemp -d)"
container=""
roundtrip_container="crane-blog-roundtrip-build-$$"
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
    docker rm -f "$roundtrip_container" >/dev/null 2>&1 || true
    if [[ -n "${container:-}" ]]; then
        docker_step 20 docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    rm -rf "$scratch"
    rm -f posts/fixture.md posts/fixture.bin posts-encrypted/fixture.eml
    rm -f posts/fixture-noaad.md posts-encrypted/fixture-noaad.eml
    rm -f "keys/${key_id:-}.pub" .roundtrip-key-id
}
trap cleanup EXIT

# The Crane-extracted tools require the Coq/Crane toolchain image; both the
# tool build and the round-trip run inside it (the host has no dune/coq).
if ! command -v docker >/dev/null 2>&1; then
    echo "docker required: the encrypt_post/decrypt_post tools are Crane-extracted" >&2
    echo "C++ and build only inside ${builder_image} (no host opam/coq/dune)." >&2
    exit 1
fi
if ! docker image inspect "$builder_image" >/dev/null 2>&1; then
    echo "FAIL: builder image '${builder_image}' not found." >&2
    echo "Build it first:  docker build --target builder -t ${builder_image} ." >&2
    exit 1
fi

# key_id is produced inside the container (it depends on the generated
# keypair) and written to the bind-mounted worktree so the host cleanup
# trap can remove keys/<key_id>.pub afterwards.
key_id=""

# ---------------------------------------------------------------------------
# In-container stage: build the Crane-extracted C++ tools, run the
# encrypt -> validate -> decrypt -> diff round-trip, and the empty-AAD
# backward-compat fallback.  Runs as the image's default opam user (uid
# 1000) so _build/ artifacts written into the bind mount stay owned by the
# host user; xxd + python3-cryptography are installed via passwordless sudo.
# Every assertion from the original host-side script is preserved verbatim.
# ---------------------------------------------------------------------------
docker run --name "$roundtrip_container" --rm -i \
    -v "$PWD:/home/opam/crane-blog" \
    "$builder_image" \
    bash -euo pipefail -s <<'INNER'
eval "$(opam env)"
cd /home/opam/crane-blog

# --- in-container deps: xxd (hex) + python3-cryptography (AAD fixture) ---
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq >/dev/null
sudo apt-get install -y -qq --no-install-recommends xxd python3-cryptography >/dev/null

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# ---- Generate test ECDH P-256 keypair ----
openssl ecparam -name prime256v1 -genkey -noout -out "$scratch/key.pem" 2>/dev/null

# Extract uncompressed public key (65 bytes: 04 || x || y)
pub_hex=$(openssl ec -in "$scratch/key.pem" -pubout -conv_form uncompressed 2>/dev/null |
  openssl pkey -pubin -outform DER 2>/dev/null |
  tail -c 65 | xxd -p -c 999 | tr -d '\n')

# Extract private key scalar (32 bytes).  openssl prints the scalar across
# multiple ":"-separated lines; capture every line between "priv:" and "pub:"
# (the original single-getline awk grabbed only ~15 of the 32 bytes).  A
# leading 0x00 sign byte makes it 33 bytes (66 hex chars) -- strip it.
priv_hex=$(openssl ec -in "$scratch/key.pem" -text -noout 2>/dev/null |
  awk '/priv:/{f=1;next}/pub:/{f=0}f' | tr -d ' :\n')
if [ ${#priv_hex} -eq 66 ]; then priv_hex=${priv_hex#00}; fi
if [ ${#priv_hex} -ne 64 ] || [ ${#pub_hex} -ne 130 ]; then
    echo "FAIL: key extraction wrong (priv_len=${#priv_hex} want 64, pub_len=${#pub_hex} want 130)" >&2
    exit 1
fi

# Compute key ID = first 12 chars of SHA-256(pubkey)
key_id=$(printf '%s' "$pub_hex" | xxd -r -p | shasum -a 256 | cut -c 1-12)

mkdir -p keys
printf '%s' "$pub_hex" > "keys/$key_id.pub"

export CRANE_BLOG_AUTHOR_KEY_ID="$key_id"
export CRANE_BLOG_AUTHOR_EMAIL="test@crane.blog"
export CRANE_BLOG_PRIVATE_KEY="$priv_hex"

# Generate signing keypair for tests
openssl ecparam -name prime256v1 -genkey -noout -out "$scratch/sign.pem"
sign_pub_hex=$(openssl ec -in "$scratch/sign.pem" -pubout -outform DER 2>/dev/null | xxd -p -c 256)
sign_priv_hex=$(openssl ec -in "$scratch/sign.pem" -outform DER 2>/dev/null | xxd -p -c 256 | tail -c 65)
sign_key_id=$(printf '%s' "$sign_pub_hex" | xxd -r -p | shasum -a 256 | cut -c 1-12)
printf '%s' "$sign_pub_hex" > "keys/$sign_key_id.sign.pub"
export CRANE_BLOG_SIGNING_KEY_ID="$sign_key_id"
export CRANE_BLOG_SIGNING_KEY="$sign_priv_hex"

# ---- Build the tools (Crane -> C++23 -> clang++) ----
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

if [[ -f posts/proof.md ]]; then
    "$enc" posts/proof.md
    test -f posts-encrypted/convergence-proof.eml
fi

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

# OpenSSL 3.x removed `openssl enc -aes-256-gcm` (AEAD ciphers unsupported)
# and even where present `enc` never emits the GCM tag, so the fixture is
# built with python3 + cryptography: ECDH P-256 + the custom KDF
# (PRK=sha256(00*32||shared); key=sha256(PRK||info||01); info wrap =
# "crane-blog-wrap-v1") + AES-256-GCM with EMPTY AAD, producing
# nonce(12)||ct||tag(16) for both the wrapped CEK and the body -- exactly
# the package layout decrypt_post / src/CryptoSpec.v expect.
noaad_body="Fallback AAD test body"
noaad_eml="posts-encrypted/fixture-noaad.eml"

PUB_HEX="$pub_hex" NOAAD_BODY="$noaad_body" NOAAD_EML="$noaad_eml" \
python3 - <<'PY'
import os, hashlib, base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

pub_hex = os.environ["PUB_HEX"]
body = os.environ["NOAAD_BODY"].encode()
out_path = os.environ["NOAAD_EML"]

# Recipient public key (65-byte uncompressed 04||X||Y).
recipient_pub = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256R1(), bytes.fromhex(pub_hex))

# key_id = first 12 hex chars of sha256(pubkey bytes).
key_id = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:12]

# Ephemeral keypair for the wrap; sender-side ECDH against the recipient.
eph = ec.generate_private_key(ec.SECP256R1())
eph_pub_hex = eph.public_key().public_bytes(
    Encoding.X962, PublicFormat.UncompressedPoint).hex()
shared = eph.exchange(ec.ECDH(), recipient_pub)

def custom_kdf(info: bytes) -> bytes:
    prk = hashlib.sha256(b"\x00" * 32 + shared).digest()
    return hashlib.sha256(prk + info + b"\x01").digest()

def seal(key: bytes, pt: bytes) -> bytes:
    nonce = os.urandom(12)
    # AESGCM.encrypt returns ciphertext||tag(16); empty AAD => aad=None.
    return nonce + AESGCM(key).encrypt(nonce, pt, None)

wrap_key = custom_kdf(b"crane-blog-wrap-v1")
cek = os.urandom(32)
wrapped_pkg_hex = seal(wrap_key, cek).hex()

ct_b64 = base64.b64encode(seal(cek, body)).decode()

eml = (
    'Content-Type: multipart/hpke+wrapped; boundary="---noaad"\n'
    f"Public-Keys: {key_id}\n"
    "\n"
    "-----noaad\n"
    "Content-Type: application/wrapped-keys\n"
    f"Wraps: {key_id}:{eph_pub_hex}:{wrapped_pkg_hex}\n"
    "\n"
    "-----noaad\n"
    "Content-Type: application/aes-gcm\n"
    "Content-Transfer-Encoding: base64\n"
    "\n"
    f"{ct_b64}\n"
    "-----noaad--\n"
)
with open(out_path, "w") as f:
    f.write(eml)
PY

rm -f posts/fixture-noaad.md
"$dec" "$noaad_eml"
noaad_result=$(cat posts/fixture-noaad.md)
if [[ "$noaad_result" != "$noaad_body" ]]; then
    echo "FAIL: AAD backward-compat fallback decryption produced wrong output" >&2
    echo "expected: '$noaad_body'" >&2
    echo "got:      '$noaad_result'" >&2
    exit 1
fi
echo "AAD fallback OK"

# Hand the key_id back to the host (for its cleanup trap) via the bind mount.
printf '%s' "$key_id" > .roundtrip-key-id
INNER

# Recover the key_id the container generated so the host cleanup trap can
# remove keys/<key_id>.pub.
if [[ -f .roundtrip-key-id ]]; then
    key_id="$(cat .roundtrip-key-id)"
    rm -f .roundtrip-key-id
fi

# ---- Docker: build Rocq/Crane generator and site ----
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
# Run as the host uid/gid so the generated _site/ tree is owned by the
# invoking user (the runtime image is rootless-CMD'd as root otherwise,
# which would leave root-owned files the host can't clean on the next run).
docker_step "$run_timeout" docker run --name "$container" --rm \
    --user "$(id -u):$(id -g)" \
    -v "$PWD/posts-encrypted:/site/posts-encrypted:ro" \
    -v "$PWD/static:/site/static:ro" \
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
