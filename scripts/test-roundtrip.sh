#!/usr/bin/env bash
# test-roundtrip.sh -- end-to-end check of the HPKE encryption pipeline.
# Generates a test ECDH P-256 keypair + an author ECDSA signing keypair via
# openssl, encrypts a fixture post with encrypt_post, asserts the signed
# envelope headers, decrypts with decrypt_post, diffs the round-tripped
# bytes against the originals, and checks that a tampered Signature header
# is rejected.  Also lint-checks the generated HTML for metadata leaks.
#
# The encrypt_post/decrypt_post tools are now Crane-extracted C++ built
# from src/EncryptPost.v + src/DecryptPost.v (+ CryptoSpec.v / MimeBuild.v).
# Building them needs Coq + the Crane plugin, which live only inside the
# `crane-blog:builder` image -- this host (fuji) has no opam/coq/dune.  So
# the tool build + the encrypt/decrypt round-trip + the tamper rejection
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
    rm -f posts-encrypted/fixture-tampered.eml
    rm -f posts/public-hostile.md posts-encrypted/public-hostile.eml
    rm -f "keys/${key_id:-}.pub" "keys/${sign_key_id:-}.sign.pub" \
        .roundtrip-key-id .roundtrip-sign-key-id
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

# key_id / sign_key_id are produced inside the container (they depend on the
# generated keypairs) and written to the bind-mounted worktree so the host
# cleanup trap can remove keys/<id>.pub / keys/<id>.sign.pub afterwards.
key_id=""
sign_key_id=""

# ---------------------------------------------------------------------------
# In-container stage: build the Crane-extracted C++ tools, run the
# encrypt -> validate -> decrypt -> diff round-trip, assert the ECDSA
# Signature/Signing-Key headers, and reject a tampered signature.  Runs as
# the image's default opam user (uid 1000) so _build/ artifacts written
# into the bind mount stay owned by the host user; xxd is installed via
# passwordless sudo.
# ---------------------------------------------------------------------------
docker run --name "$roundtrip_container" --rm -i \
    -v "$PWD:/home/opam/crane-blog" \
    "$builder_image" \
    bash -euo pipefail -s <<'INNER'
eval "$(opam env)"
cd /home/opam/crane-blog

# --- in-container deps: xxd (hex dump for key extraction) ---
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq >/dev/null
sudo apt-get install -y -qq --no-install-recommends xxd >/dev/null

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# ---- Generate test ECDH P-256 recipient keypair ----
openssl ecparam -name prime256v1 -genkey -noout -out "$scratch/key.pem" 2>/dev/null

# Extract uncompressed public key (65 bytes: 04 || x || y).
pub_hex=$(openssl ec -in "$scratch/key.pem" -pubout -conv_form uncompressed 2>/dev/null |
  openssl pkey -pubin -outform DER 2>/dev/null |
  tail -c 65 | xxd -p -c 999 | tr -d '\n')

# Extract private key scalar (32 bytes).  openssl prints the scalar across
# multiple ":"-separated lines; capture every line between "priv:" and "pub:".
# A leading 0x00 sign byte makes it 33 bytes (66 hex chars) -- strip it.
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

# ---- Generate author ECDSA signing keypair ----
# Same extraction discipline as the recipient key: 65-byte uncompressed
# public key hex (NOT the ~91-byte SPKI DER) and 32-byte private scalar.
openssl ecparam -name prime256v1 -genkey -noout -out "$scratch/sign.pem" 2>/dev/null
sign_pub_hex=$(openssl ec -in "$scratch/sign.pem" -pubout -conv_form uncompressed 2>/dev/null |
  openssl pkey -pubin -outform DER 2>/dev/null |
  tail -c 65 | xxd -p -c 999 | tr -d '\n')
sign_priv_hex=$(openssl ec -in "$scratch/sign.pem" -text -noout 2>/dev/null |
  awk '/priv:/{f=1;next}/pub:/{f=0}f' | tr -d ' :\n')
if [ ${#sign_priv_hex} -eq 66 ]; then sign_priv_hex=${sign_priv_hex#00}; fi
if [ ${#sign_priv_hex} -ne 64 ] || [ ${#sign_pub_hex} -ne 130 ]; then
    echo "FAIL: signing key extraction wrong (priv_len=${#sign_priv_hex} want 64, pub_len=${#sign_pub_hex} want 130)" >&2
    exit 1
fi
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

# ---- Signature headers ----
grep -q '^Signature: [0-9a-f]' posts-encrypted/fixture.eml \
  || { echo "FAIL: envelope missing non-empty Signature header"; exit 1; }
if ! grep '^Signing-Key: ' posts-encrypted/fixture.eml | tr -d '\r' \
    | grep -qx "Signing-Key: $sign_pub_hex"; then
    echo "FAIL: Signing-Key header does not match keys/$sign_key_id.sign.pub" >&2
    exit 1
fi

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

# ---- Tamper rejection ----
# Corrupt ONE hex char in the Signature header value (always to a different
# valid hex char, so the signature still decodes but verification must fail).
tampered="posts-encrypted/fixture-tampered.eml"
cp posts-encrypted/fixture.eml "$tampered"
perl -0pi -e 's/(^Signature: [0-9a-fA-F]{100})([0-9a-fA-F])/($2 eq "f") ? "${1}e" : "${1}f"/me' "$tampered"
if ! "$dec" "$tampered" >"$scratch/tamper.out" 2>&1; then
    if ! grep -q 'author signature verification failed' "$scratch/tamper.out"; then
        echo "FAIL: tampered envelope rejected, but not with the signature error:" >&2
        cat "$scratch/tamper.out" >&2
        exit 1
    fi
else
    echo "FAIL: tampered envelope was accepted" >&2
    exit 1
fi
rm -f "$tampered"
echo "tamper rejection OK"

# ===========================================================================
# Public (keyless) post leg — feature 2 (Public-Keys: *)
# ===========================================================================
mkdir -p posts
cat > posts/public-fixture.md <<'EOF'
---
title: Public round-trip fixture
date: 2026-04-24
slug: public-fixture
recipients: *
---
Hello from a PUBLIC post. No key needed.
EOF
orig_public_md="$(cat posts/public-fixture.md)"

# ---- Encrypt (public branch: no keys/<kid>.pub resolution) ----
"$enc" posts/public-fixture.md
public_eml="posts-encrypted/public-fixture.eml"
test -f "$public_eml"
clean_eml="$(tr -d '\r' < "$public_eml")"
outer_head="$(sed -n '1,/^$/p' <<<"$clean_eml")"

# ---- Envelope shape (D1): same container, Public-Keys: *, no wraps/aes-gcm ----
grep -q 'multipart/hpke+wrapped' "$public_eml" \
  || { echo "FAIL: public envelope missing multipart/hpke+wrapped"; exit 1; }
grep -qx 'Public-Keys: \*' <<<"$outer_head" \
  || { echo "FAIL: public envelope missing exactly 'Public-Keys: *'"; exit 1; }
if grep -q 'application/wrapped-keys' "$public_eml"; then
    echo "FAIL: public envelope must not carry a wrapped-keys part"; exit 1
fi
if grep -q 'application/aes-gcm' "$public_eml"; then
    echo "FAIL: public envelope must not carry an aes-gcm part"; exit 1
fi
grep -q 'application/x-crane-public' "$public_eml" \
  || { echo "FAIL: public envelope missing application/x-crane-public part"; exit 1; }
# C4/A3: scope the metadata grep to the OUTER header block — the inner MIME's
# protected From/To/Date headers sit at line starts INSIDE the part body.
if grep -E '^(From|To|Date): ' <<<"$outer_head" >/dev/null; then
    echo "FAIL: public envelope outer header exposes sender, recipient, or date metadata" >&2
    exit 1
fi

# ---- Public decrypt with NO private key ----
rm -f posts/public-fixture.md
unset CRANE_BLOG_PRIVATE_KEY
public_out="$("$dec" "$public_eml" 2>&1)" || { echo "FAIL: public decrypt failed: $public_out"; exit 1; }
grep -q 'Verified public post' <<<"$public_out" \
  || { echo "FAIL: public decrypt did not report 'Verified public post': $public_out"; exit 1; }
roundtripped_public="$(cat posts/public-fixture.md)"
if [[ "$orig_public_md" != "$roundtripped_public" ]]; then
    echo "FAIL: public markdown mismatch after round-trip" >&2
    diff <(printf '%s' "$orig_public_md") <(printf '%s' "$roundtripped_public") || true
    exit 1
fi
rm -f posts/public-fixture.md
# Restore the private key for any later encrypted-leg assertions.
export CRANE_BLOG_PRIVATE_KEY="$priv_hex"
echo "public round-trip OK"

# ---- Public tamper (body byte flip -> canonical digest changes) ----
tampered_public="posts-encrypted/public-tampered.eml"
cp "$public_eml" "$tampered_public"
perl -0pi -e 's/Hello from a PUBLIC post\./Hello from a PUBLIC post?/' "$tampered_public"
if ! "$dec" "$tampered_public" >"$scratch/pub-tamper.out" 2>&1; then
    grep -q 'author signature verification failed' "$scratch/pub-tamper.out" \
      || { echo "FAIL: tampered public envelope rejected without signature error:"; cat "$scratch/pub-tamper.out"; exit 1; }
else
    echo "FAIL: tampered public envelope was accepted"; exit 1
fi
rm -f "$tampered_public"
echo "public tamper rejection OK"

# ---- Rename attack (slug binding): same bytes, different slug -> reject ----
renamed="posts-encrypted/public-renamed.eml"
cp "$public_eml" "$renamed"
if "$dec" "$renamed" >"$scratch/pub-rename.out" 2>&1; then
    echo "FAIL: renamed public envelope accepted (slug binding broken)"; exit 1
fi
grep -q 'author signature verification failed' "$scratch/pub-rename.out" \
  || { echo "FAIL: rename attack rejected without signature error:"; cat "$scratch/pub-rename.out"; exit 1; }
rm -f "$renamed"
echo "public rename-attack rejection OK"

# ---- Kind-flip (D-Q7/A12): Public-Keys: * -> a kid => fail closed ----
kindflip="posts-encrypted/public-kindflip.eml"
sed 's/^Public-Keys: \*/Public-Keys: 0123456789ab/' "$public_eml" | tr -d '\r' > "$kindflip"
if "$dec" "$kindflip" >"$scratch/pub-kind.out" 2>&1; then
    echo "FAIL: kind-flipped envelope accepted"; exit 1
fi
rm -f "$kindflip"
echo "public kind-flip rejection OK"

# ---- Mixed "*" + named readers (D3/D-M2) -> encrypt must reject ----
cat > posts/public-mixed.md <<'EOF'
---
title: Mixed
slug: public-mixed
recipients: 0123456789ab, *
---
Mixed content.
EOF
if "$enc" posts/public-mixed.md >"$scratch/mixed.out" 2>&1; then
    echo "FAIL: mixed recipients accepted"; exit 1
fi
rm -f posts/public-mixed.md posts-encrypted/public-mixed.eml
echo "public mixed rejection OK"

# ---- Trailing-comma "*," (R1 B9) -> rejected, never silently public ----
cat > posts/public-starcomma.md <<'EOF'
---
title: Star comma
slug: public-starcomma
recipients: *,
---
Nope.
EOF
if "$enc" posts/public-starcomma.md >"$scratch/sc.out" 2>&1; then
    echo "FAIL: '*,' accepted"; exit 1
fi
rm -f posts/public-starcomma.md posts-encrypted/public-starcomma.eml
echo "public '*' trailing-comma rejection OK"

# ---- M11/A16: REAL signature verification (openssl, DER-wrapped r||s) ----
# digest = sha256(sign_info_public || slug || normalize_crlf(inner_mime)); the
# FFI hashes that 32-byte digest once more (e = SHA-256(digest)) before ECDSA,
# so openssl dgst receives the pre-hash as its message.  The Signature header
# is raw 64-byte r||s; wrap it in a DER ECDSA-Sig-Value before verifying.
if command -v python3 >/dev/null 2>&1; then
    python3 - "$public_eml" "$scratch" <<'PYEOF'
import hashlib, re, sys
eml_path, scratch = sys.argv[1], sys.argv[2]
raw = open(eml_path, 'rb').read()
# Recover the inner MIME from the application/x-crane-public part body: the
# wire body is inner_mime (ending CRLF) + CRLF + closing boundary; capture the
# bytes up to the boundary's preceding CRLF.
m = re.search(rb'Content-Type: application/x-crane-public\r\n(?:[^\r\n]*\r\n)*?\r\n(.*?)\r\n--=_cb_outer_0_=--', raw, re.S)
if not m:
    print('FAIL: could not locate public part'); sys.exit(1)
inner = m.group(1)
norm = inner.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
digest = hashlib.sha256(b'crane-blog-sign-public-v1' + b'public-fixture' + norm).digest()
open(scratch + '/pub-digest.bin', 'wb').write(digest)
sig_hex = re.search(rb'^Signature: ([0-9a-f]{128})\r?$', raw, re.M).group(1)
rs = bytes.fromhex(sig_hex.decode())
r, s = rs[:32], rs[32:]
def der_int(b):
    b = b.lstrip(b'\x00') or b'\x00'
    if b[0] & 0x80:
        b = b'\x00' + b
    return b'\x02' + bytes([len(b)]) + b
body = der_int(r) + der_int(s)
der = b'\x30' + bytes([len(body)]) + body
open(scratch + '/pub-sig.der', 'wb').write(der)
# SPKI DER for the P-256 uncompressed point from the Signing-Key header.
pk_hex = re.search(rb'^Signing-Key: ([0-9a-f]{130})\r?$', raw, re.M).group(1)
spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + bytes.fromhex(pk_hex.decode())
open(scratch + '/pub-pk.der', 'wb').write(spki)
PYEOF
    if [[ -f "$scratch/pub-digest.bin" ]]; then
        openssl pkey -pubin -inform DER -in "$scratch/pub-pk.der" -out "$scratch/pub-pk.pem" 2>/dev/null
        if openssl dgst -sha256 -verify "$scratch/pub-pk.pem" \
              -signature "$scratch/pub-sig.der" "$scratch/pub-digest.bin" 2>/dev/null | grep -q 'Verified OK'; then
            echo "public signature externally verified (M11/A16)"
        else
            echo "FAIL: public signature did not verify under openssl" >&2
            exit 1
        fi
    fi
fi

# ---- Feature 1 regression rows (D-R7/R8) ----
# R7: empty/absent recipients: -> encrypted to the AUTHOR ONLY.
cat > posts/author-only.md <<'EOF'
---
title: Author only
slug: author-only
recipients:
---
For the author's eyes only.
EOF
"$enc" posts/author-only.md
ao_eml="posts-encrypted/author-only.eml"
ao_head="$(tr -d '\r' < "$ao_eml" | sed -n '1,/^$/p')"
grep -qx "Public-Keys: $key_id" <<<"$ao_head" \
  || { echo "FAIL: author-only post not encrypted to the author"; exit 1; }
rm -f posts/author-only.md "$ao_eml"
echo "author-only default OK"

# R8: SMTP-extract -> CLI-re-encrypt reader-preservation row.  Two readers
# (kid1 = the author, kid2 = one extra ECDH keypair): encrypt with
# `recipients: kid1, kid2`, decrypt as the author (always the first
# recipient), then assert the readers survive both the round-tripped
# frontmatter and the re-encrypted envelope's Public-Keys header.
openssl ecparam -name prime256v1 -genkey -noout -out "$scratch/extra.pem" 2>/dev/null
extra_pub_hex=$(openssl ec -in "$scratch/extra.pem" -pubout -conv_form uncompressed 2>/dev/null |
  openssl pkey -pubin -outform DER 2>/dev/null |
  tail -c 65 | xxd -p -c 999 | tr -d '\n')
extra_priv_hex=$(openssl ec -in "$scratch/extra.pem" -text -noout 2>/dev/null |
  awk '/priv:/{f=1;next}/pub:/{f=0}f' | tr -d ' :\n')
if [ ${#extra_priv_hex} -eq 66 ]; then extra_priv_hex=${extra_priv_hex#00}; fi
if [ ${#extra_priv_hex} -ne 64 ] || [ ${#extra_pub_hex} -ne 130 ]; then
    echo "FAIL: extra reader key extraction wrong (priv_len=${#extra_priv_hex} want 64, pub_len=${#extra_pub_hex} want 130)" >&2
    exit 1
fi
extra_kid=$(printf '%s' "$extra_pub_hex" | xxd -r -p | shasum -a 256 | cut -c 1-12)
printf '%s' "$extra_pub_hex" > "keys/$extra_kid.pub"

cat > posts/two-readers.md <<EOF
---
title: Two readers
slug: two-readers
recipients: $key_id, $extra_kid
---
For the author and one extra reader.
EOF
"$enc" posts/two-readers.md
tr_eml="posts-encrypted/two-readers.eml"
test -f "$tr_eml"
tr_head="$(tr -d '\r' < "$tr_eml" | sed -n '1,/^$/p')"
grep -qx "Public-Keys: $key_id, $extra_kid" <<<"$tr_head" \
  || { echo "FAIL: two-reader envelope missing both kids"; exit 1; }

# Decrypt as the author (CRANE_BLOG_PRIVATE_KEY is the author's key; the
# author is always the first recipient).
rm -f posts/two-readers.md
"$dec" "$tr_eml"
grep -qx "recipients: $key_id, $extra_kid" posts/two-readers.md \
  || { echo "FAIL: round-tripped two-reader post lost recipients frontmatter"; exit 1; }

# Re-encrypt the round-tripped post: both kids must survive into the new
# envelope's Public-Keys header.
"$enc" posts/two-readers.md
re_head="$(tr -d '\r' < "$tr_eml" | sed -n '1,/^$/p')"
grep -qx "Public-Keys: $key_id, $extra_kid" <<<"$re_head" \
  || { echo "FAIL: re-encrypted two-reader envelope lost a kid"; exit 1; }
rm -f posts/two-readers.md "$tr_eml" "keys/$extra_kid.pub"
echo "two-reader SMTP-extract re-encrypt OK"

# ---- F3/NIT-3 (D-D7.2): hostile-body PUBLIC fixture for site-lint vacuity ----
# The markdown body carries literal <script>/<img>; the site generator escapes
# the envelope body (PageModel.html_escape), so the deploy lint
# `grep -R -l '<img' _site` must stay vacuous.  Keep the EML so the site-gen
# leg renders it; the HOST site-lint section asserts the escaped forms.
cat > posts/public-hostile.md <<'EOF'
---
title: Hostile body fixture
date: 2026-04-25
slug: public-hostile
recipients: *
---
<script>alert(1)</script> <img src=x onerror=alert(1)>
EOF
"$enc" posts/public-hostile.md
hostile_eml="posts-encrypted/public-hostile.eml"
test -f "$hostile_eml"
grep -qx 'Public-Keys: \*' <<<"$(tr -d '\r' < "$hostile_eml" | sed -n '1,/^$/p')" \
  || { echo "FAIL: hostile fixture not a public post"; exit 1; }
rm -f posts/public-hostile.md
echo "public hostile-body fixture staged"

# Clean the public fixture so the site-gen leg only renders the encrypted
# fixture (whose lints are unchanged).
rm -f "$public_eml"

echo "public leg passed"

# Hand the key ids back to the host (for its cleanup trap) via the bind mount.
printf '%s' "$key_id" > .roundtrip-key-id
printf '%s' "$sign_key_id" > .roundtrip-sign-key-id
INNER

# Recover the key ids the container generated so the host cleanup trap can
# remove keys/<id>.pub and keys/<id>.sign.pub.
if [[ -f .roundtrip-key-id ]]; then
    key_id="$(cat .roundtrip-key-id)"
    rm -f .roundtrip-key-id
fi
if [[ -f .roundtrip-sign-key-id ]]; then
    sign_key_id="$(cat .roundtrip-sign-key-id)"
    rm -f .roundtrip-sign-key-id
fi

# ---- Docker: build Rocq/Crane generator and site ----
image="${CRANE_BLOG_DOCKER_IMAGE:-crane-blog-roundtrip}"
published_image="${CRANE_BLOG_GEN_IMAGE:-${CRANE_BLOG_GENERATOR_IMAGE:-ghcr.io/wklm/crane-blog-generator:latest}}"
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
# F3/NIT-3 (D-D7.2): the hostile public body must render HTML-escaped — its
# raw <script>/<img> literals never become real tags, so the deploy lint above
# stays vacuous even though a public post's body carries them.
hostile_page="_site/public-hostile/index.html"
if ! grep -q '&lt;script&gt;' "$hostile_page" 2>/dev/null; then
    echo "FAIL: hostile public body not HTML-escaped (missing &lt;script&gt;)" >&2
    exit 1
fi
if ! grep -q '&lt;img' "$hostile_page" 2>/dev/null; then
    echo "FAIL: hostile public body not HTML-escaped (missing &lt;img)" >&2
    exit 1
fi
if grep -q '<script>' "$hostile_page" 2>/dev/null; then
    echo "FAIL: raw <script> leaked into rendered public post" >&2
    exit 1
fi
if grep -q '<img' "$hostile_page" 2>/dev/null; then
    echo "FAIL: raw <img leaked into rendered public post" >&2
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
