#!/usr/bin/env bash
# DinD-safe roundtrip core verification (no bind mounts — docker cp in/out).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

S="$(mktemp -d)"
trap 'rm -rf "$S"' EXIT
mkdir -p "$S/keys" "$S/posts"

# --- generate author ECDSA signing keypair ---
openssl ecparam -name prime256v1 -genkey -noout -out "$S/sign.pem" 2>/dev/null
SIGN_PUB=$(openssl ec -in "$S/sign.pem" -pubout -conv_form uncompressed 2>/dev/null \
  | openssl pkey -pubin -outform DER 2>/dev/null | tail -c 65 | xxd -p -c 999 | tr -d '\n')
SIGN_PRIV=$(openssl ec -in "$S/sign.pem" -text -noout 2>/dev/null | awk '/priv:/{f=1;next}/pub:/{f=0}f' | tr -d ' :\n')
if [ ${#SIGN_PRIV} -eq 66 ]; then SIGN_PRIV=${SIGN_PRIV#00}; fi
[ ${#SIGN_PRIV} -eq 64 ] && [ ${#SIGN_PUB} -eq 130 ] || { echo "key extraction failed"; exit 1; }
SIGN_KID=$(printf '%s' "$SIGN_PUB" | xxd -r -p | shasum -a 256 | cut -c1-12)
printf '%s' "$SIGN_PUB" > "$S/keys/$SIGN_KID.sign.pub"

# --- generate author ECDH recipient keypair (for the encrypted leg) ---
openssl ecparam -name prime256v1 -genkey -noout -out "$S/key.pem" 2>/dev/null
AUTHOR_PUB=$(openssl ec -in "$S/key.pem" -pubout -conv_form uncompressed 2>/dev/null \
  | openssl pkey -pubin -outform DER 2>/dev/null | tail -c 65 | xxd -p -c 999 | tr -d '\n')
AUTHOR_PRIV=$(openssl ec -in "$S/key.pem" -text -noout 2>/dev/null | awk '/priv:/{f=1;next}/pub:/{f=0}f' | tr -d ' :\n')
if [ ${#AUTHOR_PRIV} -eq 66 ]; then AUTHOR_PRIV=${AUTHOR_PRIV#00}; fi
[ ${#AUTHOR_PRIV} -eq 64 ] && [ ${#AUTHOR_PUB} -eq 130 ] || { echo "recipient key extraction failed"; exit 1; }
AUTHOR_KID=$(printf '%s' "$AUTHOR_PUB" | xxd -r -p | shasum -a 256 | cut -c1-12)
printf '%s' "$AUTHOR_PUB" > "$S/keys/$AUTHOR_KID.pub"

cat > "$S/posts/public-fixture.md" <<'EOF'
---
title: Public round-trip fixture
date: 2026-04-24
slug: public-fixture
recipients: *
---
Hello from a PUBLIC post. No key needed.
EOF
cat > "$S/posts/enc-fixture.md" <<'EOF'
---
title: Enc round-trip fixture
date: 2026-04-25
slug: enc-fixture
---
Secret encrypted content marker.
EOF

# --- build the runner container with the tools ---
CID=$(docker create --user root -w /site \
  -e CRANE_BLOG_AUTHOR_KEY_ID="$AUTHOR_KID" \
  -e CRANE_BLOG_AUTHOR_EMAIL=test@crane.blog \
  -e CRANE_BLOG_PRIVATE_KEY="$AUTHOR_PRIV" \
  -e CRANE_BLOG_SIGNING_KEY_ID="$SIGN_KID" \
  -e CRANE_BLOG_SIGNING_KEY="$SIGN_PRIV" \
  -e CRANE_BLOG_SIGNING_PUB="$SIGN_PUB" \
  crane-blog:builder bash -c '
    set -euo pipefail
    enc=/site/enc; dec=/site/dec
    # ---------- PUBLIC leg ----------
    $enc posts/public-fixture.md
    test -f posts-encrypted/public-fixture.eml
    echo "PUB1 encrypted OK"
    grep -qx "Public-Keys: \\*" <(sed -n "1,/^$/p" posts-encrypted/public-fixture.eml | tr -d "\r") || { echo "FAIL: Public-Keys not exactly *"; exit 1; }
    grep -q "multipart/hpke+wrapped" posts-encrypted/public-fixture.eml || { echo "FAIL: no hpke container"; exit 1; }
    grep -q "application/x-crane-public" posts-encrypted/public-fixture.eml || { echo "FAIL: no public part"; exit 1; }
    grep -q "application/wrapped-keys" posts-encrypted/public-fixture.eml && { echo "FAIL: has wrapped-keys"; exit 1; }
    grep -q "application/aes-gcm" posts-encrypted/public-fixture.eml && { echo "FAIL: has aes-gcm"; exit 1; }
    echo "PUB2 envelope shape OK"
    # decrypt with NO private key
    rm -f posts/public-fixture.md
    OUT=$(env -u CRANE_BLOG_PRIVATE_KEY $dec posts-encrypted/public-fixture.eml 2>&1)
    echo "$OUT" | grep -q "Verified public post" || { echo "FAIL: not verified public: $OUT"; exit 1; }
    grep -q "Hello from a PUBLIC post" posts/public-fixture.md || { echo "FAIL: content mismatch"; exit 1; }
    echo "PUB3 keyless decrypt OK"
    # tamper -> signature fail
    cp posts-encrypted/public-fixture.eml /tmp/t.eml
    perl -0pi -e "s/Hello from a PUBLIC post\./Hello from a PUBLIC post?/" /tmp/t.eml
    if env -u CRANE_BLOG_PRIVATE_KEY $dec /tmp/t.eml 2>/tmp/t.out; then echo "FAIL: tamper accepted"; exit 1; fi
    grep -q "author signature verification failed" /tmp/t.out || { echo "FAIL: wrong tamper error: $(cat /tmp/t.out)"; exit 1; }
    echo "PUB4 tamper rejection OK"
    # kind-flip -> reject
    sed "s/^Public-Keys: \*/Public-Keys: 0123456789ab/" posts-encrypted/public-fixture.eml | tr -d "\r" > /tmp/kf.eml
    if env -u CRANE_BLOG_PRIVATE_KEY $dec /tmp/kf.eml 2>/tmp/kf.out; then echo "FAIL: kind-flip accepted"; exit 1; fi
    echo "PUB5 kind-flip rejection OK"
    # mixed -> encrypt rejects
    printf -- "---\ntitle: Mixed\nslug: mixed\nrecipients: 0123456789ab, *\n---\nMixed.\n" > posts/mixed.md
    if $enc posts/mixed.md 2>/tmp/mixed.out; then echo "FAIL: mixed accepted"; exit 1; fi
    echo "PUB6 mixed rejection OK"
    # trailing-comma "*," -> encrypt rejects, never silently public (R1 B9)
    printf -- "---\ntitle: Star comma\nslug: starcomma\nrecipients: *,\n---\nNope.\n" > posts/starcomma.md
    if $enc posts/starcomma.md 2>/tmp/sc.out; then echo "FAIL: '*,' accepted"; exit 1; fi
    echo "PUB7 trailing-comma rejection OK"
    # rename attack (slug binding): same bytes, different filename/slug -> reject
    cp posts-encrypted/public-fixture.eml /tmp/rn.eml
    if env -u CRANE_BLOG_PRIVATE_KEY $dec /tmp/rn.eml 2>/tmp/rn.out; then echo "FAIL: rename accepted (slug binding broken)"; exit 1; fi
    grep -q "author signature verification failed" /tmp/rn.out || { echo "FAIL: wrong rename error: $(cat /tmp/rn.out)"; exit 1; }
    echo "PUB8 rename-attack rejection OK"
    # ---------- ENCRYPTED leg (regression) ----------
    $enc posts/enc-fixture.md
    test -f posts-encrypted/enc-fixture.eml
    echo "ENC1 encrypted OK"
    $dec posts-encrypted/enc-fixture.eml
    grep -q "Secret encrypted content marker" posts/enc-fixture.md || { echo "FAIL: enc content mismatch"; exit 1; }
    echo "ENC2 roundtrip OK"
    cp posts-encrypted/enc-fixture.eml /tmp/et.eml
    perl -0pi -e "s/(^Signature: [0-9a-fA-F]{100})([0-9a-fA-F])/(\$2 eq \"f\") ? \"\${1}e\" : \"\${1}f\"/me" /tmp/et.eml
    if $dec /tmp/et.eml 2>/tmp/et.out; then echo "FAIL: enc tamper accepted"; exit 1; fi
    grep -q "author signature verification failed" /tmp/et.out || { echo "FAIL: wrong enc tamper error"; exit 1; }
    echo "ENC3 tamper rejection OK"
    # Signing-Key header exact match (Signing-Key: <130-hex> == keys/<kid>.sign.pub)
    expected_signing="$(cat "keys/$CRANE_BLOG_SIGNING_KEY_ID.sign.pub")"
    actual_signing="$(grep "^Signing-Key: " posts-encrypted/enc-fixture.eml | tr -d "\r" | sed "s/^Signing-Key: //")"
    [ "$actual_signing" = "$expected_signing" ] || { echo "FAIL: Signing-Key header mismatch"; exit 1; }
    echo "ENC4 Signing-Key header OK"
    # author-only default (empty recipients:) -> encrypted to the author ONLY
    printf -- "---\ntitle: Author only\nslug: author-only\nrecipients:\n---\nFor the author.\n" > posts/author-only.md
    $enc posts/author-only.md
    test -f posts-encrypted/author-only.eml
    if grep -qx "Public-Keys: $CRANE_BLOG_AUTHOR_KEY_ID" <(sed -n "1,/^$/p" posts-encrypted/author-only.eml | tr -d "\r"); then :; else echo "FAIL: author-only not encrypted to author"; exit 1; fi
    echo "ENC5 author-only default OK"
    echo "ALL ROUNDTRIP CHECKS PASSED"
  ')
docker cp _build/default/tools/encrypt_post.exe "$CID:/site/enc"
docker cp _build/default/tools/decrypt_post.exe "$CID:/site/dec"
docker cp "$S/keys/." "$CID:/site/keys/"
docker cp "$S/posts/." "$CID:/site/posts/"
docker start -a "$CID"

# --- M11: independent openssl ECDSA verification of the public signature ---
docker cp "$CID:/site/posts-encrypted/public-fixture.eml" "$S/public-fixture.eml" 2>/dev/null || true
if [ -f "$S/public-fixture.eml" ] && command -v python3 >/dev/null 2>&1; then
  python3 - "$S/public-fixture.eml" "$S" <<'PYEOF'
import hashlib, re, sys
eml_path, scratch = sys.argv[1], sys.argv[2]
raw = open(eml_path, 'rb').read()
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
pk_hex = re.search(rb'^Signing-Key: ([0-9a-f]{130})\r?$', raw, re.M).group(1)
spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + bytes.fromhex(pk_hex.decode())
open(scratch + '/pub-pk.der', 'wb').write(spki)
PYEOF
  openssl pkey -pubin -inform DER -in "$S/pub-pk.der" -out "$S/pub-pk.pem" 2>/dev/null
  if openssl dgst -sha256 -verify "$S/pub-pk.pem" -signature "$S/pub-sig.der" "$S/pub-digest.bin" 2>/dev/null | grep -q 'Verified OK'; then
    echo "M11 public signature externally verified (openssl DER-wrapped r||s)"
  else
    echo "FAIL: public signature did not verify under openssl (M11)"; exit 1
  fi
fi

# --- M11 (encrypted leg): independent openssl verification of the ciphertext
#     signature over SHA-256("crane-blog-sign-v1" || ct_package) — the G6
#     double-hash check for the encrypted path. ---
docker cp "$CID:/site/posts-encrypted/enc-fixture.eml" "$S/enc-fixture.eml" 2>/dev/null || true
if [ -f "$S/enc-fixture.eml" ] && command -v python3 >/dev/null 2>&1; then
  python3 - "$S/enc-fixture.eml" "$S" <<'PYEOF'
import hashlib, re, base64, sys
eml_path, scratch = sys.argv[1], sys.argv[2]
raw = open(eml_path, 'rb').read()
m = re.search(rb'Content-Type: application/aes-gcm\r?\n(?:[^\r\n]*\r?\n)*?\r?\n(.*?)\r?\n--=', raw, re.S)
if not m:
    print('FAIL: could not locate aes-gcm part'); sys.exit(1)
ct_b64 = b''.join(m.group(1).split())
ct_package = base64.b64decode(ct_b64)
# FIRST hash of the realized double hash (dgst -sha256 -verify applies the 2nd).
digest = hashlib.sha256(b'crane-blog-sign-v1' + ct_package).digest()
open(scratch + '/enc-digest.bin', 'wb').write(digest)
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
open(scratch + '/enc-sig.der', 'wb').write(der)
pk_hex = re.search(rb'^Signing-Key: ([0-9a-f]{130})\r?$', raw, re.M).group(1)
spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + bytes.fromhex(pk_hex.decode())
open(scratch + '/enc-pk.der', 'wb').write(spki)
PYEOF
  openssl pkey -pubin -inform DER -in "$S/enc-pk.der" -out "$S/enc-pk.pem" 2>/dev/null
  if openssl dgst -sha256 -verify "$S/enc-pk.pem" -signature "$S/enc-sig.der" "$S/enc-digest.bin" 2>/dev/null | grep -q 'Verified OK'; then
    echo "M11 encrypted ciphertext signature externally verified (openssl DER-wrapped r||s)"
  else
    echo "FAIL: encrypted ciphertext signature did not verify under openssl (M11)"; exit 1
  fi
fi
