#!/usr/bin/env bash
# verify-fixture-signature.sh — G6/M11: independently verify a committed
# encrypted fixture's author signature with openssl, over the realized DOUBLE
# hash  SHA-256(SHA-256("crane-blog-sign-v1" || ct_package)).
#
# The Signature header is the raw 64-byte r||s (openssl rejects it), so it is
# wrapped in a DER ECDSA-Sig-Value before verification.  The ciphertext
# package (ct_package) is the whitespace-stripped, base64-decoded body of the
# application/aes-gcm part.  Uses `openssl dgst -sha256 -verify` on the FIRST
# hash (the FFI's realized signature hashes that 32-byte digest once more), so
# the double hash is applied exactly once — matching scripts/test-roundtrip.sh
# and scripts/verify-roundtrip-dind.sh.
#
# Usage: scripts/verify-fixture-signature.sh [eml]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
eml="${1:-posts-encrypted/crane-blog-internals.eml}"
[ -f "$eml" ] || { echo "FAIL: $eml not found" >&2; exit 1; }
[ -f keys/author-signing.pub ] || { echo "FAIL: keys/author-signing.pub (trust anchor) missing" >&2; exit 1; }

# The envelope's Signing-Key must equal the committed pin (belt-and-braces; the
# deploy/e2e workflows already assert this).
pinned="$(tr -d '\r\n ' < keys/author-signing.pub)"
eml_key="$(grep -a '^Signing-Key: ' "$eml" | tr -d '\r' | sed 's/^Signing-Key: *//')"
if [ "$eml_key" != "$pinned" ]; then
  echo "FAIL: $eml Signing-Key does not match keys/author-signing.pub" >&2
  exit 1
fi

S="$(mktemp -d)"; trap 'rm -rf "$S"' EXIT
python3 - "$eml" "$S" <<'PYEOF'
import hashlib, re, base64, sys
eml_path, scratch = sys.argv[1], sys.argv[2]
raw = open(eml_path, 'rb').read()
m = re.search(rb'Content-Type: application/aes-gcm\r?\n(?:[^\r\n]*\r?\n)*?\r?\n(.*?)\r?\n--=', raw, re.S)
if not m:
    print('FAIL: could not locate the application/aes-gcm part'); sys.exit(1)
ct_b64 = b''.join(m.group(1).split())
ct_package = base64.b64decode(ct_b64)
# FIRST hash of the realized double hash (dgst -sha256 -verify applies the 2nd).
digest = hashlib.sha256(b'crane-blog-sign-v1' + ct_package).digest()
open(scratch + '/digest.bin', 'wb').write(digest)
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
open(scratch + '/sig.der', 'wb').write(der)
pk_hex = re.search(rb'^Signing-Key: ([0-9a-f]{130})\r?$', raw, re.M).group(1)
spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + bytes.fromhex(pk_hex.decode())
open(scratch + '/pk.der', 'wb').write(spki)
PYEOF

openssl pkey -pubin -inform DER -in "$S/pk.der" -out "$S/pk.pem" 2>/dev/null
if openssl dgst -sha256 -verify "$S/pk.pem" -signature "$S/sig.der" "$S/digest.bin" 2>/dev/null | grep -q 'Verified OK'; then
  echo "fixture signature verified (openssl double-hash, DER-wrapped r||s)"
else
  echo "FAIL: $eml signature did not verify under openssl (M11)" >&2
  exit 1
fi
