#!/usr/bin/env bash
# generate-signing-key.sh -- create an author ECDSA P-256 signing keypair.
#
# encrypt_post / smtp_server sign every envelope with the author signing key
# (CRANE_BLOG_SIGNING_KEY_ID + CRANE_BLOG_SIGNING_KEY) and readers verify it
# against keys/<kid>.sign.pub.  This script creates a fresh keypair, writes
# the public half to keys/<kid>.sign.pub (gitignored) and prints the private
# scalar for your environment / fuji secrets.
#
# Usage: scripts/generate-signing-key.sh
set -euo pipefail

repo="$(git rev-parse --show-toplevel)"
cd "$repo"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# 1. Generate a P-256 keypair into a scratch PEM (never written to disk
#    outside the temp dir; the private key only ever appears on stdout).
openssl ecparam -name prime256v1 -genkey -noout -out "$scratch/sign.pem" 2>/dev/null

# 2. Extract the uncompressed public key: 65 bytes (04 || X || Y) -> 130 hex
#    chars.  `-conv_form uncompressed` + DER + tail -c 65 yields exactly the
#    SEC1 point, NOT the ~91-byte SPKI DER wrapper.
pub_hex=$(openssl ec -in "$scratch/sign.pem" -pubout -conv_form uncompressed 2>/dev/null |
  openssl pkey -pubin -outform DER 2>/dev/null |
  tail -c 65 | xxd -p -c 999 | tr -d '\n')

# 3. Extract the private key scalar (32 bytes -> 64 hex chars).  openssl
#    prints it across multiple ":"-separated lines; capture everything
#    between "priv:" and "pub:".  A leading 0x00 sign byte makes it 33 bytes
#    (66 hex chars) -- strip it.
priv_hex=$(openssl ec -in "$scratch/sign.pem" -text -noout 2>/dev/null |
  awk '/priv:/{f=1;next}/pub:/{f=0}f' | tr -d ' :\n')
if [ ${#priv_hex} -eq 66 ]; then priv_hex=${priv_hex#00}; fi
if [ ${#priv_hex} -ne 64 ] || [ ${#pub_hex} -ne 130 ]; then
    echo "FAIL: key extraction wrong (priv_len=${#priv_hex} want 64, pub_len=${#pub_hex} want 130)" >&2
    exit 1
fi

# 4. key ID = first 12 hex chars of SHA-256 of the 65-byte public key.
key_id=$(printf '%s' "$pub_hex" | xxd -r -p | shasum -a 256 | cut -c 1-12)

# 5. Publish the public half where encrypt_post/decrypt_post look for it.
#    keys/ is gitignored: no key material is ever committed.
mkdir -p keys
printf '%s' "$pub_hex" > "keys/$key_id.sign.pub"

# 6. Report.  The private key prints here (and only here) for env setup.
cat <<EOF
Created author ECDSA P-256 signing key.

  key ID:     $key_id
  public key: $repo/keys/$key_id.sign.pub
              (130 hex chars = 65-byte uncompressed SEC1 point; gitignored)

  private key (32-byte scalar, hex):
  $priv_hex

Export it for encrypt_post / smtp_server:

  export CRANE_BLOG_SIGNING_KEY_ID=$key_id
  export CRANE_BLOG_SIGNING_KEY=$priv_hex

Keep the private key secret: anyone holding it can author posts as $key_id.
EOF
