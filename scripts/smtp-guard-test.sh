#!/usr/bin/env bash
# smtp-guard-test.sh — SMTP integration gate for the public-post guards (G2/M9/D3).
#
# Proves, end-to-end against the Crane-extracted smtp_server binary:
#
#   G2 (request-level opt-in): an unauthenticated sender (empty BLOG_ALLOW_FROM)
#     sending `X-Crane-Public-Keys: *` is rejected 451 — the keyless public
#     branch requires BLOG_ALLOW_PUBLIC=1, and the per-request header is NOT a
#     bypass of the startup guard.
#
#   D3 (mixed marker): `X-Crane-Public-Keys: <kid>, *` (a "*" mixed with a named
#     reader) is rejected 451, never silently public and never encrypted.
#
#   C6/M9 (startup guard): BLOG_PUBLIC_KEYS=* without BLOG_ALLOW_PUBLIC=1
#     refuses to start (exit 1).
#
# The SMTP client runs in a sibling python:3-slim container that shares the
# listener's network namespace (--network container:<id>), because Docker
# Desktop's host port-forwarding does not reliably reach a container-bound
# 0.0.0.0 listener on macOS.  DinD-safe otherwise (keys docker-cp'd in, no bind
# mounts).  The smtp image is built from smtp/Dockerfile, which consumes
# smtp_server.exe from crane-blog:builder.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

IMG="${CRANE_BLOG_SMTP_IMAGE:-crane-blog-smtp:latest}"
PY_IMG="${CRANE_BLOG_PY_IMAGE:-python:3-slim}"
PORT="${SMTP_TEST_PORT:-25261}"
S="$(mktemp -d)"
trap 'rm -rf "$S"' EXIT
mkdir -p "$S/keys" "$S/posts-encrypted"

# ---- author ECDSA signing keypair (the publish pipeline reads the public
#      half back from keys/<kid>.sign.pub before the public branch) ----
openssl ecparam -name prime256v1 -genkey -noout -out "$S/sign.pem" 2>/dev/null
SIGN_PUB=$(openssl ec -in "$S/sign.pem" -pubout -conv_form uncompressed 2>/dev/null \
  | openssl pkey -pubin -outform DER 2>/dev/null | tail -c 65 | xxd -p -c 999 | tr -d '\n')
SIGN_PRIV=$(openssl ec -in "$S/sign.pem" -text -noout 2>/dev/null \
  | awk '/priv:/{f=1;next}/pub:/{f=0}f' | tr -d ' :\n')
if [ ${#SIGN_PRIV} -eq 66 ]; then SIGN_PRIV=${SIGN_PRIV#00}; fi
[ ${#SIGN_PRIV} -eq 64 ] && [ ${#SIGN_PUB} -eq 130 ] || { echo "signing key extraction failed"; exit 1; }
SIGN_KID=$(printf '%s' "$SIGN_PUB" | xxd -r -p | shasum -a 256 | cut -c1-12)
printf '%s' "$SIGN_PUB" > "$S/keys/$SIGN_KID.sign.pub"

# ---- C6/M9 startup guard: env BLOG_PUBLIC_KEYS=* without the opt-in refuses ----
if ! out="$(docker run --rm \
      -e SMTP_HOST=127.0.0.1 -e SMTP_PORT="$PORT" \
      -e BLOG_PUBLIC_KEYS='*' -e BLOG_ALLOW_PUBLIC='' -e BLOG_ALLOW_FROM='' \
      --entrypoint /usr/local/bin/smtp_server \
      "$IMG" 2>&1)"; then
  echo "$out" | grep -q 'BLOG_ALLOW_PUBLIC=1' \
    || { echo "FAIL: startup guard exited but without the BLOG_ALLOW_PUBLIC=1 message:"; echo "$out"; exit 1; }
  echo "G2/C6 STARTUP-GUARD OK (BLOG_PUBLIC_KEYS=* without opt-in refused to start)"
else
  echo "FAIL: startup guard did not refuse BLOG_PUBLIC_KEYS=* without BLOG_ALLOW_PUBLIC=1" >&2
  exit 1
fi

# ---- start the listener for the two request-level rows ----
CID=$(docker create -w /site \
  -e SMTP_HOST=0.0.0.0 -e SMTP_PORT="$PORT" \
  -e BLOG_ALLOW_FROM='' -e BLOG_PUBLIC_KEYS='' -e BLOG_ALLOW_PUBLIC='' \
  -e CRANE_BLOG_AUTHOR_KEY_ID='e2e000000001' \
  -e CRANE_BLOG_AUTHOR_EMAIL='test@crane.blog' \
  -e CRANE_BLOG_SIGNING_KEY_ID="$SIGN_KID" \
  -e CRANE_BLOG_SIGNING_KEY="$SIGN_PRIV" \
  --entrypoint /usr/local/bin/smtp_server \
  "$IMG")
docker cp "$S/keys" "$CID:/site/keys"
docker start "$CID" >/dev/null
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true; rm -rf "$S"' EXIT

# ---- request-level rows: drive a full SMTP DATA per header, assert the reply ----
docker run --rm -i --network container:"$CID" "$PY_IMG" python3 - "$PORT" <<'PYEOF'
import socket, sys, time
port = int(sys.argv[1])

def recv_line(s):
    buf = b""
    while not buf.endswith(b"\r\n"):
        c = s.recv(1)
        if not c:
            break
        buf += c
    return buf

def connect():
    last = None
    for _ in range(100):
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=5)
        except OSError as e:
            last = e
            time.sleep(0.1)
    raise last

def smtp_data(x_crane_public_keys):
    """Send one SMTP envelope carrying X-Crane-Public-Keys and return the
    final DATA reply line (e.g. '451 processing failed')."""
    s = connect()
    try:
        recv_line(s)  # 220 banner
        s.sendall(b"EHLO test\r\n");        assert recv_line(s).startswith(b"250")
        s.sendall(b"MAIL FROM:<attacker@example.com>\r\n"); assert recv_line(s).startswith(b"250")
        s.sendall(b"RCPT TO:<x@y.z>\r\n");  assert recv_line(s).startswith(b"250")
        s.sendall(b"DATA\r\n");             assert recv_line(s).startswith(b"354")
        payload = (b"Subject: forged public post\r\n"
                   + x_crane_public_keys.encode() + b"\r\n"
                   + b"\r\n"
                   + b"Hello from an unauthenticated sender.\r\n"
                   + b".\r\n")
        s.sendall(payload)
        final = recv_line(s)
        s.sendall(b"QUIT\r\n")
        return final.decode(errors="replace").strip()
    finally:
        s.close()

# G2: X-Crane-Public-Keys: * with no BLOG_ALLOW_PUBLIC=1 -> 451 (never public).
row = smtp_data("X-Crane-Public-Keys: *")
print("G2 header-override reply:", row)
if not row.startswith("451"):
    print("FAIL: X-Crane-Public-Keys: * was not rejected 451 (got: %r)" % row)
    sys.exit(1)
print("G2 HEADER-OVERRIDE OK (X-Crane-Public-Keys: * -> 451)")

# D3: a "*" mixed with a named kid -> 451 (mixed reject, not silent public).
row = smtp_data("X-Crane-Public-Keys: e2e000000001, *")
print("D3 mixed-marker reply:", row)
if not row.startswith("451"):
    print("FAIL: mixed '*, <kid>' was not rejected 451 (got: %r)" % row)
    sys.exit(1)
print("D3 MIXED-MARKER OK (X-Crane-Public-Keys: '<kid>, *' -> 451)")
PYEOF

echo "SMTP guard test passed"
