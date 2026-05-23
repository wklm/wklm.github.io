# crane_blog

A static site generator whose core is written in
[Rocq](https://rocq-prover.org) and extracted to C++ by
[Bloomberg's Crane](https://github.com/bloomberg/crane). Posts are
encrypted with HPKE (ECDH P-256 + AES-256-GCM) before commit and
rendered as encrypted MIME envelopes. Deployed at
<https://wklm.github.io>.

## What the site is

Every post on the site is a HPKE-encrypted MIME envelope rendered
inside a classic, restrained blog shell. The homepage lists opaque
entries whose visible title is always `Subject: ...`; each link points
to a page whose public text is the same placeholder and a ciphertext
block. A reader who has enrolled a P-256 keypair in the browser can
decrypt posts in-page via Web Crypto API. An unenrolled reader sees
only opaque ciphertext.

## Authoring model

Plaintext lives on the author's working tree under `posts/` and is
**gitignored**. A pre-commit hook converts every staged
`posts/*.md` into `posts-encrypted/<slug>.eml`, stages the `.eml`,
and unstages the plaintext. Only ciphertext is tracked.

```text
posts/                working-tree only; never committed
posts-encrypted/      the only thing the remote ever sees
```

Each `.eml` is a HPKE MIME envelope: a `multipart/hpke+wrapped`
container with `application/wrapped-keys` (per-recipient CEK wraps)
and `application/aes-gcm` (AES-256-GCM ciphertext) parts. The inner
payload is a `multipart/mixed` containing the original Markdown and
every inline image as a base64 attachment.

### Frontmatter keys

| key          | meaning                                                           |
|--------------|-------------------------------------------------------------------|
| `slug`       | output directory and `.eml` basename; falls back to the file stem |
| `recipients` | comma-separated emails (max 3); the author is always added        |

All other keys are left for the author's own reference inside the
encrypted body — they are never leaked, because the body is never
rendered. The outer envelope carries only `Subject: ...` plus the
MIME headers needed for HPKE envelope framing.

### Image references

Any inline `![alt](path)` where `path` is a plain relative filename
under `posts/` is picked up by the hook, read as raw bytes, and
attached to the inner MIME tree. HTTP(S) URLs and absolute paths
are left untouched (they end up as plaintext inside the encrypted
body).

## Workflow

### Email from Mail.app

Configure an outgoing SMTP server:

```text
Server: 100.99.77.105
Port:   2525
TLS:    off
Auth:   none
```

The hostname `fuji` is an SSH alias on this Mac, not normal macOS DNS, so
Mail.app must use the Tailscale IP unless MagicDNS is enabled system-wide.
Write a normal plaintext email. The fuji container encrypts the body in
memory with the checked-in public key, wraps it in an HPKE envelope with
only `Subject: ...` visible, writes only `posts-encrypted/*.eml`, and pushes
the commit.

For a smoke test of that SMTP path:

```bash
python3 scripts/send_test.py
```

The script accepts `--host`, `--port`, `--from`, `--to`, and `--subject`; the
same values can be supplied via `BLOG_SMTP_HOST`, `BLOG_SMTP_PORT`,
`BLOG_SMTP_FROM`, `BLOG_SMTP_TO`, and `BLOG_SMTP_SUBJECT`.

### Local Git Hook

```bash
# One-time per clone
scripts/setup-hooks.sh

# Scaffold a new post
scripts/new-post.sh my-slug

# Write prose in posts/my-slug.md, referencing images by
# relative filename.  When ready:
git add posts/my-slug.md
git commit -m "new: my slug"
# -> staged file becomes posts-encrypted/my-slug.eml
# -> posts/my-slug.md stays on disk, untracked

# To edit an existing post:
./_build/default/tools/decrypt_post.exe posts-encrypted/my-slug.eml
# -> decrypted markdown + images land in posts/
# You need your P-256 private key in CRANE_BLOG_PRIVATE_KEY env var.
```

## Pipeline

1. `smtp/listener.py` (Docker on fuji). Receives normal SMTP from
   Mail.app over Tailscale, encrypts the message body using HPKE
   with the checked-in P-256 public keys, wraps it as a
   `multipart/hpke+wrapped` MIME envelope, writes
   `posts-encrypted/*.eml`, commits, and pushes. No private key lives
   on fuji.
2. `tools/encrypt_post.ml` (OCaml). Parses the frontmatter, resolves
   recipients, builds a `multipart/mixed` inner MIME tree, generates a
   random 32-byte CEK, encrypts the body with AES-256-GCM, wraps the
   CEK for each recipient via HPKE base-mode (ECDH P-256 + custom
   SHA-256 KDF), and writes the `multipart/hpke+wrapped` envelope to
   `posts-encrypted/<slug>.eml`. All crypto is delegated to
   Crane_crypto (mirage-crypto + digestif).
3. `.githooks/pre-commit` calls that tool with `--stage` for every
   staged `posts/*.md`.
4. `src/Logic.v` (Rocq, extracted to C++) reads
   `./posts-encrypted/*.eml`, splits headers from body at the first
   blank line, and renders each file as a page whose `<pre>` holds
   the body verbatim. The generator is pure, total, and never
   touches cryptographic bytes — it only concatenates already-ciphertext
   strings into HTML.
5. `tools/decrypt_post.ml` (OCaml) is the local inverse: parses the HPKE
   envelope, unwraps the CEK using the local private key, decrypts the
   body with AES-256-GCM, and writes the inner MIME parts back to `posts/`.
6. `static/decrypt.ml` and `static/enroll.ml` (OCaml, compiled to
   JavaScript by js_of_ocaml) provide browser-side decryption and reader
   enrollment via Web Crypto API and WebAuthn passkeys.

## Verification claims

- Rocq type-checks `src/Logic.v`; every recursion is structural or
  fuel-bounded. This check is run in Docker, not against host-local
  Rocq/coqc installations.
- Crane extracts the Rocq definitions to C++23 and clang accepts
  the result.
- `scripts/test-roundtrip.sh` runs end to end with an ephemeral
  ECDH P-256 keypair: it generates a test key with openssl, encrypts a
  fixture via `encrypt_post`, decrypts via `decrypt_post`, confirms
  byte-for-byte round-trip, builds the Rocq/Crane generator in Docker,
  and confirms the rendered HTML contains no leaks.
- **The encryption itself is not formally verified.** The HPKE protocol
  is specified in CryptoSpec.v with cryptographic axioms, but the OCaml
  FFI (mirage-crypto), JavaScript bridge (Web Crypto API), and
  openssl-backed C++ (sha256_trunc) are trust boundaries. No verified
  ECDH/AES-GCM implementation exists in Rocq/Coq today.

## Build

The Rocq/Crane generator is built and run exclusively inside Docker. Host-side
opam/dune is only for the small OCaml authoring tools.

```bash
docker build -t crane-blog .
mkdir -p _site
docker run --rm \
  -v "$PWD/posts-encrypted:/site/posts-encrypted:ro" \
  -v "$PWD/_site:/site/_site" \
  crane-blog
```

Publishing a new encrypted post does not rebuild Rocq/Crane. CI pulls the
published runtime generator image and mounts the new `posts-encrypted/` tree.
The slow image rebuild runs only when `Dockerfile`, `dune-project`, `src/`, or
`.dockerignore` changes.

Pinned: opam 2.5, OCaml 5.4, Rocq 9.0.0, `coq-itree`, `coq-paco`,
`coq-ext-lib`, `rocq-crane` (from upstream), mirage-crypto, digestif.

Iterative work:

```bash
docker build --target builder -t crane-blog-builder .
docker run --rm -it -v "$PWD":/home/opam/crane-blog crane-blog-builder bash
eval $(opam env) && dune build src/blog_generator.exe
./_build/default/src/blog_generator.exe
```

## Deploy

`.github/workflows/deploy.yml` runs on every push to `main`. If the generator
changed, CI rebuilds and publishes the runtime generator image to GHCR. For a
post-only commit, CI pulls the existing image, mounts the already-ciphertext
`posts-encrypted/` tree plus `_site/`, runs the generator, uploads via
`actions/upload-pages-artifact`, and publishes via `actions/deploy-pages`. CI
never holds private keys.

## Credits

[Crane](https://github.com/bloomberg/crane) is developed by
Bloomberg; this repository uses it as an opam dependency. HPKE
cryptography is delegated to
[mirage-crypto](https://github.com/mirage/mirage-crypto) and
[digestif](https://github.com/mirage/digestif).
