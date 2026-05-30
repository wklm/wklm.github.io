# crane_blog

A static site generator whose every behavioral component is authored
in [Rocq](https://rocq-prover.org) (`.v`) and extracted to C++23 by
[Bloomberg's Crane](https://github.com/bloomberg/crane), then compiled
two ways: native with `clang++` (the generator, the CLI tools, and the
SMTP listener) and to WebAssembly with `em++`/Emscripten (the in-browser
decrypt and enrollment apps). Rocq is the single source of truth: the
exact bytes produced, all control flow, and every accept/reject decision
live in a `.v` file. The only non-`.v` artifacts are thin FFI shim
C headers, build configuration, and an end-to-end test harness — every
trusted boundary is catalogued in [`TRUSTED.md`](TRUSTED.md). Posts are
encrypted with HPKE (ECDH P-256 + AES-256-GCM) before commit and
rendered as encrypted MIME envelopes. Deployed at
<https://wklm.online>.

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

To smoke-test that SMTP path, send a normal plaintext email to the
listener from any SMTP client (Mail.app, or a one-shot tool such as
`swaks --server 100.99.77.105:2525 --from you@example.com --to
you@example.com --header 'Subject: hello'`). The listener's accept
policy, host, and port are configured by the `BLOG_ALLOW_FROM`,
`SMTP_HOST`, and `SMTP_PORT` environment variables (see `compose.yml`
and `smtp/entrypoint.sh`).

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

1. `src/SmtpServer.v` (Rocq → C++23 → native `smtp_server.exe`, Docker
   on fuji). `run : IO unit` over `dirE +' ioE +' toolE +' netE +' procE`.
   Receives normal SMTP from Mail.app over Tailscale, runs the pure SMTP
   state machine (`src/Smtp.v`), ingests the inbound MIME (`src/MimeIngest.v`)
   and assembles the markdown + frontmatter (`src/PostBuild.v`), encrypts the
   body **in process** (HPKE, via `CryptoSpec.v` + `MimeBuild.v` — no
   subprocess), writes `posts-encrypted/*.eml`, then commits and pushes. The
   socket layer is realized by `src/net_helpers.h` (boundary C5) and git/
   subprocess calls by `src/proc_helpers.h` (C6). No private key lives on
   fuji. Built native to `smtp_server.exe` by `smtp/Dockerfile`
   (`FROM crane-blog:builder`).
2. `src/EncryptPost.v` (Rocq → C++23 → native `tools/encrypt_post.exe`).
   Parses the frontmatter, resolves recipients, builds a `multipart/mixed`
   inner MIME tree, generates a random 32-byte CEK, encrypts the body with
   AES-256-GCM, wraps the CEK for each recipient via HPKE base mode (ECDH
   P-256 + `custom_kdf_sha256`), and writes the `multipart/hpke+wrapped`
   envelope to `posts-encrypted/<slug>.eml`. The HPKE protocol layer
   (`src/CryptoSpec.v`) and MIME construction (`src/MimeBuild.v`) are pure
   Rocq; only the nine cryptographic primitives cross the FFI, realized
   natively by OpenSSL EVP in `src/crypto_helpers.h` (boundary C1).
3. `.githooks/pre-commit` calls `_build/default/tools/encrypt_post.exe
   --stage` for every staged `posts/*.md`.
4. `src/Logic.v` (Rocq → C++23 → native `blog_generator.exe`) reads
   `./posts-encrypted/*.eml`, splits headers from body at the first
   blank line, and renders each file as a page whose `<pre>` holds
   the body verbatim. The generator is pure, total, and never
   touches cryptographic bytes — it only concatenates already-ciphertext
   strings into HTML, and emits the `<script type="module">` bootstrap that
   loads the WASM decrypt/enroll modules.
5. `src/DecryptPost.v` (Rocq → C++23 → native `tools/decrypt_post.exe`) is
   the local inverse: parses the HPKE envelope, unwraps the CEK using the
   local private key, decrypts the body with AES-256-GCM, and writes the
   inner MIME parts back to `posts/`. It reuses the same pure-Rocq
   `CryptoSpec.v` + `MimeBuild.v`.
6. `src/DecryptApp.v` and `src/EnrollApp.v` (Rocq → C++23 → WASM)
   provide browser-side post decryption and reader enrollment.
   Each is `run : BIO unit` over the `brE` browser effect algebra in
   `src/BrowserEffect.v` (DOM, sessionStorage, IndexedDB, WebAuthn, CSPRNG),
   reusing the **same** pure-Rocq `CryptoSpec.v` HPKE protocol plus
   `src/InnerMime.v` for rendering. In the browser the nine crypto
   primitives are re-pointed (`src/BrowserCrypto.v`) to `crypto.subtle` /
   `getRandomValues`, realized by `EM_ASM` glue in `src/browser_helpers.h`
   (boundaries C2/C3). The Dockerfile `wasm` stage Crane-extracts these and
   links them with `em++` (emsdk 3.1.61, `-O2 -sASYNCIFY`) into
   `static/crane_decrypt.{mjs,wasm}` and `static/crane_enroll.{mjs,wasm}`.

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
  composition (wrap/unwrap CEK, body encrypt/decrypt, `custom_kdf_sha256`,
  P-256 point compression) is pure Rocq in `CryptoSpec.v`, but the nine
  underlying primitives (ECDH P-256, AES-256-GCM, SHA-256, base64, CSPRNG)
  are stated as axioms and cross an FFI boundary: natively to OpenSSL EVP
  (`crypto_helpers.h`, C1) and in the browser to `crypto.subtle` /
  `getRandomValues` (`browser_helpers.h`, C2). The round-trip/AEAD
  properties are *stated as axioms* in `CryptoSpec.v`. No verified
  ECDH/AES-GCM implementation exists in Rocq/Coq today. Every trusted
  boundary (C1–C13) is enumerated in [`TRUSTED.md`](TRUSTED.md).

## Build

The Rocq/Crane toolchain is pinned and built inside Docker. The same builder
image compiles every native binary — the generator, the `encrypt_post` /
`decrypt_post` CLI tools, and the `smtp_server` listener — all from
Crane-extracted C++23; the `wasm` stage links the browser apps with `em++`.
`dune` drives the whole build.

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

Pinned: opam 2.5, Coq/Rocq 9.0.0, `coq-itree`, `coq-paco`, `coq-ext-lib`,
`rocq-crane` (from a pinned upstream commit), `clang++` for native builds,
and Emscripten `emsdk` 3.1.61 for the WASM build. Native crypto links
OpenSSL (`-lssl -lcrypto`); there is no mirage-crypto, digestif,
js_of_ocaml, or base64 OCaml dependency.

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
Bloomberg; this repository uses it as an opam dependency to extract
Rocq to C++23. The HPKE protocol is pure Rocq; its underlying
cryptographic primitives are delegated across an FFI boundary to
[OpenSSL](https://www.openssl.org/) (native) and the
[Web Crypto API](https://www.w3.org/TR/WebCryptoAPI/) (browser) — see
[`TRUSTED.md`](TRUSTED.md).
