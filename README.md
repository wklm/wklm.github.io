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
encrypted with HPKE (ECDH P-256 + AES-256-GCM) and signed with the author's
ECDSA P-256 key before commit, then rendered as encrypted MIME envelopes.
Deployed at
<https://wklm.online>.

## What the site is

Every post on the site is a HPKE-encrypted MIME envelope rendered
inside a classic, restrained blog shell. The homepage lists opaque
entries whose visible title is always `Subject: ...`; each link points
to a page whose public text is the same placeholder and a ciphertext
block. Every envelope carries an ECDSA P-256 author signature,
which both the native tool and the browser verify before any key is
unwrapped. A reader who has enrolled a P-256 keypair in the browser can
decrypt posts in-page via Web Crypto API. An unenrolled reader sees
only opaque ciphertext.

## Authoring model

Plaintext lives on the author's working tree under `posts/` and is
**gitignored**. A pre-commit hook converts every staged
`posts/*.md` into `posts-encrypted/<slug>.eml`, stages the `.eml`,
and unstages the plaintext. Only ciphertext is tracked, and only
**signed** ciphertext: the hook rejects any staged `.eml` that lacks
the `Signature:` / `Signing-Key:` headers.

```text
posts/                working-tree only; never committed
posts-encrypted/      the only thing the remote ever sees
```

Each `.eml` is a HPKE MIME envelope: a `multipart/hpke+wrapped` container
with `application/wrapped-keys` (per-recipient CEK wraps)
and `application/aes-gcm` (AES-256-GCM ciphertext) parts. The inner
payload is a `multipart/mixed` containing the original Markdown and
every inline image as a base64 attachment. Two outer headers
authenticate the envelope: `Signature:` (128 hex chars — the raw 64-byte
ECDSA P-256 signature over `SHA-256("crane-blog-sign-v1" ‖ ciphertext)`) and
`Signing-Key:` (130 hex chars — the 65-byte uncompressed SEC1 signing public
key), alongside `Public-Keys:` (recipient key IDs).

### Frontmatter keys

| key          | meaning                                                           |
|--------------|-------------------------------------------------------------------|
| `slug`       | output directory and `.eml` basename; falls back to the file stem |
| `recipients` | comma-separated reader key IDs (max 3); the author is always added. Each listed key is resolved from `keys/<kid>.pub` — automatically fetched from the public key directory if missing (see the reader flow below) |

All other keys are left for the author's own reference inside the
encrypted body — they are never leaked, because the body is never
rendered. The outer envelope carries only `Subject: ...` plus the
MIME headers needed for HPKE envelope framing and the signing headers.

### Signing

Every envelope must be signed by the author. One-time setup:

```bash
# One-time per clone
scripts/generate-signing-key.sh
# -> writes keys/<kid>.sign.pub (gitignored) and prints the private
#    scalar once; export it in every shell that runs encrypt_post:
export CRANE_BLOG_SIGNING_KEY_ID=<kid>
export CRANE_BLOG_SIGNING_KEY=<private-scalar-hex>
```

`keys/` is gitignored — the public half is never committed; the private
half exists only in the author's environment and in fuji's secrets (the
smtp container receives the same two env vars via `compose.yml`).
`encrypt_post` / `smtp_server` sign with these env vars; `decrypt_post`
resolves the trust anchor from `CRANE_BLOG_SIGNING_KEY_ID` +
`keys/<kid>.sign.pub`; the browser verifies against the envelope's own
`Signing-Key` header.

The pre-signing-era posts (unsigned envelopes) were removed from
`posts-encrypted/` when signing landed; the site is published from
`posts-encrypted/` only, and the pre-commit hook plus both deploy
workflows reject unsigned envelopes.

### Image references

Any inline `![alt](path)` where `path` is a plain relative filename
under `posts/` is picked up by the hook, read as raw bytes, and
attached to the inner MIME tree. HTTP(S) URLs and absolute paths
are left untouched (they end up as plaintext inside the encrypted
body).

## Reader enrollment and the key directory

The "reader sends only the short key ID" story is fully automatic — no key
files are ever exchanged by hand, and no reader key is stored on fuji's disk.

1. **Enroll.** On `wklm.online/enroll/` the reader's browser rolls an ECDH
   P-256 keypair, stores the private JWK in IndexedDB, and **POSTs the public
   key to the blog's public key directory** — a Cloudflare Worker + KV
   (`crane-blog-keydir`, outside this repo). Registration is
   self-authenticating: the directory derives the key ID from the pubkey
   (`kid = sha256(compress(pubkey))[:12]`) and rejects mismatches, so a key
   can only be registered under its own ID. The enroll page then shows the
   key ID and a "Registered with the key directory" status; offline, it
   falls back to showing the key for the manual path.
2. **Encrypt by ID only.** The author writes `recipients: <kid>` in the
   frontmatter. The pre-commit hook calls `scripts/resolve-keys.sh <kid>`,
   which fetches the pubkey from the directory into `keys/<kid>.pub`
   (gitignored, auto-populated — never saved by hand); `encrypt_post` wraps
   the CEK for every listed recipient (plus the author) and emits one
   `Public-Keys` / `Wraps` entry each. The smtp listener's entrypoint does
   the same for its configured `BLOG_PUBLIC_KEYS`.
3. **Decrypt.** Unchanged: the browser matches its enrolled key ID against
   the envelope's `Public-Keys`, verifies the author signature, unwraps and
   renders.

The directory only ever holds public keys; the private JWK never leaves the
reader's device. It is a registry, not an identity provider — registering a
key proves only that its holder can be addressed as a recipient (see
`TRUSTED.md` C16).

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
memory with the checked-in public key, signs the envelope with the author
ECDSA key (env `CRANE_BLOG_SIGNING_KEY_ID` / `CRANE_BLOG_SIGNING_KEY`,
injected from fuji secrets), wraps it in an HPKE envelope with
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
# (the hook runs encrypt_post, so CRANE_BLOG_SIGNING_KEY_ID and
#  CRANE_BLOG_SIGNING_KEY must be exported in this shell)

# To edit an existing post:
./_build/default/tools/decrypt_post.exe posts-encrypted/my-slug.eml
# -> decrypted markdown + images land in posts/
# You need your P-256 private key in CRANE_BLOG_PRIVATE_KEY env var,
# plus CRANE_BLOG_SIGNING_KEY_ID (decrypt_post verifies the envelope's
# signature against keys/<kid>.sign.pub).
```

## Pipeline

1. `src/SmtpServer.v` (Rocq → C++23 → native `smtp_server.exe`, Docker
   on fuji). `run : IO unit` over `dirE +' ioE +' toolE +' netE +' procE`.
   Receives normal SMTP from Mail.app over Tailscale, runs the pure SMTP
   state machine (`src/Smtp.v`), ingests the inbound MIME (`src/MimeIngest.v`)
   and assembles the markdown + frontmatter (`src/PostBuild.v`), encrypts the
   body **in process** (HPKE, via `CryptoSpec.v` + `MimeBuild.v` — no
   subprocess), signs the ciphertext package with the author ECDSA key
   (`CRANE_BLOG_SIGNING_KEY_ID` / `CRANE_BLOG_SIGNING_KEY`), writes
   `posts-encrypted/*.eml`, then commits and pushes. The socket layer is
   realized by `src/net_helpers.h` (boundary C5) and git/
   subprocess calls by `src/proc_helpers.h` (C6). No recipient/reader private
   key lives on fuji; the only key material there is the author's ECDSA
   signing key, injected as environment from fuji secrets and never written
   to disk. Built native to `smtp_server.exe` by `smtp/Dockerfile`
   (`FROM crane-blog:builder`).
2. `src/EncryptPost.v` (Rocq → C++23 → native `tools/encrypt_post.exe`).
   Parses the frontmatter, resolves recipients, builds a `multipart/mixed`
   inner MIME tree, generates a random 32-byte CEK, encrypts the body with
   AES-256-GCM, wraps the CEK for each recipient via HPKE base mode (ECDH
   P-256 + `custom_kdf_sha256`), signs the raw ciphertext package with the
   author ECDSA key (`sign_post`; env `CRANE_BLOG_SIGNING_KEY_ID` /
   `CRANE_BLOG_SIGNING_KEY`), and writes the `multipart/hpke+wrapped`
   envelope with `Signature:` / `Signing-Key:` headers to
   `posts-encrypted/<slug>.eml`. The HPKE protocol layer
   (`src/CryptoSpec.v`) and MIME construction (`src/MimeBuild.v`) are pure
   Rocq; only the eleven cryptographic primitives cross the FFI, realized
   natively by OpenSSL EVP in `src/crypto_helpers.h` (boundary C1).
3. `.githooks/pre-commit` calls `_build/default/tools/encrypt_post.exe
   --stage` for every staged `posts/*.md` — and **rejects** any staged
   `.eml` that lacks the `Signature:` (128 hex) / `Signing-Key:` (130 hex)
   / `Public-Keys:` headers.
4. `src/Logic.v` (Rocq → C++23 → native `blog_generator.exe`) reads
   `./posts-encrypted/*.eml`, splits headers from body at the first
   blank line, and renders each file as a page whose `<pre>` holds
   the body verbatim. The generator is pure, total, and never
   touches cryptographic bytes — it only concatenates already-ciphertext
   strings into HTML, and emits the `<script type="module">` bootstrap that
   loads the WASM decrypt/enroll modules.
5. `src/DecryptPost.v` (Rocq → C++23 → native `tools/decrypt_post.exe`) is
   the local inverse: **verifies the ECDSA signature first** — it loads the
   trust anchor from `CRANE_BLOG_SIGNING_KEY_ID` + `keys/<kid>.sign.pub`
   and refuses a missing `Signature` header, a `Signing-Key` mismatch, or a
   failed `verify_post` — then parses the HPKE envelope, unwraps the CEK
   using the local private key, decrypts the body with AES-256-GCM, and
   writes the inner MIME parts back to `posts/`. It reuses the same
   pure-Rocq `CryptoSpec.v` + `MimeBuild.v`.
6. `src/DecryptApp.v` and `src/EnrollApp.v` (Rocq → C++23 → WASM)
   provide browser-side post decryption and reader enrollment.
   Each is `run : BIO unit` over the `brE` browser effect algebra in
   `src/BrowserEffect.v` (DOM, sessionStorage, IndexedDB, WebAuthn, CSPRNG),
   reusing the **same** pure-Rocq `CryptoSpec.v` HPKE protocol plus
   `src/InnerMime.v` for rendering — and rejecting envelopes whose ECDSA
   signature does not verify against the envelope's own `Signing-Key`
   header before decrypting. In the browser the eleven crypto
   primitives are re-pointed (`src/BrowserCrypto.v`) to `crypto.subtle` /
   `getRandomValues`, realized by `EM_ASM` glue in `src/browser_helpers.h`
   (boundaries C2/C3). The Dockerfile `wasm` stage Crane-extracts these and
   links them with `em++` (emsdk 3.1.61, `-O2 -sASYNCIFY`) into
   `static/crane_decrypt.{mjs,wasm}` and `static/crane_enroll.{mjs,wasm}`.
7. `tests/e2e/roundtrip.spec.ts` (Playwright, on the fuji self-hosted
   runner) is the browser acceptance gate: **7 test rows** — in-browser
   enroll via a CDP virtual WebAuthn authenticator (3 authenticator
   profiles), enroll-fails-visibly, inbox NO-KEY/HAS-KEY coherence, and
   decrypt-failure visibility — against a signed fixture envelope served
   over HTTPS. `scripts/check-tail-position.sh` (wired into the e2e and
   both deploy workflows) gates the freshly extracted C++ against
   non-tail self-recursion, the WASM stack-overflow class.

## Verification claims

- Rocq type-checks `src/Logic.v`; every recursion is structural or
  fuel-bounded. This check is run in Docker, not against host-local
  Rocq/coqc installations.
- Crane extracts the Rocq definitions to C++23 and clang accepts
  the result.
- `scripts/test-roundtrip.sh` runs end to end with ephemeral keypairs:
  it generates an ECDH P-256 keypair **and an author ECDSA signing
  keypair** with openssl, encrypts a fixture via `encrypt_post`, asserts
  the signed envelope headers (`Signature:` / `Signing-Key:`), decrypts
  via `decrypt_post`, confirms byte-for-byte round-trip, rejects a
  tampered `Signature` header, builds the Rocq/Crane generator in Docker,
  and confirms the rendered HTML contains no leaks.
- **The encryption itself is not formally verified.** The HPKE protocol
  composition (wrap/unwrap CEK, body encrypt/decrypt, `custom_kdf_sha256`,
  P-256 point compression) is pure Rocq in `CryptoSpec.v`, but the eleven
  underlying primitives (ECDH P-256, AES-256-GCM, SHA-256, ECDSA P-256
  sign/verify, base64, CSPRNG)
  are stated as axioms and cross an FFI boundary: natively to OpenSSL EVP
  (`crypto_helpers.h`, C1) and in the browser to `crypto.subtle` /
  `getRandomValues` (`browser_helpers.h`, C2). The round-trip/AEAD
  properties — including `ecdsa_roundtrip` — are *stated as axioms* in
  `CryptoSpec.v`. No verified
  ECDH/AES-GCM/ECDSA implementation exists in Rocq/Coq today. Every trusted
  boundary (C1–C15) is enumerated in [`TRUSTED.md`](TRUSTED.md).
- The e2e gate (`tests/e2e/`, Playwright + CDP virtual WebAuthn
  authenticator, 7 rows) runs on the fuji self-hosted runner against the
  shipped WASM apps; the tail-position gate (`scripts/check-tail-position.sh`)
  runs in CI on the freshly extracted C++. No Python is involved anywhere
  in the pipeline (the legacy host-installed python SMTP listener was
  decommissioned — see `scripts/setup_fuji.sh`).

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
