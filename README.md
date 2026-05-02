# crane_blog

A static site generator whose core is written in
[Rocq](https://rocq-prover.org) and extracted to C++ by
[Bloomberg's Crane](https://github.com/bloomberg/crane). Posts are
encrypted with OpenPGP before commit and rendered as PGP/MIME emails.
Deployed at <https://wklm.github.io>.

## What the site is

Every post on the site is, literally, a PGP-encrypted email rendered
inside a classic, restrained blog shell. The homepage lists opaque
entries whose visible title is always `Subject: ...`; each entry links
to a page whose public text is the same placeholder and a
`-----BEGIN PGP MESSAGE-----` ciphertext block. The only way to read a
post is to copy the armored block and run `gpg --decrypt`. A reader who
is not a listed recipient sees opaque ciphertext.

## Authoring model

Plaintext lives on the author's working tree under `posts/` and is
**gitignored**. A pre-commit hook converts every staged
`posts/*.md` into `posts-encrypted/<slug>.eml`, stages the `.eml`,
and unstages the plaintext. Only ciphertext is tracked.

```text
posts/                working-tree only; never committed
posts-encrypted/      the only thing the remote ever sees
```

Each `.eml` is an RFC 3156 `multipart/encrypted; protocol=
"application/pgp-encrypted"` message. The inner payload is a
`multipart/mixed` containing the original Markdown and every inline
image as a base64 attachment, all signed-then-encrypted by `gpg` to
the author and up to three declared recipients.

### Frontmatter keys

| key          | meaning                                                           |
|--------------|-------------------------------------------------------------------|
| `slug`       | output directory and `.eml` basename; falls back to the file stem |
| `recipients` | comma-separated emails (max 3); the author is always added        |

All other keys are left for the author's own reference inside the
encrypted body — they are never leaked, because the body is never
rendered. The outer envelope carries only `Subject: ...` plus the MIME
headers needed for RFC 3156 framing.

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
memory with the checked-in public key, wraps it in an RFC 3156 envelope with
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
```

## Pipeline

1. `smtp/listener.py` (Docker on fuji). Receives normal SMTP from
   Mail.app over Tailscale, encrypts the message body in memory with
   GnuPG and the checked-in public key, wraps it as RFC 3156
   `multipart/encrypted`, writes `posts-encrypted/*.eml`, commits, and
   pushes. No private key lives on fuji.
2. `tools/encrypt_post.ml` (OCaml). Parses the frontmatter, resolves
   `recipients`, builds a `multipart/mixed` inner MIME tree, pipes
   it to `gpg --sign --encrypt --armor --local-user <author>
   --recipient <author> --recipient …`, wraps the armored output in
   the RFC 3156 envelope, writes `posts-encrypted/<slug>.eml`. No
   crypto is implemented here; all OpenPGP work is done by `gpg`.
3. `.githooks/pre-commit` calls that tool with `--stage` for every
   staged `posts/*.md`.
4. `src/Logic.v` (Rocq, extracted to C++) reads
   `./posts-encrypted/*.eml`, splits headers from body at the first
   blank line, and renders each file as a page whose `<pre>` holds
   the body verbatim. The generator is pure, total, and never
   touches OpenPGP bytes — it only concatenates already-ciphertext
   strings into HTML.
5. `tools/decrypt_post.ml` is the local inverse: walks the MIME tree
   in a `.eml`, pipes the armored part through `gpg --decrypt`,
   writes the parts back to `posts/`.

## Verification claims

- Rocq type-checks `src/Logic.v`; every recursion is structural or
  fuel-bounded. This check is run in Docker, not against host-local
  Rocq/coqc installations.
- Crane extracts the Rocq definitions to C++23 and clang accepts
  the result.
- `scripts/test-roundtrip.sh` runs end to end with an ephemeral GPG
  keyring: it confirms byte-for-byte round-trip of the Markdown and
  image, confirms a PKESK packet is present in the armored body,
  builds and runs the Rocq/Crane generator in Docker, and confirms the
  rendered HTML contains no `<img>` tag, contains the armor, and shows
  only `Subject: ...` publicly.
- **The encryption itself is not formally verified.** OpenPGP is
  delegated to GnuPG, which is the same trust boundary any PGP
  email client operates under. No verified OpenPGP implementation
  exists today in any language; building on verified primitives
  (e.g. HACL\*) would require re-implementing RFC 4880 framing,
  which would contradict the goal of replicating PGP email
  bit-for-bit.

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
`coq-ext-lib`, `rocq-crane` (from upstream), GnuPG 2.x.

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
Bloomberg; this repository uses it as an opam dependency. OpenPGP
work is delegated to [GnuPG](https://gnupg.org/).
