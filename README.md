# crane_blog

A static site generator whose core is written in
[Rocq](https://rocq-prover.org) and extracted to C++ by
[Bloomberg's Crane](https://github.com/bloomberg/crane). Posts are
encrypted with OpenPGP before commit and rendered as PGP/MIME emails.
Deployed at <https://wklm.github.io>.

## What the site is

Every page on the site is, literally, a PGP-encrypted email. The
homepage is a mail-client-style inbox with `From`, `Date`, and
`Subject: ...` rows; each entry links to a page that shows the RFC
5322 headers of one message and, below them, the
`-----BEGIN PGP MESSAGE-----` armor of the ciphertext. The only way
to read a post is to copy the armored block and run
`gpg --decrypt`. A reader who is not a listed recipient sees opaque
ciphertext.

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
rendered. The outer envelope always carries `Subject: ...` so no
metadata leaks through it.

### Image references

Any inline `![alt](path)` where `path` is a plain relative filename
under `posts/` is picked up by the hook, read as raw bytes, and
attached to the inner MIME tree. HTTP(S) URLs and absolute paths
are left untouched (they end up as plaintext inside the encrypted
body).

## Workflow

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

1. `tools/encrypt_post.ml` (OCaml). Parses the frontmatter, resolves
   `recipients`, builds a `multipart/mixed` inner MIME tree, pipes
   it to `gpg --sign --encrypt --armor --local-user <author>
   --recipient <author> --recipient …`, wraps the armored output in
   the RFC 3156 envelope, writes `posts-encrypted/<slug>.eml`. No
   crypto is implemented here; all OpenPGP work is done by `gpg`.
2. `.githooks/pre-commit` calls that tool with `--stage` for every
   staged `posts/*.md`.
3. `src/Logic.v` (Rocq, extracted to C++) reads
   `./posts-encrypted/*.eml`, splits headers from body at the first
   blank line, and renders each file as a page whose `<pre>` holds
   the body verbatim. The generator is pure, total, and never
   touches OpenPGP bytes — it only concatenates already-ciphertext
   strings into HTML.
4. `tools/decrypt_post.ml` is the local inverse: walks the MIME tree
   in a `.eml`, pipes the armored part through `gpg --decrypt`,
   writes the parts back to `posts/`.

## Verification claims

- Rocq type-checks `src/Logic.v`; every recursion is structural or
  fuel-bounded.
- Crane extracts the Rocq definitions to C++23 and clang accepts
  the result.
- `scripts/test-roundtrip.sh` runs end to end with an ephemeral GPG
  keyring: it confirms byte-for-byte round-trip of the Markdown and
  image, confirms a PKESK packet is present in the armored body,
  and confirms the rendered HTML contains no `<img>` tag, contains
  the armor, and shows only `Subject: ...` on the inbox.
- **The encryption itself is not formally verified.** OpenPGP is
  delegated to GnuPG, which is the same trust boundary any PGP
  email client operates under. No verified OpenPGP implementation
  exists today in any language; building on verified primitives
  (e.g. HACL\*) would require re-implementing RFC 4880 framing,
  which would contradict the goal of replicating PGP email
  bit-for-bit.

## Build

```bash
docker build -t crane-blog .
docker run --name crane-blog-run crane-blog
docker cp crane-blog-run:/home/opam/crane-blog/_site ./_site
docker rm crane-blog-run
```

Pinned: opam 2.5, OCaml 5.4, Rocq 9.0.0, `coq-itree`, `coq-paco`,
`coq-ext-lib`, `rocq-crane` (from upstream), GnuPG 2.x.

Iterative work:

```bash
docker run --rm -it -v "$PWD":/home/opam/crane-blog crane-blog bash
eval $(opam env) && dune build src/blog_generator.exe
./_build/default/src/blog_generator.exe
```

## Deploy

`.github/workflows/deploy.yml` runs on every push to `main`: builds
the image, runs the container (reading only the already-ciphertext
`posts-encrypted/` tree), `docker cp`s `_site` out, uploads via
`actions/upload-pages-artifact`, publishes via
`actions/deploy-pages`. CI never holds private keys.

## Credits

[Crane](https://github.com/bloomberg/crane) is developed by
Bloomberg; this repository uses it as an opam dependency. OpenPGP
work is delegated to [GnuPG](https://gnupg.org/).
