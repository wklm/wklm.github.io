# wklm.github.io — Editorial & Design Brief

This document describes the *intent* of the site at `wklm.github.io`. The
companion `README.md` covers the build. Here I am concerned with what
the site is trying to be, how it should read, and how it should look.

## Premise

`wklm.github.io` is a personal publication of technical essays
distributed as PGP-encrypted email. Every page on the public site is,
literally, a PGP/MIME message: an inbox of `Subject: ...` headers on
the homepage, an RFC 5322 envelope on each post page, and below it a
`-----BEGIN PGP MESSAGE-----` block. The reader is not given a
rendered essay. The reader is given ciphertext, and — if they hold
one of the listed recipient keys — the means to decrypt it.

The point of this is not novelty. It is the editorial stance: the
site does not solicit a passing audience. To read a piece you must
already be on the recipient list, or you must do the work of
becoming one. Everyone else sees the envelope.

The generator that builds the inbox is written in Rocq and extracted
to C++ via Crane. That fact matters to me, but the site is not a
demo for the generator. The generator is infrastructure; the
encryption is the editorial gesture; the writing is the product.

## Voice and editorial scope

First person, restrained, declarative. The pieces themselves —
which only the recipients ever read — follow the same rules as
before:

- No marketing register. No "unlock", "leverage", "powerful",
  "seamless", "cutting-edge".
- No hedging tics. If it is worth noting, note it.
- Claims are either grounded or marked as opinion.
- Essays, not posts. Length is whatever the argument needs.

Topics in scope: proof engineering in Rocq and adjacent systems;
extraction pipelines; programming-language design; small,
well-shaped tools; typography; the visual grammar of
early-20th-century European design. Topics out of scope: product
announcements, hot takes, career advice.

The public site itself carries no editorial register at all — only
metadata and ciphertext. Subjects are always the literal string
`Subject: ...`, so even the title of a piece does not leak.

## Visual language

The site renders as a plain mail client, deliberately ugly in the
way real `.eml` files are ugly. Monospace everywhere. Minimal
chrome. The reference points are early Pine/Mutt screenshots and
the raw output of `gpg --decrypt`. Concretely:

- A near-white page with near-black text. A single muted accent for
  rule lines and the inbox hover state. No second typeface, no
  ornaments, no display headings.
- A single monospace family for the entire site (system
  `ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace`).
- Each post page has two regions, separated by a horizontal rule:
  a `<dl class='eml-headers'>` table of `From / To / Date /
  Content-Type` rows, then a `<pre class='eml-body'>` containing
  the multipart-encrypted body verbatim, including the
  `-----BEGIN PGP MESSAGE-----` armor.
- The homepage is an `<ol class='inbox'>` of rows; each row shows
  `From`, `Date`, and a link whose text is `Subject: ...`.
- No JavaScript. No webfonts. No images on any rendered page —
  every image in a post is encrypted as a MIME attachment inside
  the ciphertext, never exposed.

Explicit anti-patterns:

- No card grids, no hero, no featured tile.
- No gradients, no blurred blobs, no glassmorphism.
- No decorative emoji. No badges. No social-embed chrome.
- Nothing that suggests the site is trying to be read by a casual
  visitor. The aesthetic should communicate, immediately, that
  this page is correspondence and not an article.

## Information architecture

- **Homepage.** A list of envelopes. Rendered by
  `render_inbox_page` in [src/Logic.v](src/Logic.v). Each row is:
  `From`, `Date`, `Subject: ...` as a link to `/<slug>/`. Sorted
  by `Date` descending.
- **Post page.** Headers table on top, ciphertext `<pre>` below.
  Rendered by `render_eml_page` in [src/Logic.v](src/Logic.v). The
  `<pre>` contains the body of the `.eml` byte-for-byte after HTML
  escaping; nothing is reformatted.
- **URL shape.** Each message lives at `/<slug>/`. The slug is the
  basename of the `.eml` file in `posts-encrypted/`.
- **Visible headers.** `From`, `To`, `Date`, `MIME-Version`,
  `Content-Type`. Everything else (`Subject`, any `X-` headers,
  `Message-ID`) is suppressed at render time so it cannot leak
  metadata, and the public `Subject:` is always literally `...`.

## What is verified today

I want to be precise about this, because the encryption story is
easy to overclaim.

What currently holds:

- The generator is written in Rocq ([src/Logic.v](src/Logic.v)) and
  is accepted by the type checker. All recursive definitions are
  total under structural recursion or explicit `nat` fuel.
- Extraction via `Crane Extraction "blog" run` succeeds, yielding
  C++23 source.
- That C++ source compiles under clang++ and runs, producing the
  `_site/` tree.
- `scripts/test-roundtrip.sh` confirms end-to-end that the OCaml
  encrypt/decrypt tools round-trip a Markdown post and a binary
  attachment byte-for-byte through `gpg`, that the resulting
  armored body contains a PKESK packet, and that the rendered HTML
  contains the armor and never an `<img>` or a real subject line.

What is *not* verified today:

- There are no theorems in the repository.
- The OpenPGP encryption itself is **not** formally verified. It
  is delegated to GnuPG, which is the same trust boundary any PGP
  email client operates under. No verified end-to-end OpenPGP
  implementation exists today in any language; building one on
  top of verified primitives (e.g. HACL\*) would require
  re-implementing RFC 4880 framing, which would defeat the goal
  of replicating PGP-email behaviour bit-for-bit.
- The OCaml glue in `tools/` — frontmatter parsing, MIME framing,
  subprocess plumbing — is type-checked code, not proved code.

Compile-time success is evidence that the system is type-consistent
and terminating. Round-trip success is evidence that the framing
matches what `gpg` expects. Neither is a correctness claim about
the cryptography.

## Roadmap

Verification work I consider worth doing, in rough order:

1. A narrowly-scoped theorem about `render_eml_page`: every visible
   header value passes through `html_escape`, and no character
   outside the ciphertext alphabet (`A–Z a–z 0–9 + / = -` plus
   newline) appears inside `<pre class='eml-body'>`.
2. A proof that `parse_eml` and the unparser used by the OCaml
   tool agree on the boundary (headers / blank line / body) for
   the subset of messages we generate.
3. A formalisation of the RFC 3156 envelope structure, against
   which the OCaml emitter can be checked by extraction and round
   trip.

Content and tooling work:

- A `decrypt-all` driver that reconstructs `posts/` from
  `posts-encrypted/` for the author.
- A pre-receive check in CI that rejects any push touching
  `posts/`.
- A short note on each recipient's key fingerprint, kept in the
  repo so subscribers can verify out-of-band.

## Out of scope

Comments, analytics, newsletters, pop-ups, cookie banners,
tracking pixels, A/B tests, a CMS, a dashboard, a Twitter-card
generator, a theme switcher, any rendering of post bodies on the
public site, any plaintext on the public site beyond envelope
metadata. If any of these appear, something has gone wrong.
