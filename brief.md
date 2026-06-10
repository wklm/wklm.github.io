# wklm.online — Editorial & Design Brief

This document describes the *intent* of the site at `wklm.online`. The
companion `README.md` covers the build. Here I am concerned with what
the site is trying to be, how it should read, and how it should look.

## Premise

`wklm.online` is a personal publication of technical essays
distributed as HPKE-encrypted MIME envelopes. The public site is a classic,
restrained blog shell, but every post is still only an HPKE/MIME
ciphertext: a list of `Subject: ...` entries on the homepage and, on
each post page, a ciphertext block. The reader is
not given a rendered essay. The reader is given ciphertext, and — if
they have enrolled an authorized keypair — the means to decrypt it.

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

The public site itself carries almost no editorial register — only the
classic shell, the fixed placeholder, and ciphertext. Subjects are
always the literal string `Subject: ...`, so even the title of a piece
does not leak.

## Visual language

The site renders as a small literary page, not a webmail imitation.
The reference points are classic personal sites, quiet book typography,
and source artifacts shown without apology. Concretely:

- A near-white page with near-black text, restrained width, generous
  leading, and minimal navigation.
- Serif body typography for the shell; monospace only for the encrypted
  body.
- The homepage is a plain list of links whose text is always
  `Subject: ...`.
- Each post page has a classic article shell with the fixed heading
  `Subject: ...`, followed by `<pre class='eml-body'>` containing the
  multipart-encrypted body verbatim after HTML escaping.
- No JavaScript. No webfonts. No images on any rendered page — every
  image in a post is encrypted as a MIME attachment inside the
  ciphertext, never exposed.

Explicit anti-patterns:

- No card grids, hero sections, featured tiles, badges, or social chrome.
- No gradients, blurred blobs, glassmorphism, or decorative emoji.
- No plaintext excerpts, summaries, descriptions, or real titles.

## Information architecture

- **Homepage.** A list of opaque entries. Rendered by
  `render_inbox_page` in [src/Logic.v](src/Logic.v). Each row links to
  `/<slug>/` with the literal text `Subject: ...`. Sorted by a hidden
  key: timestamp slugs first, otherwise the generated date key.
- **Post page.** Classic shell on top, ciphertext `<pre>` below.
  Rendered by `render_eml_page` in [src/Logic.v](src/Logic.v). The
  `<pre>` contains the body of the `.eml` byte-for-byte after HTML
  escaping; nothing is reformatted.
- **URL shape.** Each message lives at `/<slug>/`. The slug is the
  basename of the `.eml` file in `posts-encrypted/`.
- **Visible metadata.** The public title/link text is always literally
  `Subject: ...`. Sender, recipient, date, message id, and real subject
  are suppressed from the public HTML and from newly generated outer
  envelopes.

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
- `scripts/test-roundtrip.sh` confirms end-to-end that the native
  encrypt/decrypt tools round-trip a Markdown post and a binary
  attachment byte-for-byte, that the resulting encrypted
  body is a valid HPKE envelope, and that the public output contains the
  ciphertext and never an `<img>`, real subject line, or outer sender/date
  metadata.

What is *not* verified today:

- The theorems in the repository (privacy, HTML escaping, parse_eml
  structure) verify the *public rendering* — that the public page
  contains only the ciphertext body and fixed template strings. They
  do not verify the *cryptography*.
- **The encryption itself is not formally verified.** The HPKE protocol
  composition is pure Rocq in `CryptoSpec.v`, but the underlying primitives
  (ECDH P-256, AES-256-GCM, SHA-256, base64, CSPRNG) are stated as axioms
  and cross an FFI boundary. The round-trip/AEAD properties are *stated as
  axioms* in `CryptoSpec.v`. No verified ECDH/AES-GCM implementation exists
  in Rocq/Coq today. Every trusted boundary is enumerated in `TRUSTED.md`.
- The extracted C++ glue — frontmatter parsing, MIME framing,
  subprocess plumbing — is type-checked code, not proved code.

Compile-time success is evidence that the system is type-consistent
and terminating. Round-trip success is evidence that the framing
matches what is expected. Neither is a correctness claim about
the cryptography.

## Roadmap

Verification work I consider worth doing, in rough order:

1. ~~A narrowly-scoped theorem about `render_eml_page`~~ — done. The
   `privacy` theorem in `src/Spec.v` proves that `render_eml_page` only
   reads `ep_body` and the public subject is the literal placeholder.
2. A proof that `parse_eml` and the unparser used by the native
   tool agree on the boundary (headers / blank line / body) for
   the subset of messages we generate.
3. A formalisation of the HPKE envelope structure, against
   which the C++ emitter can be checked by extraction and round
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
