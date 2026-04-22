# wklm.online — Editorial & Design Brief

This document describes the *intent* of the site at `wklm.online`. The
companion `README.md` covers the build. Here I am concerned with what
the site is trying to be, how it should read, and how it should look.

## Premise

`wklm.online` is a personal publication of technical essays. The
subject matter is narrow: formal verification, the tools we use to
build software, visual design, and the places where those concerns
overlap. The generator that builds it is written in Rocq and extracted
to C++ via Crane — that fact matters to me, but the site is not a demo
for the generator. The generator is infrastructure; the writing is the
product.

## Voice and editorial scope

First person, restrained, declarative. I am writing for readers who
already know the territory, or who are willing to meet the text on its
own terms. The editorial rules are:

- No marketing register. No "unlock", "leverage", "powerful",
  "seamless", "cutting-edge".
- No hedging tics ("it's worth noting that…", "at the end of the
  day…"). If it is worth noting, note it.
- Claims are either grounded or marked as opinion. A piece that asserts
  something about a proof, a compiler, or a spec is expected to cite
  the relevant artifact.
- Essays, not posts. Minimum viable length is "whatever is needed";
  there is no quota and no schedule.

Topics in scope: proof engineering in Rocq and adjacent systems;
extraction pipelines; programming-language design; small, well-shaped
tools; typography; the visual grammar of early-20th-century European
design. Topics out of scope: product announcements, hot takes on
industry news, career advice.

## Visual language

The reference points are Bauhaus (Tschichold, Bayer, Moholy-Nagy),
Klimt's ornamental palette, and the broader early modernist print
tradition. In practice this means:

- A warm off-white page (`#f4f0e8`) against near-black text
  (`#171717`), with a muted gold accent (`#b08d57`) used sparingly for
  link underlines and rules. A deep blue-black (`#12202c`) anchors code
  blocks. Secondary text sits in a warm grey (`#5c554c`). These are the
  literal values in the `stylesheet` constant in `src/Logic.v:637`.
- A two-family type system: a serif (Georgia) for running prose and a
  geometric-leaning sans (Arial/Helvetica as a pragmatic stand-in) for
  the site mark, navigation, and display headings. Display headings
  are set lowercase and tightly leaded; metadata and nav are uppercase
  with generous letter-spacing. See `.index-intro h1` and
  `.site-mark` in the same stylesheet.
- Strong horizontal rules. The site header is anchored by a heavy
  top border, not a logo lockup.
- Generous measure — text column caps around 36rem — and a grid-based
  post layout (`.post-layout` is a two-column grid of a meta rail and
  the article proper).

Explicit anti-patterns:

- No card grids on the homepage. No tile-flavoured "featured" hero.
- No gradients, no blurred blobs, no glassmorphism, no pastel
  "AI-slop minimalism".
- No decorative emoji in the chrome. No badges. No social-embed chrome.
- No JavaScript on reading pages. The generator emits a single
  stylesheet and static HTML; `render_post_page` and `render_index_page`
  in `src/Logic.v` do not reference a script tag.

## Information architecture

- **Homepage.** A numbered index. The HTML is literally an `<ol>`
  (`<ol class='post-list'>` emitted by `render_index_page` at
  `src/Logic.v:631`). Each entry is: number, small-caps metadata line,
  title as a link, a short deck. Nothing else. Posts are sorted by
  date, descending, via `sort_posts` / `insert_post`.
- **Post page.** Single-column article with a left meta rail
  (topic chip, date), a title, a deck, an optional lead image, and the
  body. This is `render_post_page` in `src/Logic.v:589`.
- **URL shape.** Each post lives at `/<slug>/`. The generator writes
  `output_dir/<slug>/index.html`; see `file_output_path` in
  `src/Logic.v:313`. Slugs are derived from the frontmatter `slug`
  field or the filename stem via `slugify` / `file_stem`.
- **Frontmatter.** The `Meta` record in `src/Logic.v:101` defines the
  supported keys: `title`, `date`, `slug`, `summary`, `topic`,
  `lead_image`, `lead_image_alt`, `draft`. `draft: true` suppresses
  publication via `should_publish`. Anything else is ignored.
- **Block grammar.** The `Block` ADT is deliberately small: `Heading2`,
  `Heading3`, `Paragraph`, `CodeBlock`, `ImageBlock`. The `Inline` ADT
  covers `Text`, `Link`, `CodeSpan`, `Emphasis`, `Strong`. There are no
  lists, tables, blockquotes, or footnotes yet; they will be added
  when an essay actually needs them, not before.

## What is verified today

I want to be precise about this, because the previous version of this
document overclaimed.

What currently holds:

- The generator is written in Rocq (`src/Logic.v`) and is accepted by
  the type checker. All definitions are total under the encoded fuel
  discipline — recursive text-processing functions (`parse_inlines_aux`,
  `parse_blocks`, `html_escape_aux`, `find_double_star`, etc.) take a
  `nat` fuel bound and terminate structurally on it.
- Extraction via `Crane Extraction "blog" run` (`src/Logic.v:705`)
  succeeds, yielding C++23 source.
- That C++ source compiles under clang++ and runs, producing the
  `_site/` tree.

What is *not* verified today:

- There are no theorems in the repository. In particular, there is no
  proof that `render_post_page` produces well-formed HTML, no proof of
  parser soundness, and no round-trip statement between `parse_post`
  and any canonical form.
- The `parse_*` family and the serializers in `render_block_impl` are
  best-effort: type-checked code, not proved code.

Compile-time success is evidence that the system is type-consistent
and terminating, nothing more. It is not a correctness claim.

## Roadmap

Verification work I consider worth doing, in rough order:

1. A narrowly-scoped theorem about `render_block_impl`: for every
   `Block`, the emitted string is balanced with respect to a small
   explicit tag alphabet (`<h2>`/`</h2>`, `<p>`/`</p>`, etc.) and every
   user-supplied substring passes through `html_escape`. This is
   tractable and worth the effort.
- A soundness statement for `html_escape` against a spec predicate
   that forbids the raw characters `&<>"'` in the output.
- A parser round-trip on a restricted grammar fragment (paragraphs of
   `Text` and `CodeSpan` only), extended opportunistically.

Content and tooling work:

- More `Block` constructors (lists, blockquotes) when an essay needs
  them.
- An RSS/Atom feed emitted from the same `Post` list.
- A local preview mode that watches `posts/` and rebuilds.

## Out of scope

Comments, analytics, newsletters, pop-ups, cookie banners, tracking
pixels, A/B tests, a CMS, a dashboard, a Twitter-card generator, and a
theme switcher. If any of these appear, something has gone wrong.
