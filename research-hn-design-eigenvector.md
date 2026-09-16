# HN Design Eigenvector — 60 linked blogs, averaged, consulted, applied

Source thread: <https://news.ycombinator.com/item?id=47302553> ("Ask HN: Most beautiful
personal blog UI you have ever seen?"). All 58 comments were fetched via the HN Firebase
API; 60 unique external links were extracted; one dedicated research subagent analyzed
each link's real HTML/CSS (vectors: `/tmp/opencode/hn-eigen/vectors/<slug>.json`, brief:
`/tmp/opencode/hn-eigen/BRIEF.md`, 60 task ids logged, composite snapshot:
`/tmp/opencode/hn-eigen/COMPOSITE.md`).

## 1. Method

1. Extract every external link from all 58 comments (dedupe; 60 unique).
2. Per link: fetch HTML/CSS with curl, parse fonts/scale/measure/palette/layout/motion/
   payload/structure, score 12 dimensions 0–10 with evidence, tag controlled-vocabulary
   design moves, write a structured "design eigenvector" JSON.
3. Average: confidence-weighted means (n=58 scored; `bryson-test` is a reserved `.test`
   domain, `vmfunc` was unreachable at HTTP 402 — excluded from means).
4. Consult: every one of the 60 subagents was resumed with the composite and the draft
   application plan; each answered "what matches / what the average gets wrong / one
   concrete CSS-HTML recommendation", with its own site's measured evidence.
5. Apply: edit the design surface of this repo (`src/Logic.v` CSS, `src/PageModel.v`
   markup), rebuild in `crane-blog:builder`, regenerate `_site`, re-run gates.

## 2. Composite eigenvector (confidence-weighted means, 0–10)

| personality | distinctiveness | content_presentation | color | layout | readability |
|---|---|---|---|---|---|
| 8.38 | 8.30 | 8.15 | 7.81 | 7.68 | 7.61 |

| typography | illustration | navigation | performance | accessibility | motion |
|---|---|---|---|---|---|
| 7.40 | 6.89 | 6.80 | 6.57 | 6.07 | 5.66 |

Top signature moves (weighted): restrained-palette 28 · hover-microinteractions 27 ·
single-column 23 · editorial-serif 20 · custom-display-type 19 · mono-accent 18 ·
dark-light-auto 17 · warm-paper 16 · custom-illustration 15 · static-fast 13.

Exemplars by mean: maggieappleton 8.96 · nicchan 8.92 · garden-bradwoods 8.71 ·
anhvn 8.54 · simonsarris 8.33 · svg-tutorial 8.29 · lynnandtonic 8.29 · meyerweb 8.25.

Reading: the thread rewards authorship and framing (personality, distinctiveness,
content presentation) above craft hygiene (accessibility, performance, motion). The
strongest sites are two- or three-voice type systems on warm paper with one accent —
not the most animated.

## 3. Consultation synthesis (60/60 replied)

Consensus adopted:
- One restrained accent with a real contrast job; **contrast must be measured, not
  assumed**. Multiple sites lost points to 2.7–3.7:1 "muted" text; every token here
  was re-derived to ≥4.5:1 (body ≥14:1).
- Mono reserved for ciphertext/metadata; serif for prose; measure in `ch` (the canvas
  already lands ≈66ch at 600px/18px).
- No gradients, no five-colour coding; a single recurring mark does more identity work
  than any palette (the brief's "no gradients" anti-pattern was being violated by the
  previous rainbow rule).
- Keep `prefers-reduced-motion`, `:focus-visible` with offset, skip-link, semantic
  landmarks; never `outline:0` (several celebrated sites shipped exactly that failure).
- Reduced-colour chrome means every grey must earn 4.5:1.

Contested, resolved by explicit product decision:
- ~15 agents warned that a canvas-only reading view costs find-in-page, selection and
  no-JS resilience. Countervailing fact for this repo: posts are HPKE ciphertext — with
  no JS there is nothing readable to fall back to, and `#real-body` is already the
  canonical decrypted DOM filled by the same WASM pass, clipped `sr-only` (not
  `display:none`). The user explicitly asked for one unified canvas default; the toggle
  was removed, and the e2e suite now asserts its absence.
- Mobile/desktop measure tokens: keep the 42rem shell and the canvas's own 37.5rem
  measure (≈66ch); no separate rem measure was layered on top (danluu/garden-bradwoods
  agents: set the measure once, don't double-cap).

## 4. Applied changes

`src/Logic.v` (stylesheet):
- Palette (lines 446–447): near-black ink `#1b1917` (16.5:1 on `#faf8f5`), metadata
  `#57534b` (7.2:1), single rust accent `#8a3b1f` (7.3:1; hover `#6f2f17`), stronger
  rules; dark scheme is darker paper `#141312` with `#f7f4ef` ink (16.9:1), `#b5aea3`
  metadata (8.4:1), `#f2a377` accent (9.1:1). All `--serene-*` variables removed;
  `color-scheme:light dark` added.
- Masthead (line 464): five-colour `border-image` gradient replaced by a solid ink rule
  (aligns with brief.md "No gradients").
- Links/focus (lines 457–459): hover/focus use the single accent; `:focus-visible` is a
  2px accent outline with 2px offset; `::selection` tinted with the accent.
- Reading view: "Comfortable spacing" toggle rules deleted; `#real-body` remains the
  clipped accessibility mirror and the canvas is the single default view;
  `.post-colophon:empty` hides the footer when empty.
- `serene · sleepless 2018` colophon `::after` removed.

`src/PageModel.v`:
- Removed the `reader-a11y` checkbox/label and its ID constant (line 95); post page now
  renders header → canvas → `sr-only` `#real-body` → images → colophon.

`tests/e2e/roundtrip.spec.ts`:
- Replaced the toggle test with unified-view assertions: no `.reader-a11y-label`, no
  `#reader-a11y`, canvas visible (lines 327–330).

## 5. Verification

- `dune build @proofs` — exit 0 (all Rocq modules type-check with the edits).
- `dune build src/blog_generator.exe tools/encrypt_post.exe tools/decrypt_post.exe
  src/smtp_server.exe src/crane_decrypt.check src/crane_enroll.check` — exit 0.
- Regenerated `_site`; new stylesheet `site.9406af83eb775f17f3fbe78a.css` (12.1KB, down
  from 13.7KB). Generated pages contain `reader-canvas` + `id='real-body'`, and no
  `reader-a11y` / `Comfortable spacing` / `serene` / `sleepless` / `border-image`.
- `scripts/check-single-source.sh` OK; `scripts/check-dom-coherence.sh` PASS (29 DOM
  args); `scripts/check-shim-thinness.sh` OK.
- Playwright e2e not executed locally (needs the fuji fixture server, ephemeral reader
  keys and freshly linked WASM); the edited spec is the CI gate.

## 6. Notes / deferred

- The KaTeX CDN `@import` in `stylesheet_core` remains the one external request; several
  consulted agents flagged it under "static-fast", but removing it needs a self-hosted
  fallback for math in the HTML mirror, which is out of scope here.
- Canvas typeset metrics (`Typeset/Metrics.v`) are trusted Rocq data and were not
  touched; typography changes are confined to the HTML shell + mirror, so the
  Knuth-Plass layout stays byte-verifiable.
