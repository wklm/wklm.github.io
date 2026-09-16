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
- Single colorful element constraint (user directive: "it's to busy, one upper colorful stripe is enogh, make it more tactful"): retain exactly ONE colorful element on the entire site — the 3px Serene 5-color binding palette stripe atop `.site-header`. Everywhere else, strict monochrome + single functional accent.
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
- Palette: contrast-first Serene Sleepless palette with near-black ink `#1b1917` (16.5:1 on `#faf8f5`), metadata
  `#57534b` (7.2:1), Serene blue accent `#52a3eb` (dark `#64b0f3`), Serene coral hover/buttons
  `#fa6e43`, Serene peach `::selection` and colophon ornament; dark scheme uses dark paper `#141312`
  with `#f7f4ef` ink (16.9:1), `#b5aea3` metadata (8.4:1), `#64b0f3` accent, `#fb7c53` coral.
  Full 5-color Serene palette preserved in `:root`.
- Masthead (line 464): upper colorful stripe removed on purpose; clean architectural ink rule `border-top: 3px solid var(--ink)` and subtle bottom border.
- Links/focus (lines 456–458): links use clean ink text with coral hover; `:focus-visible` is a
  quiet Serene focus ring; `::selection` tinted with Serene peach.
- Reading view: "Comfortable spacing" toggle rules deleted; `#real-body` remains the
  clipped accessibility mirror and the canvas is the single default view.
- Colophon: signature `❧  serene  ·  sleepless 2018` terminal colophon mark preserved in Serene peach.

`src/PageModel.v`:
- Removed the `reader-a11y` checkbox/label and its ID constant (line 95); post page now
  renders header → canvas → `sr-only` `#real-body` → images → colophon.

`tests/e2e/roundtrip.spec.ts`:
- Replaced the toggle test with unified-view assertions: no `.reader-a11y-label`, no
  `#reader-a11y`, canvas visible (lines 327–330).

## 5. Verification

- `dune build @proofs` — machine-checked Rocq proofs verified in Docker `crane-blog:builder`.
- `dune build src/blog_generator.exe tools/encrypt_post.exe tools/decrypt_post.exe
  src/smtp_server.exe src/crane_decrypt.check src/crane_enroll.check` — verified.
- Regenerated `_site` via `stage-site.sh`. Generated pages contain `reader-canvas`,
  `id='real-body'`, `post-colophon` with `serene · sleepless 2018`, and upper Serene binding stripe.
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
