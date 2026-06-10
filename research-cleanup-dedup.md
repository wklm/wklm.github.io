# crane_blog — Consolidated Cleanup / Dedup Plan

**Scope:** what to DELETE or MERGE (removal/dedup-focused). Complementary to
`research-simplification-opportunities.md` (proof-automation / stdlib-reuse). All
claims grep-verified against `src/*.v`, `Typeset/*.v`, `src/dune`, `Typeset/dune`,
`tools/dune`, `Dockerfile`, `src/*.h`, `static/`.

---

## 1. EXECUTIVE SUMMARY

**Removable, conservative total: ~330–390 lines** across 5 deleted module files,
6 confirmed-dead defs, ~140 lines of Logic↔StringLib duplication, and ~21–70
lines of KnuthPlass scan dedup. Plus **7 axioms leave the TCB for free** (5 DomFFI
+ 2 Base64) just by deleting orphan files.

### Highest-leverage actions (in priority order)

1. **Delete 5 confirmed orphan modules** — `src/Base64.v`, `src/HpkeEnvelope.v`,
   `src/DomFFI.v`, `Typeset/Microtype.v`, `Typeset/Hyphenation.v`. Zero inbound
   `Require`, not entry points, not dune targets, no exported symbol referenced
   outside themselves.
2. **Dedup Logic.v ↔ StringLib.v** — Logic re-implements ~14 StringLib string
   primitives byte-for-byte (~140 lines). `Require Import StringLib` and delete.
3. **Delete 6 confirmed-dead definitions** inside live modules.

### Deletions that ALSO fix HEAD build breakage (the broken orphans)

`src/dune` has `(alias proofs)(deps (glob_files *.v))` — **every `src/*.v` is
force-compiled in CI** (`dune build @proofs`). Two broken orphans therefore
**actively break CI**:

| File | Breakage at HEAD | Effect |
|---|---|---|
| `src/Base64.v` | `Base64.v:20` syntax error (`Extract Constant` OCaml-pipeline ref) | breaks `dune build @proofs` |
| `src/HpkeEnvelope.v` | `HpkeEnvelope.v:37` uses `fold_parts` before its `Fixpoint` at `:44` | breaks `dune build @proofs` |

**Deleting these two unblocks CI AND cleans up.** The third broken file,
`Typeset/Microtype.v:74` (failed tactic), is invisible to the build because
`Typeset/dune` has **no** `*.v` glob — so deleting it is pure cleanup, no CI impact,
but still removes latent breakage if anyone ever wires Typeset into `@proofs`.

---

## 2. ORPHAN MODULES TO DELETE

In-degree = number of `.v` files that `Require` it (comment mentions excluded).
"Exported symbols referenced anywhere?" = whole-repo whole-word grep of every
top-level export, excluding comment blocks and the def site itself.

| Module | Confirmed orphan? | Broken at HEAD? | Exported symbols referenced anywhere? | Action | Status |
|---|---|---|---|---|---|
| `src/Base64.v` | YES (in=0, not entry point, not dune target) | YES — `:20` syntax err | NO — `base64_encode/decode` resolve to independent axioms in `CryptoSpec.v:99,102` (live → crypto_helpers.h) + `BrowserCrypto.v:88-91` (live → browser_helpers.h); Base64's copies never imported | **DELETE** (also unblocks CI) | CONFIRMED |
| `src/HpkeEnvelope.v` | YES (in=0) | YES — `:37` `fold_parts` before def | NO — `hpke_envelope`/`parse_hpke_envelope`/`fold_parts`/`build_hpke_envelope`/`parse_wraps_*`/`split_colon_entry` all clean; only external mention is comment `StringLib.v:6` | **DELETE** (also unblocks CI) | CONFIRMED |
| `src/DomFFI.v` | YES (in=0, no `Crane Extraction run`) | no | NO — `el_text`/`show_el`/`hide_el` clean; `set_text_content`/`set_inner_html` are comment-only (`InnerMime.v:11,13` privacy narrative + `browser_helpers.h:379` comment). Live DOM FFI is `brE` in `BrowserEffect.v` (`dom_set_text`/`dom_set_inner_html`) | **DELETE** | CONFIRMED |
| `Typeset/Microtype.v` | YES (in=0) | YES — `:74` failed tactic (invisible to build; no Typeset `*.v` glob) | NO — `expand_paragraph`/`expand_width`/`clamp_expansion`/`protr_left/right`/`effective_line_width`/`box_*_protrusion`/`expand_item`/`protrusion_table`/`max_expansion` all clean; only mention is comment `Boxes.v:4` | **DELETE** (pure cleanup, no CI impact) | CONFIRMED |
| `Typeset/Hyphenation.v` | YES (in=0) | no (un-built; Liang infra) | NO — `hyphenate_word`/`hyphen_width`/`disc_break`/`word_items*`/`pattern_matches`/`hyphen_penalty_val`/`int_of_nat` clean. `nat_of_int_fuel` exists elsewhere but those are **independent local Fixpoints** (`Logic.v:79`, `StringLib.v:104`, `CryptoSpec.v:24`), not imports. Other mentions are comments (`Boxes.v:4,141`, `Metrics.v:185`) | **DELETE** | CONFIRMED |
| `src/Decrypt.v` | YES (in=0, no extraction) | no (compiles, harmless) | NO — self-declared MimeLib-reexport shim; only defines `Definition fuel := mime_fuel`; `Decrypt.fuel` referenced nowhere. Distinct from live `DecryptApp.v`/`DecryptPost.v` | **DELETE** | NEEDS-CHECK — confirm no external/legacy build refs `Decrypt.fuel`; trivially small, low risk |
| `src/Spec.v` | orphan-by-design (proof leaf) | no | n/a — it is the *consumer* (`Require Logic`), and proof files are never imported. Contains 12 obligations incl. `Theorem privacy` (`:14`); force-compiled by `src` `@proofs` glob = CI-checked | **KEEP+FIX** (the pending privacy proof) | CONFIRMED keep |
| `Typeset/Tests.v` | orphan-by-wiring (un-built test suite) | no | n/a — no extraction; `Typeset/dune` has no `@proofs` glob → **not built by `dune build` at all**. Typesetter correctness/optimality fixtures over Boxes/Metrics/KnuthPlass; references live `total_width/stretch/shrink` (`:58`) | **KEEP** — wire into a Typeset `@proofs` alias, do NOT delete | CONFIRMED keep |

**Transitive-orphan check (CONFIRMED):** none exist. Deleting the 5 confirmed
orphans frees nothing else and breaks nothing. `Metrics` (in=2: DecryptApp[live] +
Microtype[orphan]) and `Boxes` (in=7, of which 3 orphan: Microtype/Hyphenation/Tests,
4 live: Extract/GlyphLayout/KnuthPlass/Metrics) each retain ≥1 live requirer.
`Extract.v` is in=0 but is an entry point (`typeset_demo break_demo`) — NOT an orphan.

**Approx. lines removed by the 5 deletions + Decrypt:** ~6 whole files (Base64,
HpkeEnvelope, DomFFI small; Microtype, Hyphenation, Decrypt). Order-of-magnitude
**~150–200 lines** of `.v` source plus dead `Crane Extract`/`Extract Constant`
directives.

---

## 3. DEAD DEFINITIONS (within live modules, ranked)

Method: each name occurring exactly once repo-wide (its def site) = zero external
refs. Proof obligations / compile-time invariants excluded (deleting them weakens
proofs, against project rules).

### CONFIRMED dead — delete now (6 defs)

| Rank | file:line | name | kind | why dead |
|---|---|---|---|---|
| 1 | `Typeset/KnuthPlass.v:285` | `scan_width_tr_eq` | Lemma (Qed) | leftover from `5cab40f` tail-rec refactor; nothing consumes it (`scan_width_nth` is proved directly by induction) |
| 2 | `Typeset/KnuthPlass.v:311` | `scan_stretch_tr_eq` | Lemma (Qed) | same — `scan_stretch_nth` is the consumed one |
| 3 | `Typeset/KnuthPlass.v:332` | `scan_shrink_tr_eq` | Lemma (Qed) | same — `scan_shrink_nth` is the consumed one |
| 4 | `Typeset/KnuthPlass.v:377` | `item_at` | Definition | dead; `legal_after`/`break_penalty`/`break_flagged` inline `nth … forbidden_break` directly. Corroborated by `research-simplification-opportunities.md:48` |
| 5 | `src/Logic.v:246` | `empty_ep` | Definition (`EncryptedPost`) | placeholder never built; parse path uses `mkEncryptedPost`/`parse_eml` |
| 6 | `src/StringLib.v:44` | `fuel_exhausted` | Definition (`string` sentinel) | sentinel `"__FUEL_EXHAUSTED__"` returned by nothing |

**~21 lines** for the three `scan_*_tr_eq` lemmas alone; ~30 lines total for all six.

### NEEDS-CHECK — verified-but-unconsumed correctness lemmas (human judgment)

Each is `Qed`-closed, consumed by no other proof, so strictly "dead" — but each is a
standalone "fast impl = spec" bridge a human may want to keep as a verified artifact.
Confirm intent before removing.

| file:line | name | role |
|---|---|---|
| `Typeset/KnuthPlass.v:563` | `dp_step_table_eq` | "DP-step uses prefix-sum table = spec form" bridge; consumes `pw/py/pz_at_correct`, consumed by nothing |
| `Typeset/KnuthPlass.v:645` | `start_node_cache_ok` | "start node (0,0,0) cache correct"; `try_extend_*` take `node_cache_ok` as hypothesis, never instantiate with start |
| `Typeset/KnuthPlass.v:680/779/801` | `try_extend_feasible`/`_demerits`/`_pos` | T7(b)/Bellman L1/L2 soundness lemmas — named T6/T7 suite artifacts; treat as removable only under aggressive policy |

### NOT dead — do NOT delete (1-occurrence but load-bearing)

- `KnuthPlass.v:916 T6_optimal` — capstone optimality Theorem (relies on
  `Axiom dp_optimal_invariant_holds:908` — see §6).
- `PageModel.v` `:= eq_refl` obligations (`post_page_contains_*`, `inbox_page_*`,
  `enroll_page_contains_*`, `spec_*_valid`, `spec_bare_static_invalid`,
  `*_ids_unique`) and the `Example`s — purpose is compile-time invariant checking.
- `Logic.v` `newline_str` — second occurrence is a `Crane Extract Inlined Constant`
  directive (load-bearing extraction realization), not dead.
- `MimeBuild.v` — **no dead top-level defs** (every def has a real downstream use).

---

## 4. CROSS-MODULE DEDUP

### (a) Logic.v re-implements StringLib.v primitives — CONFIRMED, highest dedup win

Dependency graph: `Logic → PageModel → {StringLib, MimeBuild}`; `MimeBuild → MimeLib → StringLib`.
**StringLib is already in Logic's transitive graph** — the Logic-side copies are pure
redundancy. `Logic.v:9` requires only `PageModel`, never `StringLib`, yet re-defines
~14 helpers (whitespace-normalized pairwise diff):

| Symbol | StringLib | Logic | Verdict |
|---|---|---|---|
| `int_eqb` | `:48` | `Logic.v:48` | byte-identical |
| `is_empty` | `:50` | `Logic.v:50` | byte-identical |
| `nat_of_int_fuel` | `:104` | `Logic.v:79` | byte-identical |
| `nat_of_len` | `:112` | `Logic.v:87` | identical mod fuel-name |
| `find_char` | `:85` | `Logic.v:104` | byte-identical |
| `string_eqb_aux` | `:94` | `Logic.v:113` | byte-identical |
| `string_eqb` | `:115` | `Logic.v:123` | byte-identical |
| `starts_with_aux` | `:61` | `Logic.v:90` | byte-identical |
| `starts_with` | `:72` | `Logic.v:101` | **semantically equal, different shape** (Logic calls `nat_of_len pref`) — NEEDS-CHECK |
| `substring_from` | `:143` | `Logic.v:147` | byte-identical |
| `reverse_string_acc` | `:164` | `Logic.v:150` | byte-identical |
| `reverse_string` | `:174` | `Logic.v:160` | identical mod fuel-name |
| `trim_left_from` | `:146` | `Logic.v:163` | byte-identical |
| `trim_left` | `:161` | `Logic.v:178` | identical mod fuel-name |
| `trim_right` | `:177` | `Logic.v:181` | byte-identical |
| `trim` | `:180` | `Logic.v:184` | byte-identical |

Plus `Logic.fuel := 2000000` (`:38`) ≡ `StringLib.scanner_fuel := 2000000` (`:37`)
and re-declared `ch_*` Notations (`Logic.v:19-32` vs `StringLib.v:17-33`).
**~140 duplicated lines** (`Logic.v:19-32` + `:46-185`).

**Merge sketch:** add `Require Import StringLib.` to Logic; delete `Logic.v:19-32`
(ch_*) + the 14 helper bodies in `:46-185`; keep `Logic.fuel` as alias *or* switch to
`scanner_fuel`. Call sites unchanged (same names/arities). `cat` (`Logic.v:218`) already
resolves to `StringLib.cat` transitively — confirms the link already exists.

**Semantic caveats (NEEDS-CHECK, build-confirm):**
1. `starts_with` shape difference — if any Logic/Spec proof `unfold`s it, must still
   close. (No Logic/Spec proof references `starts_with` → likely safe.)
2. `concat_all` override — `Logic.v:603` redirects `Logic.concat_all` → `concat_all_std`.
   StringLib primitives carry **no** Crane directives (verified `grep "Crane Extract"
   StringLib.v` → empty), so merging the 14 string helpers moves no realization. Only
   `concat_all` (see (d)) needs the override to travel with it.

### (b) MIME splitter / header-parser family — CONFIRMED dead-path after orphan deletion

Three parallel families: buggy original (`MimeLib.v`), fixed port (`MimeBuild.v`),
plus a third copy inside `Logic.v`.

**KEY FINDING:** `MimeLib.split_multipart` (`:162`), `split_multipart_body` (`:180`),
and the 1-arg `MimeLib.split_headers_body` (`:90`) are referenced by **exactly one
module: `HpkeEnvelope.v`** (`:28,34,50`) — a confirmed orphan (§2). `Decrypt.v` only
re-exports MimeLib and is itself orphan. Every live MIME consumer (DecryptApp,
DecryptPost, EncryptPost, InnerMime, MimeIngest, SmtpServer, PostBuild→MimeBuild) uses
the **MimeBuild** family.

**Merge sketch:** after deleting `HpkeEnvelope.v` + `Decrypt.v` (§2), the three buggy
MimeLib splitters become dead → **re-grep, then delete them too**
(`MimeLib.split_multipart`/`split_multipart_body`/1-arg `split_headers_body`).

**Caveat (NEEDS-CHECK / blocked):** `Logic.split_headers_body` (`:302`),
`lookup_header`/`lookup_header_aux` (`:337,354`), `parse_header_line` (`:325`) parse the
public `.eml` header block only, differ in arity/return type from MimeLib/MimeBuild
versions, and are **tied to Spec.v proofs** (`Spec.v:15,87,92,97`). Merging requires
porting the privacy proof to the new signature → leave as-is, flag AIDEV-TODO.

### (c) Parallel record shapes — do NOT merge (low value)

`Logic.EncryptedPost` (`:240`), `MimeIngest.ingested` (`:153`),
`InnerMime.inner_content` (`:68`), `DecryptApp.parsed_envelope` (`:109`) are
semantically distinct (different fields/lifecycles). Merging would couple unrelated
layers and risk `std::any`-prone generics (against crane-extraction-gotchas). **Keep.**

### (d) Smaller cross-dups

- **`concat_all`** — `Logic.concat_all` (`:73`) and `MimeBuild.concat_all` (`:37`) are
  byte-identical fixpoints. Only Logic has the `concat_all_std` override (`Logic.v:603`);
  MimeBuild's extracts the recursive Coq version (potential O(n²) in C++). **NEEDS-CHECK:**
  keep one shared `MimeBuild.concat_all` + add its `Crane Extract Inlined` override there;
  verify the linear realization reaches Logic's native path before relying on it.
- **`html_escape_char` vs `escape_byte`** — `Logic.html_escape_char` (`:53`) escapes 5
  entities incl. apostrophe (attribute context, via `PrimString.sub`); `InnerMime.escape_byte`
  (`:146`) escapes 4, no apostrophe (text-node context, via `PrimString.make`). **Semantic
  difference + 6 Spec.v lemmas (`:25-67`) pin Logic's version → do NOT merge.** Flag the
  apostrophe asymmetry as intentional.
- **base64 decode (3 impls)** — `CryptoSpec.base64_decode` (Axiom, live → crypto_helpers.h),
  `Base64.base64_decode` (Axiom, orphan → DELETE §2), `MimeIngest.b64_decode` (`:53-85`,
  pure-ROCQ table decoder, deliberately crypto-free per `:50-52`). **Keep MimeIngest's**
  (intentional independent re-impl avoiding crypto dep in SMTP path); delete Base64's via §2.

---

## 5. KNUTHPLASS SCAN DEDUP

Three structurally identical scan families differing **only** by a per-item weight:

| Family | weight `w : item -> sp` | location |
|---|---|---|
| width | `IBox→bx_width \| IGlue→gl_width \| IPenalty→0` | `KnuthPlass.v:207-218` |
| stretch | `IGlue→gl_stretch \| _→0` | `:220-229` |
| shrink | `IGlue→gl_shrink \| _→0` | `:231-240` |

Per weight: `scan_*_tr` Fixpoint + `scan_*` wrapper (`:207-240`), `scan_*_tr_eq` +
`scan_*_nth` (`:285-352`), `total_*_cons` (`:255-276`); Boxes.v has `total_*` (`:180-191`)
+ `total_*_app` (`:225-258`). Boxes already factored its *app* proofs through one generic
`fold_left_app_add` (`:218-223`) — the scan layer never got the same treatment.

**Reference map (CONFIRMED, whole-repo grep):**
- `scan_*`/`scan_*_tr`/`scan_*_tr_eq`/`scan_*_nth`: referenced **only inside KnuthPlass.v**
  (consumers: `build_psums:245-246`, `pw/py/pz_at_correct:354-362`). No external `.v`,
  no dune target, no extraction directive. **Free to reshape.**
- `total_width/stretch/shrink`: external consumers exist (`GlyphLayout.v:156-158,175-177`,
  `Tests.v:58`). **Names/signatures MUST be preserved.**

### CRITICAL RISK — Crane "method-on-struct" trap (blocks the cleanest form)

`Boxes.v:171-179` warns: a standalone `item -> sp` function gets attached by Crane as a
**method on the `item` C++ struct**, re-emitted per importing module → "class member cannot
be redeclared". The brief's literal `scan_tr (w : item -> sp) …` sent through the
extraction surface (`build_psums:245-246` is on the live DecryptApp path) is exactly this
hazard, and the project has documented WASM compile breakage from precisely this pattern.

### Recommended: Option A (lowest risk, behavior- and proof-preserving)

1. **Free win, do now (CONFIRMED):** delete the three unused `scan_*_tr_eq` lemmas
   (`:285-298, 311-319, 332-340`) — **~21 lines**, nothing references them (= dead-defs §3 #1-3).
2. **Proof-layer dedup:** keep the three concrete extracted `scan_*` definitions byte-identical
   (so emitted C++/WASM is unchanged), but factor the six `scan_*_tr_eq`+`scan_*_nth` proofs
   (~68 lines) through ONE proof-only generic scanner + one generic lemma, then derive the
   three concrete `scan_*_nth` as ~2-line corollaries. The generic `scan_gen_tr` is **never
   reachable from extraction** (only the three concrete scans feed `build_psums`), so Crane
   never emits it — same technique Boxes.v uses to keep `item_width` proof-only (`:177-179`).
   **~45-50 additional lines saved.**

**Proof-preservation:** `pw/py/pz_at_correct:354-362` need only `scan_*_nth` + `Z.add_0_l`
→ unchanged if the three names survive as corollaries. `dp_step_table_eq:563-577` depends on
`*_at_correct` by name only → untouched. T6 (`best_to_minimal:817`, `T6_optimal:916`) and T7
(`try_extend_feasible:680`) never mention the scan layer → fully insulated.

**Total realistic savings: ~65-70 lines, zero change to extracted C++/WASM, all proofs preserved.**

### AVOID: Option B (parameterize the *extracted* scan by `item -> sp`)

Saves more source (~75-80 lines) but sends `item -> sp` through the extraction boundary —
the `Boxes.v:171-179` trap. **Only with a full native + emscripten build to confirm no
"class member cannot be redeclared" regression.** Not recommended given project history.

---

## 6. TCB REDUCTIONS

Repo: 25 `Axiom` + 79 `Crane Extract`-family directives + 32 real `EM_ASM` (all in the
protected `src/browser_helpers.h`). Axioms split cleanly into eliminable-via-deletion vs
irreducible FFI seams.

### Eliminable for FREE by deleting orphans (§2) — 7 axioms leave the TCB, CONFIRMED

| Source | Axioms removed | Notes |
|---|---|---|
| `src/DomFFI.v` | **5**: `el_text:28`, `set_text_content:29`, `set_inner_html:30`, `show_el:31`, `hide_el:32` (+5 dead `Crane Extract Inlined`) | superseded by `BrowserEffect.brE` (`dom_set_text`/`dom_set_inner_html`, `:144-199`); zero behavior change |
| `src/Base64.v` | **2**: `base64_encode:14`, `base64_decode:17` (+2 dead `Extract Constant` OCaml-pipeline refs, build-breaking) | superseded by live CryptoSpec copies (`:99,102` → crypto_helpers.h) |
| `src/HpkeEnvelope.v` | 0 (no axioms) | listed for completeness — deletion removes CI breakage, no TCB change |
| `Typeset/Microtype.v`, `Typeset/Hyphenation.v` | 0 each | no TCB impact |

**Net: −7 axioms, zero behavior change.** Also strips dead `Crane Extract`/`Extract
Constant` directives.

### Proof-replaceable (NEEDS-CHECK, non-trivial effort)

- `Typeset/KnuthPlass.v:908 dp_optimal_invariant_holds` — the **only** axiom that is a
  deferred proof, not an external assumption. AIDEV-TODO (`:899-907`) says the math core
  (`best_to_minimal`) is proven; only global-induction bookkeeping is admitted. Sole support
  of `T6_optimal:916` (`:925`). Eliminable in principle by induction on `legal_positions p`
  using `best_to_minimal`; flagged NEEDS-CHECK (real proof effort).

### NOT eliminable — irreducible FFI / crypto-assumption TCB (keep)

| Axioms | file:line | Why irreducible |
|---|---|---|
| 9 crypto primitives (`ecdh_p256_*`, `random_bytes`, `aes_256_gcm_*`, `sha256`, `base64_*`) | `CryptoSpec.v:49,54,57,62,66,72,77,99,102` | OpenSSL EVP / WebCrypto FFI seam |
| 4 crypto round-trip specs (`hpke_roundtrip`, `cek_wrap_roundtrip`, `aes_gcm_roundtrip`, `base64_roundtrip`) | `CryptoSpec.v:229,235,240,245` | correctness assumptions about opaque FFI primitives — unprovable by construction |
| 3 JSON-bridge (`json_array_len`, `json_array_field`, `json_object4`) | `BridgeFFI.v:27,30,34` | live (DecryptApp/EnrollApp), JSON-bridge FFI seam |
| `draw_glyph_quads` | `GlyphLayout.v:269` | live GPU-draw FFI seam (DecryptApp) |

All 79 `Crane Extract` are realizations of the above FFI axioms / effect inductives
(`brE`/`toolE`/`netE`/`procE`/`consoleE`) or the orphan dead ones already counted. No
standalone Crane Extract is independently eliminable beyond the orphan deletions. All 32
live `EM_ASM` are in the protected shim header (out of scope).

---

## 7. SUGGESTED ORDER OF APPLICATION

Lowest-risk highest-leverage first. **[BUILD]** marks steps that require a build to confirm.

| # | Step | Risk | Leverage | Build needed? |
|---|---|---|---|---|
| 1 | Delete `src/Base64.v` + `src/HpkeEnvelope.v` | very low | **unblocks CI** + −2 axioms | `dune build @proofs` should now PASS (was failing) **[BUILD]** |
| 2 | Delete `src/DomFFI.v` (−5 axioms), `Typeset/Microtype.v`, `Typeset/Hyphenation.v` | very low | TCB + cleanup | `dune build @proofs` + Typeset targets stay green **[BUILD]** |
| 3 | Delete the 3 `scan_*_tr_eq` lemmas (`KnuthPlass.v:285-298,311-319,332-340`) | very low | ~21 lines | `dune build` KnuthPlass.vo **[BUILD]** |
| 4 | Delete 3 remaining dead defs: `empty_ep` (Logic.v:246), `fuel_exhausted` (StringLib.v:44), `item_at` (KnuthPlass.v:377) | low | ~10 lines | recompile owning modules **[BUILD]** |
| 5 | Delete `src/Decrypt.v` (after re-grep confirms no `Decrypt.fuel` ref) | low | cleanup | re-grep, then `dune build @proofs` **[BUILD]** |
| 6 | Delete now-dead `MimeLib.split_multipart`/`split_multipart_body`/1-arg `split_headers_body` (re-grep after step 5) | low | cleanup | re-grep MUST show 0 refs, then **[BUILD]** |
| 7 | Logic↔StringLib dedup: `Require Import StringLib`, delete `Logic.v:19-32` + 14 helpers in `:46-185` | medium | **~140 lines** | full `dune build @proofs` + native blog_generator + verify `starts_with`/`concat_all` **[BUILD]** |
| 8 | KnuthPlass scan proof-layer dedup (Option A generic lemma) | medium | ~45-50 lines | `dune build` + confirm extracted C++ byte-identical **[BUILD]** |
| 9 | (Optional) Wire `Typeset/Tests.v` into a Typeset `@proofs` alias | low | recovers proof coverage | `dune build @proofs` (Typeset) **[BUILD]** |
| 10 | (Hard, separate) Prove `dp_optimal_invariant_holds` → −1 axiom; or migrate Spec.v to share Logic header parsers | high | TCB / dedup | full proof rebuild **[BUILD]** |

**Notes on ordering:**
- Steps 1-2 are the priority — they remove **all 7 free TCB axioms** and **unblock CI** in
  one pass, with effectively zero semantic risk (pure deletions of zero-inbound files).
- Steps 5-6 are coupled: MimeLib splitters only become dead *after* HpkeEnvelope + Decrypt
  are gone — always re-grep between them.
- Step 7 (the biggest line win) is medium-risk because of the `starts_with` shape diff and
  the `concat_all` extraction override — keep it after the free deletions so a failure is
  isolated and easy to bisect.
- Steps 8 and 10 are the only ones touching proofs/extraction semantics — do last, each on
  its own commit, each with a clean build (and for any Option-B-style change, a full
  emscripten build to guard the method-on-struct trap).
- **KEEP throughout:** `src/Spec.v` (privacy proof, CI leaf), `Typeset/Tests.v` (un-wired
  test suite — wire in, don't delete), all 4 parallel records, `html_escape_char`/`escape_byte`,
  `MimeIngest.b64_decode`, all 16 crypto / 3 JSON / 1 GPU FFI axioms.
