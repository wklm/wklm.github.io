# Crane_blog ROCQ Proof/Def Simplification Opportunities

> **STATUS:** historical audit report — findings partially superseded by
> subsequent commits (see `git log`); kept for provenance.

> Harvested from the `wf_d385f5cf-4f6` "20 logicians hunting simplifications" workflow transcripts.
> Find phase: 20 expert-logician agents (14 file-coverage + 6 thematic) — all 20 emitted structured candidates.
> Verify phase: 118 adversarial reviewers were dispatched but **91 hit a session limit** and produced no verdict;
> only **27** returned a usable adopt/adopt-with-care/reject verdict. The Synthesize/lead agent failed (emitted nothing).
> This report is the reconstructed synthesis. Candidates with no recorded verdict are marked **unverified — needs check**.

## 1. Executive summary

- **Candidates recovered:** 147 raw -> **122 distinct** after de-duplicating cross-agent overlaps.
- **Estimated total lines removable:** ~**2178** (sum of per-candidate `linesRemovedEstimate`, distinct set). The bulk is concentrated in a handful of whole-file deletions.
- **Verified verdicts:** 16 adopt/adopt-with-care, 11 reject, 95 unverified.
- **Single highest-leverage change:** delete the two orphaned Typeset modules **Hyphenation.v + Microtype.v** (~485 lines; imported by nothing in the live build) — by far the largest single win, *unverified, needs an import-graph check before deletion*.
- **Runner-up wins:** delete the dead/duplicate **HpkeEnvelope.v** (~160 lines, a third parallel envelope impl); collapse **Logic.v**'s ~110-line re-implementation of all 30 StringLib string helpers onto `StringLib.v` (the trimmed 70-line version of this is the one verified ADOPT-WITH-CARE).

### recursion-to-fold items that ALSO harden against the stack-overflow class

There are **20** recursion-to-fold candidates; **14** explicitly claim to harden against the known deep-non-tail-recursion WASM stack-overflow class. Genuine fold-hardening wins (all *unverified*):

- `MimeIngest.v:lines 31-42 (flatten_ws_aux / flatten_ws)` — flatten_ws_aux: a per-byte char map open-coded as a fuel Fixpoint (8L)
- `DecryptApp.v:Fixpoint max_qy, lines 248-252` — max_qy is fold_left over a Z accumulator (already the Boxes.v idiom) (4L)
- `DecryptApp.v:Fixpoint total_height, lines 273-278` — total_height is fold_left over a Z accumulator (4L)
- `ProcFFI.v:join_nul ProcFFI.v:53-58; join_comma MimeBuil` — join_nul / join_comma / join_blank / join_wraps are fold-based separator-joins (12L)
- `ProcFFI.v:join_nul lines 53-58` — Replace ProcFFI.join_nul explicit Fixpoint with a fold (tail-safe, hardens against the WASM sta (3L)
- `MimeBuild.v:MimeBuild.v:37-41 (Fixpoint concat_all) and` — Define concat_all once in StringLib (as fold_right cat "") — drop MimeBuild & Logic copies (10L)
- `Hyphenation.v:lines 196-216 (max_over_starts, max_over_` — Replace bespoke max_over_starts / max_over_patterns Fixpoints with fold_right Nat.max over map (6L)
- `EncryptPost.v:read_images, lines 82-89` — Make read_images tail-recursive via List combinators (hardens against the WASM stack-overflow c (0L)
- `EnrollApp.v:collect_ids_aux lines 47-55, used by enroll` — Make collect_ids_aux tail-recursive (cons-after-recurse → accumulator/fold) (1L)
- `SmtpServer.v:lines 79-87 (Fixpoint clean_allow + Defini` — Replace clean_allow Fixpoint with filter + map (stdlib combinators) (6L)
- `DecryptPost.v:entries_to_triples (78-87), try_unwrap (1` — Replace the hand-rolled filter-map Fixpoints with fold combinators (entries_to_triples, try_unw (10L)

> **Caution from the verifiers:** the two fold-conversions that *were* reviewed were **REJECTED** — `scan_*_tr` (KnuthPlass.v) and `layout_all_tr` (DecryptApp.v) are **already accumulator/tail-recursive**, so rewriting them as `fold_left`/`List.map` buys no hardening and risks regressing extracted behavior. So target the fold-hardening effort at the *still-non-tail* Fixpoints above (read_images, collect_ids_aux, join_nul, max_over_*, clean_allow, max_qy, total_height), not at code already squashed by the earlier stack-overflow commits.

## 2. Top simplifications (ranked)

Ranked by (verified-adopt first) then estimated lines removed. `est` = est. lines removed.

| # | Title | file:loc | kind | before -> after | est | leverage | verdict + caveat |
|---|-------|----------|------|-----------------|-----|----------|------------------|
| 1 | Collapse 30 per-ID containment eq_refl Definitions into 3 forallb-base | `PageModel.v:lines 156-217 (post_page_contains_* / inbox` | dedup | 30 separate `Definition <page>_contains_<id> : contains -> Replace the entire block with three (or four) list-leve | 55 | high | **ADOPT** — Caveats: no local toolchain, so run `dune build @proofs` to confirm Qed; the self-containment `forallb` facts are tautological (as were the originals), so the only load-bearing ass |
| 2 | Delete the three dead scan_*_tr_eq lemmas | `KnuthPlass.v:lines 285-291 (scan_width_tr_eq), 304-310 ` | dead-code | Three lemmas, e.g. `Lemma scan_width_tr_eq : forall p a -> Remove all three lemmas entirely. | 21 | high | **ADOPT** — Summary: The three `scan_*_tr_eq` lemmas in `/home/wojtek/dev/crane_blog/Typeset/KnuthPlass.v` (lines 285-291, 304-310, 323-329) are genuinely dead. Repo-wide grep confirms zero re |
| 3 | Merge near-identical find_ws / find_non_ws into one scanner parameteri | `MimeBuild.v:find_ws (lines 99-112) and find_non_ws (lin` | dedup | Two separate Fixpoints, each ~14 lines, with IDENTICAL  -> Factor the shared 4-way whitespace test into `Definitio | 12 | medium | **ADOPT** — **One real caveat the candidate must get right:** `Bool.eqb`. The candidate writes `Bool.eqb`. With `From Stdlib Require Import Lists.List`, the bare `eqb` may be ambiguous (List d |
| 4 | Simplify is_dashes-based frontmatter open detection (drop_open_dashes  | `MimeBuild.v:drop_open_dashes (lines 176-180) and parse_` | definition-simplify | parse_frontmatter_kv matches `lines` to get `first`, ch -> Inline: `match split_lines raw with [] => [] | first :: | 5 | low | **ADOPT** — Verdict: VALID — adopt. The inline is definitionally equivalent across all three input cases, `drop_open_dashes` has no callers outside its single inlined use, `is_dashes` is pure  |
| 5 | Remove trivial wrapper meta_lookup; call header_lookup directly | `MimeBuild.v:meta_lookup (lines 193-194)` | dead-code | `Definition meta_lookup (key) (kv) : string := header_l -> Delete meta_lookup and replace its 3 call sites (Encryp | 4 | low | **ADOPT** — This is a genuine reduction: one definition plus its two-line explanatory comment removed from the TCB surface, no behavioral or proof impact. The only requirement is updating the  |
| 6 | Replace bespoke contains_id Fixpoint with Stdlib existsb (string_eqb i | `PageModel.v:lines 148-154 (Fixpoint contains_id)` | stdlib-reuse | Fixpoint contains_id (ids:list string)(id:string):bool  -> Definition contains_id (ids:list string)(id:string):boo | 4 | high | **ADOPT** — Caveat: no Coq/Rocq compiler in this environment, so the verdict is reasoning-based — run `dune build @proofs` to confirm Qed before merging. Also note the candidate's "partial app |
| 7 | Fold the three spec_* validity Definitions into one forallb over the s | `PageModel.v:lines 226-240 (spec_decrypt_post/inbox/enro` | dedup | Three named string constants spec_decrypt_post/spec_dec -> Keep the four string constants (they document the actua | 4 | low | **ADOPT** — This is a small, correct, mechanically-sound dedup. I'm confident enough to adopt it, with the standard caveat that it should be confirmed by an actual `dune build @proofs` in the  |
| 8 | Delete unused item_at definition | `KnuthPlass.v:lines 365-367 (Definition item_at)` | dead-code | `Definition item_at (p : paragraph) (k : nat) : item := -> Remove the definition (and its 1-line comment). | 3 | medium | **ADOPT** — Verdict returned: VALID, recommend adopt. `item_at` is confirmed dead code (single occurrence in the entire repo, at its own definition), not extracted, and not a dependency of any |
| 9 | Inline trivial ids_unique wrapper into id_list_unique | `PageModel.v:lines 402-403 (Definition ids_unique) and i` | definition-simplify | Definition ids_unique (ids:list string):bool := id_list -> Delete ids_unique and call id_list_unique directly: `De | 3 | medium | **ADOPT** — 4. **`eq_refl` still typechecks after inlining**: The original goal is `ids_unique post_page_ids = true`. `eq_refl` works because Coq unfolds `ids_unique` (transparent `Definition` |
| 10 | Delete the dead `layout_all` wrapper | `DecryptApp.v:lines 270-271 (Definition layout_all)` | dead-code | Definition layout_all (ps : list string) : list (list q -> Remove the definition entirely. Its sole would-be calle | 2 | high | **ADOPT** — `layout_all` at src/DecryptApp.v:270-271 is strictly dead code. A repo-wide grep for the bare identifier finds it only at its own definition site; its sole would-be caller `render_ |
| 11 | Delete ~17 duplicated string primitives — reuse StringLib.v (already t | `Logic.v:lines 48-51, 90-126, 147-185 (int_eqb, is_empty` | dedup | Logic.v locally re-defines int_eqb (L48), is_empty (L50 -> Add `Require Import StringLib.` to Logic.v's header and | 70 | high | **ADOPT-CARE** — The one caveat worth flagging: the candidate's "byte-for-byte identical" claim is factually wrong for `starts_with` (Logic.v uses `nat_of_len pref`; StringLib uses a different inli |
| 12 | Unify the triplicated prefix-scan infrastructure into one weight-param | `KnuthPlass.v:lines 207-351 (scan_width_tr/scan_stretch_` | dedup | Three structurally identical tail-recursive Fixpoints d -> Introduce one weight function selector `Definition item | 60 | high | **ADOPT-CARE** — - Extraction safety, the load-bearing risk, is well-supported: `layout_paragraph (adv : glyph_id -> sp)` at `Typeset/GlyphLayout.v:191` already threads a function-valued parameter  |
| 13 | Lift the 7 envelope/crypto helpers shared verbatim with DecryptPost.v  | `DecryptApp.v:entry_to_triple (62-67), entries_to_triple` | dedup | These 7 definitions are byte-for-byte identical to src/ -> Move the shared block into an existing reused module (e | 25 | high | **ADOPT-CARE** — Verdict returned: VALID, adopt-with-care. The duplication is real (all four blocks diff-clean), the dedup preserves extraction behavior per target and breaks no proofs, but it must |
| 14 | Extract the shared part-dispatch preamble of inner_md / inner_attachme | `MimeBuild.v:inner_md (lines 485-495) and inner_attachme` | dedup | Both Fixpoints repeat the identical 4-line preamble per -> Hoist the preamble into `Definition part_ct_body (part: | 6 | medium | **ADOPT-CARE** — The main caveats: it must stay a `Definition` (not a `fix`), the two recursions must remain separate, and since I verified against the currently-built artifact rather than a rebuil |
| 15 | Reuse Logic.concat_all's linear-time Crane override instead of a secon | `MimeBuild.v:concat_all (lines 36-41); Crane override on` | tcb-reduction | MimeBuild defines its own `Fixpoint concat_all` (lines  -> Either (a) move concat_all into a shared low-level modu | 5 | high | **ADOPT-CARE** — I've completed the adversarial review. Verdict: the underlying diagnosis is correct (verified against the actual generated C++), but the candidate as a *simplification* is invalid  |
| 16 | Reuse is_forced_break/break_penalty/break_flagged in dp_step instead o | `KnuthPlass.v:lines 526-529 (dp_step) and proof dp_step_` | stdlib-reuse | dp_step recomputes the break attributes inline: `let it -> Replace the four lets with `best_to sp_ p actives j (pw | 4 | medium | **ADOPT-CARE** — The three helpers are term-identical to dp_step's inline lets, best_to's signature lines up exactly, the only unfolder (dp_step_table_eq) gets strictly simpler (the `unfold is_forc |
| 17 | Two whole Typeset modules (Hyphenation.v, Microtype.v) are orphaned —  | `Microtype.v:Typeset/Hyphenation.v (297 lines, all 50+ d` | dead-code | Both modules `Require Import Typeset.Boxes` (Microtype  -> Delete both files and drop them from the Typeset theory | 485 | high | **unverified** — needs check |
| 18 | Delete the entire HpkeEnvelope.v file — dead, duplicated, parallel imp | `HpkeEnvelope.v:whole file, lines 1-163` | dead-code | A 163-line module defining parse_hpke_envelope (+ fold_ -> Remove src/HpkeEnvelope.v entirely (and drop the dangli | 163 | high | **unverified** — needs check |
| 19 | Delete dead, duplicate HpkeEnvelope.v — a third parallel envelope code | `HpkeEnvelope.v:entire file (162 lines): parse_hpke_enve` | dead-code | A self-described port of encrypt_post.ml/decrypt.ml env -> Remove src/HpkeEnvelope.v outright (and its _build/ cop | 162 | high | **unverified** — needs check |
| 20 | Logic.v re-implements all 30 StringLib string helpers — import StringL | `Logic.v:lines 19-185 (ch_* notations, int_eqb, is_empty` | dedup | Logic.v defines a complete inline copy of 30 helpers (1 -> Add `Require Import StringLib.` to Logic.v and delete t | 110 | medium | **unverified** — needs check |
| 21 | Collapse Logic.v's duplicated string-primitive block onto StringLib.v | `Logic.v:Logic.v:48-185 (int_eqb, is_empty, nat_of_int_f` | stdlib-reuse | Logic.v re-declares ~15 string primitives that already  -> `Require Import StringLib` in Logic.v and delete the du | 90 | high | **unverified** — needs check |
| 22 | Shared envelope-parse helpers duplicated verbatim in DecryptPost.v and | `DecryptApp.v:DecryptApp.v:62-105,167-174 vs DecryptPost` | dedup | Seven helpers are byte-identical across the two files ( -> Add the five MIME-side helpers (entry_to_triple, entrie | 50 | high | **unverified** — needs check |
| 23 | Delete 6 unused html_escape_char lemmas | `Spec.v:21-67` | dead-code | 6 lemmas -> remove; unused | 47 | high | **unverified** — needs check |
| 24 | Delete the entire DomFFI.v module — 5 dead axioms + 5 dead Crane Extra | `DomFFI.v:whole file (lines 1-46); axioms el_text/set_te` | tcb-reduction | 5 `Axiom` declarations (el_text, set_text_content, set_ -> Remove src/DomFFI.v from the repository (and any refere | 46 | high | **unverified** — needs check |
| 25 | Delete dead DomFFI.v entirely (5 Axioms + 5 Crane Extract directives,  | `DomFFI.v:whole file; axioms lines 28-32, Crane Extract ` | tcb-reduction | 5 Axioms (el_text, set_text_content, set_inner_html, sh -> Remove the file from the source tree. The DOM seam is f | 46 | high | **unverified** — needs check |
| 26 | Dead HPKE single-recipient functions hpke_encrypt / hpke_decrypt in Cr | `CryptoSpec.v:src/CryptoSpec.v:119-146 (Definition hpke_` | dead-code | `hpke_encrypt` and `hpke_decrypt` are defined (~28 line -> Delete both Definitions. wrap_cek/unwrap_cek (the actua | 28 | high | **unverified** — needs check |
| 27 | Delete orphan file Base64.v entirely (2 Axioms + 2 stale OCaml Extract | `Base64.v:whole file, lines 1-22` | dead-code | 22-line file declaring `Axiom base64_encode : string -> -> Remove the file (and drop it from any glob it is swept  | 22 | high | **unverified** — needs check |
| 28 | Drop the redundant per-op `Crane Extract Inlined Constant` directives  | `IoEffects.v:IoEffects.v lines 63-72 (5 inlined constant` | dedup | Each effect module registers the constructors twice: on -> Verify whether the smart-constructor inlined-constant d | 22 | medium | **unverified** — needs check |
| 29 | Delete dead Base64.v (2 Axioms + 2 Crane Extract; never imported, dupl | `Base64.v:whole file; Axioms lines 14,17; Crane Extract ` | dead-code | Axiom base64_encode / base64_decode plus `Extract Const -> Remove the file. grep shows zero `Require/Import Base64 | 22 | high | **unverified** — needs check |
| 30 | Reduce json_object4 Axiom + EM_ASM to a pure-ROCQ string assembler (wi | `BridgeFFI.v:Axiom lines 34-36; Crane Extract lines 46-4` | tcb-reduction | `Axiom json_object4 : 8 strings -> string` realized by  -> Implement json_object4 in pure ROCQ as conditional stri | 22 | medium | **unverified** — needs check |
| 31 | Delete the dead Decrypt.v compatibility shim entirely | `Decrypt.v:whole file (lines 1-19); symbol Decrypt.fuel` | dead-code | A 19-line 'compatibility shim' that re-imports MimeLib  -> Remove src/Decrypt.v from the tree (and drop the commen | 19 | high | **unverified** — needs check |
| 32 | Replace bespoke entries_to_triples with List.filter_map (and dedup acr | `DecryptPost.v:DecryptPost.v:78-87 (Fixpoint entries_to_` | stdlib-reuse | Fixpoint entries_to_triples (entries : list string) : l -> Drop both Fixpoints. Replace with the Stdlib combinator | 18 | high | **unverified** — needs check |

*(Full 122-candidate dataset preserved in the harvest JSON; this table shows the top non-rejected.)*

## 3. By category

| kind | count | est. lines | notes |
|------|-------|-----------|-------|
| dedup | 34 | ~611 | verbatim duplication across modules (StringLib, envelope helpers, prefix scans) |
| dead-code | 30 | ~1090 | unused defs/lemmas/whole files; lowest-risk class |
| recursion-to-fold | 20 | ~111 | Fixpoint -> fold/stdlib; SOME also harden stack-overflow (verify carefully) |
| definition-simplify | 12 | ~39 | inline trivial wrappers / collapse equivalent branches |
| stdlib-reuse | 11 | ~154 | bespoke Fixpoint -> Stdlib existsb/find/forallb |
| tcb-reduction | 6 | ~141 | removes Axioms / Crane Extract directives — shrinks trusted base |
| tactic-automation | 5 | ~17 | shorten proof scripts |
| proof-shortening | 4 | ~15 | shorten proof scripts |

## 4. TCB-shrinking wins (avoidable Axiom / Crane Extract)

Each removes trusted, unverified surface (Axioms or `Crane Extract`/`EM_ASM` FFI directives).

| Title | file | est | verdict |
|-------|------|-----|---------|
| Delete the entire DomFFI.v module — 5 dead axioms + 5 dead Crane Extract di | `DomFFI.v` | 46 | unverified |
| Delete dead DomFFI.v entirely (5 Axioms + 5 Crane Extract directives, all s | `DomFFI.v` | 46 | unverified |
| Dead HPKE single-recipient functions hpke_encrypt / hpke_decrypt in CryptoS | `CryptoSpec.v` | 28 | unverified |
| Delete orphan file Base64.v entirely (2 Axioms + 2 stale OCaml Extract dire | `Base64.v` | 22 | unverified |
| Drop the redundant per-op `Crane Extract Inlined Constant` directives that  | `IoEffects.v` | 22 | unverified |
| Delete dead Base64.v (2 Axioms + 2 Crane Extract; never imported, duplicate | `Base64.v` | 22 | unverified |
| Reduce json_object4 Axiom + EM_ASM to a pure-ROCQ string assembler (with a  | `BridgeFFI.v` | 22 | unverified |
| Drop 4 unused cryptographic round-trip Axioms from CryptoSpec.v | `CryptoSpec.v` | 18 | unverified |
| Factor triplicated splitter into aead_open | `CryptoSpec.v` | 14 | unverified |
| Delete dead definition set_item_width | `GlyphLayout.v` | 8 | unverified |
| Reuse Logic.concat_all's linear-time Crane override instead of a second qua | `MimeBuild.v` | 5 | ADOPT-CARE |
| Replace base64_encode Axiom with a pure-ROCQ Fixpoint (eliminates 1 Axiom + | `CryptoSpec.v` | 4 | unverified |
| Remove dead legacy alias Definition nat_of_int in CryptoSpec.v | `CryptoSpec.v` | 2 | unverified |

## 5. Suggested order of application (lowest-risk, highest-leverage first)

**Tier 0 — verified ADOPT, near-zero risk (do first):**
1. `PageModel.v:lines 156-217 (post_page_contains_* / inbox` — Collapse 30 per-ID containment eq_refl Definitions into 3 forallb-based list lemmas (55L)
1. `KnuthPlass.v:lines 285-291 (scan_width_tr_eq), 304-310 ` — Delete the three dead scan_*_tr_eq lemmas (21L)
1. `MimeBuild.v:find_ws (lines 99-112) and find_non_ws (lin` — Merge near-identical find_ws / find_non_ws into one scanner parameterized on the predicate (12L)
1. `MimeBuild.v:drop_open_dashes (lines 176-180) and parse_` — Simplify is_dashes-based frontmatter open detection (drop_open_dashes + first-line recheck (5L)
1. `MimeBuild.v:meta_lookup (lines 193-194)` — Remove trivial wrapper meta_lookup; call header_lookup directly (4L)
1. `PageModel.v:lines 148-154 (Fixpoint contains_id)` — Replace bespoke contains_id Fixpoint with Stdlib existsb (string_eqb id) (4L)
1. `PageModel.v:lines 226-240 (spec_decrypt_post/inbox/enro` — Fold the three spec_* validity Definitions into one forallb over the specifier list (4L)
1. `KnuthPlass.v:lines 365-367 (Definition item_at)` — Delete unused item_at definition (3L)
1. `PageModel.v:lines 402-403 (Definition ids_unique) and i` — Inline trivial ids_unique wrapper into id_list_unique (3L)
1. `DecryptApp.v:lines 270-271 (Definition layout_all)` — Delete the dead `layout_all` wrapper (2L)

**Tier 1 — verified ADOPT-WITH-CARE (apply, then run `dune build @proofs`; heed caveat):**
1. `Logic.v:lines 48-51, 90-126, 147-185 (int_eqb, is_empty` — Delete ~17 duplicated string primitives — reuse StringLib.v (already transitively imp (70L). Caveat: The one caveat worth flagging: the candidate's "byte-for-byte identical" claim is factually wrong for `starts_with` (Logic.v uses `nat_of_len pref`; StringLib uses a different inli
1. `KnuthPlass.v:lines 207-351 (scan_width_tr/scan_stretch_` — Unify the triplicated prefix-scan infrastructure into one weight-parameterized scan (60L). Caveat: - Extraction safety, the load-bearing risk, is well-supported: `layout_paragraph (adv : glyph_id -> sp)` at `Typeset/GlyphLayout.v:191` already threads a function-valued parameter 
1. `DecryptApp.v:entry_to_triple (62-67), entries_to_triple` — Lift the 7 envelope/crypto helpers shared verbatim with DecryptPost.v into a module (25L). Caveat: Verdict returned: VALID, adopt-with-care. The duplication is real (all four blocks diff-clean), the dedup preserves extraction behavior per target and breaks no proofs, but it must
1. `MimeBuild.v:inner_md (lines 485-495) and inner_attachme` — Extract the shared part-dispatch preamble of inner_md / inner_attachments (6L). Caveat: The main caveats: it must stay a `Definition` (not a `fix`), the two recursions must remain separate, and since I verified against the currently-built artifact rather than a rebuil
1. `MimeBuild.v:concat_all (lines 36-41); Crane override on` — Reuse Logic.concat_all's linear-time Crane override instead of a second quadratic con (5L). Caveat: I've completed the adversarial review. Verdict: the underlying diagnosis is correct (verified against the actual generated C++), but the candidate as a *simplification* is invalid 
1. `KnuthPlass.v:lines 526-529 (dp_step) and proof dp_step_` — Reuse is_forced_break/break_penalty/break_flagged in dp_step instead of re-inlining t (4L). Caveat: The three helpers are term-identical to dp_step's inline lets, best_to's signature lines up exactly, the only unfolder (dp_step_table_eq) gets strictly simpler (the `unfold is_forc

**Tier 2 — unverified dead-code / whole-file deletions (high leverage, low conceptual risk; verify with a repo-wide import/grep + `dune build` before deleting):**
1. `Microtype.v:Typeset/Hyphenation.v (297 lines, all 50+ d` — Two whole Typeset modules (Hyphenation.v, Microtype.v) are orphaned — imported b (485L) — unverified, needs check
1. `HpkeEnvelope.v:whole file, lines 1-163` — Delete the entire HpkeEnvelope.v file — dead, duplicated, parallel implementatio (163L) — unverified, needs check
1. `HpkeEnvelope.v:entire file (162 lines): parse_hpke_enve` — Delete dead, duplicate HpkeEnvelope.v — a third parallel envelope codec nothing  (162L) — unverified, needs check
1. `Spec.v:21-67` — Delete 6 unused html_escape_char lemmas (47L) — unverified, needs check
1. `DomFFI.v:whole file (lines 1-46); axioms el_text/set_te` — Delete the entire DomFFI.v module — 5 dead axioms + 5 dead Crane Extract directi (46L) — unverified, needs check
1. `DomFFI.v:whole file; axioms lines 28-32, Crane Extract ` — Delete dead DomFFI.v entirely (5 Axioms + 5 Crane Extract directives, all supers (46L) — unverified, needs check
1. `CryptoSpec.v:src/CryptoSpec.v:119-146 (Definition hpke_` — Dead HPKE single-recipient functions hpke_encrypt / hpke_decrypt in CryptoSpec.v (28L) — unverified, needs check
1. `Base64.v:whole file, lines 1-22` — Delete orphan file Base64.v entirely (2 Axioms + 2 stale OCaml Extract directive (22L) — unverified, needs check
1. `Base64.v:whole file; Axioms lines 14,17; Crane Extract ` — Delete dead Base64.v (2 Axioms + 2 Crane Extract; never imported, duplicates Cry (22L) — unverified, needs check
1. `BridgeFFI.v:Axiom lines 34-36; Crane Extract lines 46-4` — Reduce json_object4 Axiom + EM_ASM to a pure-ROCQ string assembler (with a verif (22L) — unverified, needs check
1. `Decrypt.v:whole file (lines 1-19); symbol Decrypt.fuel` — Delete the dead Decrypt.v compatibility shim entirely (19L) — unverified, needs check
1. `CryptoSpec.v:lines 229-246: hpke_roundtrip, cek_wrap_ro` — Drop 4 unused cryptographic round-trip Axioms from CryptoSpec.v (18L) — unverified, needs check
1. `CryptoSpec.v:21-24,208-213,215-224` — Delete dead nat_of_int/key_id/format_wrapped_entry (18L) — unverified, needs check

**Tier 3 — unverified dedup/stdlib-reuse (medium effort; confirm Stdlib signatures + extraction behavior):** the remaining `dedup`/`stdlib-reuse`/`definition-simplify` candidates in the dataset.

**Tier 4 — fold-hardening of still-non-tail Fixpoints (see section 1 caveat):** apply only to Fixpoints that are NOT already accumulator-recursive; each needs an extraction/Qed check.

**Do NOT apply (verifier-REJECTED):**
- `DecryptApp.v:lines 83-105 (find_wraps, find_ct_b64)` — Merge find_wraps and find_ct_b64 into one parametric part-scanner. Why: Verdict returned: **reject**. The merge typechecks and preserves behavior, but it is not genuinely simpler (net-zero lines, adds a higher-order concept) and it trades the current k
- `DecryptApp.v:lines 264-271 (layout_all_tr + layout_all)` — Replace layout_all_tr accumulator-recursion with List.map (drops dead wrapp. Why: 3. **The "drops dead wrapper too" sub-claim is TRUE:** `layout_all` (lines 270-271) has zero call sites — `render_canvas` calls `layout_all_tr ps nil` directly (line 303). Removing
- `DecryptApp.v:lines 69-78 (entries_to_triples)` — Make entries_to_triples a List.fold_right (filter_map shape). Why: The fold_right rewrite is semantically equivalent and order-preserving (fold_right is the correct choice over fold_left here), and no proofs depend on `entries_to_triples`. But it 
- `DecryptApp.v:lines 273-278 (total_height) and 304 (rend` — Fold the extra para_gap into total_height instead of adding it at the call . Why: Verdict returned: reject. The change would typecheck and preserve identical extracted behavior (no proofs touch these definitions, and the arithmetic is provably the same Z value),
- `KnuthPlass.v:lines 207-240 (scan_width_tr/scan_stretch_` — Rewrite scan_*_tr Fixpoints as fold_left (recursion-to-fold, hardens agains. Why: Verdict: REJECT. The candidate fails both required prongs and falls under default-to-reject (no toolchain to verify the claimed-risk extraction concern).
- `Logic.v:lines 19-32 (ch_tab..ch_9) and line 38 (Notatio` — Remove duplicated ch_* / fuel Notations — already provided by StringLib. Why: The ch_* notation values genuinely match (all 14 used in Logic.v are present in StringLib.v with identical int63 literals, StringLib being a superset), and the fuel/scanner_fuel ty
- `Logic.v:lines 73-77 (Fixpoint concat_all) + line 603 (C` — Re-home concat_all to MimeBuild instead of redefining it in Logic.v. Why: The dedup target is real (the two `concat_all` Fixpoints are byte-identical), but the candidate's behavior-preservation claim is false. `MimeBuild.concat_all` is a shared symbol us
- `Logic.v:line 144-145 (Definition string_ge) with Fixpoi` — Tighten string_ge fuel from the 2,000,000 constant to nat_of_len a. Why: The candidate's own claimed-risk reasoning ("aux always reaches the la-pos guard before exhausting fuel") is the bug: with `remaining = la`, fuel is exhausted *at* the guard step, 
- `MimeBuild.v:protected_block (lines 258-262) and image_p` — Collapse protected_block / image_parts into concat_all (map ...), hardening. Why: - However, the candidate's stack-overflow-hardening rationale is false for `src/MimeBuild.v`: its `concat_all` has no linear C++ override (only `src/Logic.v:603` overrides a differ
- `PageModel.v:lines 394-400 (Fixpoint id_list_unique)` — Reuse NoDup (via existsb) or fold for id_list_unique uniqueness scan. Why: 4. **No genuine simplification exists.** The current `id_list_unique` is already minimal (5 lines, structurally recursive, terminates trivially, reduces cleanly under `eq_refl`). T
- `PageModel.v:lines 75-89 (str_contains_aux Fixpoint + st` — Drop unused page-fuel-bounded str_contains substring scanner (proof-only, r. Why: - It is a second substring engine alongside StringLib — true, but StringLib has NO substring scanner (only `starts_with`, a prefix check). So `str_contains` is NOT a duplicate of a
