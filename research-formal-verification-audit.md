# Formal-Verification Audit — crane_blog

**Scope:** Line-by-line, first-principles audit of every ROCQ (`.v`) source file and the
C++ TCB shims of crane_blog (a ROCQ/Rocq 9.0 formally-verified static blog generator +
client-side encrypted-post reader: posts encrypted at rest, WebAuthn enroll, in-browser
WASM decrypt).

**Provenance / caveat on completeness:** This report is synthesized from the **completed
PerFile phase** of the audit — 36 independent expert reviews (35 `.v` files + `blog_helpers.h`),
each producing a structured finding (theorems, axioms, extraction/TCB boundaries, partiality
risks, soundness rating). The original workflow's **CrossCut (6 teams), Adversarial (4 red-teamers),
and 5 of 6 dedicated TCB-shim audits, plus the final Synthesis agent, all hit a session/usage
limit and produced no output.** Consequently the "Adversarial" findings below are reconstructed
from concrete representable-invalid-state risks surfaced by the PerFile experts rather than from
dedicated red-team runs, and 5 of the 6 C++ shims (`crypto_helpers.h`, `browser_helpers.h`,
`browser_helpers_stub.h`, `net_helpers.h`, `proc_helpers.h`) were **not independently audited** —
they are characterized here only via the `.v` files that bind them.

---

## 1. Executive Summary

**Does formal verification make invalid states unrepresentable in this project? No — not in the
sense the project's framing implies, and in two flagship cases the verification claim is outright
broken.**

The honest picture, from 36 line-by-line reviews:

- **21 of 36 files contain ZERO theorems.** They are ordinary total functional programs written
  in ROCQ. The only machine-checked properties they carry are the ambient ones every well-typed
  total Gallina term enjoys: **well-typedness and termination (mostly via `nat` fuel)**. They do
  *not* prove escaping, sorting, metadata suppression, parser correctness, or any security
  property — yet several carry header comments asserting exactly those behaviors. "Verified" here
  almost always means "type-checks," not "proven correct."

- **Two flagship security claims are genuinely broken:**
  1. **`Spec.v` `privacy` (header-non-leak) — does NOT compile.** `render_eml_page` was changed in
     `Logic.v` to take two arguments `(ep)(version)` (commit 7eac862, 2026-05-31); `Spec.v` still
     applies it to one argument everywhere (lines 17–18, 73–75) and was last edited a day later
     (bd6129f, 2026-06-01) without being updated. It also has a proof-script bug (six
     `html_escape_char` lemmas `rewrite H` with no preceding `intros`). There is **no `Spec.vo`**,
     and **no module `Require`s `Spec`** — it is orphaned and not in the build. The project's
     central *privacy* guarantee is asserted by a file the ROCQ kernel never accepted in its
     current form. All 9 of its security lemmas are rated `unproven`.
  2. **`KnuthPlass.v` `T6_optimal` (Knuth-Plass global optimality) is axiom-backed, not proven.**
     `Theorem T6_optimal` (line 905) is closed by `Qed`, but its proof is one line:
     `exact (dp_optimal_invariant_holds ...)`, and `dp_optimal_invariant_holds` (line 897) is an
     **`Axiom`** asserting the entire Bellman global-optimality result. `Print Assumptions
     T6_optimal` would expose the axiom. The companion guarantee **T7** ("terminates and every
     emitted line fits or is reported overfull; never panics / silently overflows") is **never
     stated as a Prop at all.**

- **The cryptographic core (`CryptoSpec.v`) asserts its own correctness.** It markets itself as a
  "verified cryptographic protocol specification" but contains **zero `Qed`/`Defined` proofs**:
  13 Axioms + extraction directives + pure Definitions. The four "round-trip" correctness
  statements (`hpke_roundtrip`, `cek_wrap_roundtrip`, `aes_gcm_roundtrip`, `base64_roundtrip`)
  are themselves **Axioms** — the cryptographic guarantees are *assumed*, not derived.
  `random_bytes` is modeled as a **pure** `int -> string`; a deterministic implementation
  (`fun _ => zero32`) type-checks and silently destroys GCM nonce/key security.

- **The eq_refl "vacuity" concern is largely a non-issue.** Of the 63 `:= eq_refl`
  definition-as-theorem sites, the audited ones are **overwhelmingly non-vacuous**: each forces the
  kernel to reduce a real computation (PageModel 14/14 substantive, Tests 13/13, Boxes 6/6,
  GlyphLayout 7/7, BrowserPolicy 3/3). The real weakness is **absence of theorems**, not
  tautological ones.

**Verdict:** ROCQ buys this project genuine, valuable totality + type-safety and a *small* core
of real proofs (data-model lemmas, prefix-sum optimization equivalence, per-step Bellman
minimality, escaping case-analysis, WebAuthn-policy-as-data guards). It does **not** deliver the
advertised "invalid/unsafe/runtime-error states are unrepresentable" property — the live
`RangeError` stack overflow that shipped to production is the empirical proof of this, and the
audit found its structural cause (non-tail recursion over attacker-controlled data extracted to
unbounded C++ recursion) present in multiple unfixed places.

---

## 2. The Trusted Computing Base (TCB)

Everything below is **assumed, not proven**. The verification's guarantees are conditional on all
of it being correct.

### 2.1 The ROCQ kernel + extraction pipeline
- The ROCQ 9.0 kernel, and **Crane** (the ROCQ→C++23→WASM extractor). All `Crane Extract` /
  `Crane Extract Inlined Constant` / `Crane Extract Inductive` directives are trust boundaries:
  the proof is about the ROCQ term; the running code is whatever Crane + the shim emit.
- **Representation substitution gap:** all numeric reasoning is done over unbounded `Z`/`nat`, but
  extracts to `int64`/native `int`. Proofs about `Z` arithmetic say nothing about the `int64` the
  code actually runs (acute in KnuthPlass `cube`/`nd_demerits` overflow; see §4).

### 2.2 Genuine Axioms (assumed function specs)
| File | Axioms (assumed) |
|------|------------------|
| `CryptoSpec.v` | **9 primitive crypto axioms** (`ecdh_p256_generate/public_key/agree`, `random_bytes`, `aes_256_gcm_encrypt/decrypt`, `sha256`, `base64_encode/decode`) **+ 4 round-trip "correctness" axioms** (`hpke_roundtrip`, `cek_wrap_roundtrip`, `aes_gcm_roundtrip`, `base64_roundtrip`) |
| `KnuthPlass.v` | **`dp_optimal_invariant_holds`** — backs the flagship T6 (critical) |
| `DomFFI.v` | 5 (DOM I/O — noted by author as dead; live path uses `BrowserEffect`) |
| `NetFFI.v` | 3 (socket primitives) |
| `BridgeFFI.v` | 3 (`json_array_len/field/object4`) |
| `ProcFFI.v` | 2 (`procE`, `raw_run_proc`) |
| `Base64.v` | 2 (retired/orphan encode+decode — dead code inflating the axiom census) |
| `GlyphLayout.v` | 1 (`draw_glyph_quads`, honestly labeled; realized as no-op in `Extract.v`) |

### 2.3 Crane Extract / EM_ASM boundaries
Effect catalogs realized entirely by hand-written, unverified shims: `BrowserEffect.v` (18
constructors → `EM_ASM`/`browser_helpers.h`), `IoEffects.v` (6), `BrowserCrypto.v` (10 — re-points
all 9 crypto axioms from native OpenSSL to the **browser** shim, broadening the real TCB beyond
what `CryptoSpec.v`'s doc-comments describe). `DecryptApp.v`, `EnrollApp.v` terminate in extraction
directives.

### 2.4 The 6 C++ shims
`blog_helpers.h` (audited), `crypto_helpers.h`, `browser_helpers.h`, `browser_helpers_stub.h`,
`net_helpers.h`, `proc_helpers.h` (**5 not independently audited — see caveat**). Key audited
finding — **`blog_helpers.h`**: `sha256_trunc` is the **identity** (`:= s`) in ROCQ (`Logic.v:254`)
but a real 48-bit-truncated SHA-256 in C++ (line 47-58). Every theorem about inbox labels / asset
hashes was proven about the **raw input** then silently reinterpreted as a hash property at
extraction — pure "policy-in-shim." 48-bit truncation → birthday collision at ~2^24 posts. OpenSSL
failure yields a **silent empty hash** (all posts share an empty label), not a crash. `concat_all`
is, by contrast, a legitimate behavior-preserving O(n²)→O(n) override.

### 2.5 Genuine `Admitted`
**None as the literal `Admitted` keyword.** The only two `grep Admitted` hits (KnuthPlass.v ~867,
895) are **comments** describing a deferred T6 induction — **confirmed**. However, T6 *is*
effectively admitted via the `Axiom dp_optimal_invariant_holds` it `exact`-applies (line 914). So
"no Admitted" is technically true but materially misleading: the centerpiece theorem is
axiom-backed.

---

## 3. Proven vs Assumed vs Vacuous

### Genuinely PROVEN (real `Qed`, substantive)
- `Boxes.v` — 6 substantive list/fold lemmas, actually consumed by KnuthPlass prefix-sum proofs.
- `PageModel.v` — 14 non-vacuous reflective facts (real bool/list computations on closed terms).
- `Tests.v` — 13 non-vacuous `eq_refl` assertions (force real reduction of break/badness/demerits).
- `GlyphLayout.v` — 7 lemmas (one quad per glyph; all box quads share baseline).
- `Smtp.v` — 3 substantive state-machine case-analysis lemmas (in isolation).
- `BrowserPolicy.v` — 3 real guards forcing WebAuthn-policy tokens at type-check time (policy as
  ROCQ data, genuinely lifted out of a JS string).
- `KnuthPlass.v` partial machinery — prefix-sum equivalence (`dp_step_table_eq`, `scan_*`,
  `*_at_correct`, `line_width_cache`) and per-step Bellman minimality (`best_to_minimal`) are real
  and non-trivial.
- `Microtype.v` — 1 substantive (`clamp_expansion_bounded`); 2 degenerate-but-true.

### ASSUMED (axioms standing in for the actual claim)
- All of `CryptoSpec.v`'s correctness (round-trip axioms) — the crypto guarantees are postulated.
- KnuthPlass T6 global optimality (`dp_optimal_invariant_holds`).
- Every FFI primitive's documented pre/post-conditions (length, freshness, on-curve, constant-time)
  — none expressed as ROCQ refinement types; all trusted in shims.

### VACUOUS / BROKEN (claims something but proves nothing real)
- `Spec.v` `privacy` + 8 supporting lemmas — **do not compile** (arity mismatch; missing `intros`;
  orphaned). Rated `unproven`.
- `CryptoSpec.v` `hpke_roundtrip` — **mislabeled**: its body never calls `hpke_encrypt/decrypt`;
  it round-trips `encrypt_body/decrypt_body` on a directly-derived CEK, bypassing the ephemeral
  encapsulation that *is* HPKE base mode. Believing "HPKE round-trip is verified" is doubly wrong.
- The eq_refl sites are **not** the vacuity problem — they are mostly genuine.

---

## 4. Gaps — security properties NOT proven

- **Confidentiality / IND-CCA / "only the right recipient decrypts":** not proven; assumed via
  `cek_wrap_roundtrip` (no key-pairing hypothesis) and the unmodeled CSPRNG.
- **Integrity / AEAD soundness:** `aes_gcm_roundtrip` is an axiom; wrong-length key/nonce/tag are
  well-typed and silently map to `""` success paths in the shim.
- **Nonce/key freshness:** `random_bytes` is a pure function in the model — freshness, entropy,
  uniqueness are entirely outside ROCQ. A constant CSPRNG type-checks. (critical)
- **Authentication (WebAuthn):** `BrowserPolicy.v` provably routes the *policy tokens* to the FFI,
  but the ceremony's actual security is in the unaudited browser shim.
- **No-leak / privacy:** the one theorem stating it (`Spec.v`) does not compile and is out of the
  build; scope is also narrow (post page only — the inbox page embeds slug + a body hash).
- **Resource bounds / no-overflow / no-panic / termination of extracted code:** not proven.
  Termination is ROCQ-level (fuel/structural), which says **nothing** about extracted C++ stack
  depth — the shipped `RangeError` proves this gap is exploitable. KnuthPlass T7 ("never panics /
  silently overflows") is never even stated.
- **`Z`→`int64` overflow at the boundary:** badness/demerit minimality is proven over unbounded
  `Z`; `cube` (~10²⁴) and accumulated `nd_demerits` exceed 2⁶³, so even a proven T6 would describe
  arithmetic the code does not perform.
- **XSS:** `Logic.v html_escape` is fuel-bounded at 2,000,000; a >2 MB body silently stops being
  escaped (no theorem rules this out).
- **The pending Spec.v privacy proof** (per project memory) is the same broken file — still
  unfixed, still orphaned.

---

## 5. Per-module soundness table

Ratings from the file expert (high = real proofs / clean TCB; medium = honest but proves
type-safety/totality only; low = proves nothing relative to its claims, or actively broken).

| File | Rating | One-line |
|------|:------:|----------|
| `Typeset/Boxes.v` | **high** | Pure data model; 6 substantive lemmas, all consumed. Cleanest file. |
| `src/Decrypt.v` | **high** | Inert compatibility shim; trivial alias, no consumers (dead). |
| `Typeset/Tests.v` | medium | 13 non-vacuous `eq_refl` golden tests. |
| `src/PageModel.v` | medium | 14 genuinely non-vacuous reflective facts; no axioms. |
| `Typeset/GlyphLayout.v` | medium | 7 real lemmas; 1 honest `draw_glyph_quads` axiom. |
| `src/BrowserPolicy.v` | medium | Policy-as-data; 3 real type-check guards. |
| `src/Smtp.v` | medium | 3 real state-machine lemmas; claims exceed scope. |
| `Typeset/Microtype.v` | medium | 1 substantive + 2 degenerate lemmas. |
| `Typeset/Extract.v` | medium | Honest build driver; no-op `draw` realization. |
| `src/ProcFFI.v` | medium | FFI marshalling; 5 substantive helper facts; narrow. |
| `Typeset/Hyphenation.v` | medium | Total pure code, **no theorems**. |
| `Typeset/Metrics.v` | medium | Unverified hand-entered metric tables; no proofs. |
| `src/StringLib.v` | medium | Plumbing; totality only, **no theorems**. |
| `src/IoEffects.v` | medium | Effect functor + extraction; **no theorems**. |
| `src/DomFFI.v` | medium | 5 axioms; author notes they're **dead** (live = BrowserEffect). |
| `src/NetFFI.v` | medium | Unverified-by-design FFI; type discipline only. |
| `src/BrowserCrypto.v` | medium | Re-points crypto to browser shim; silent identity fallbacks. |
| `src/PostBuild.v` | medium | Guarded total Gallina; **no theorems**. |
| `src/MimeBuild.v` | medium | Defensive pure code; **0 theorems**. |
| `src/MimeIngest.v` | medium | Total MIME parser; "verified" in name only. |
| `src/InnerMime.v` | medium | Total; int63 add-wrap class, no proofs. |
| `src/EnrollApp.v` | medium | Good engineering; claims > proves; **0 theorems**. |
| `src/blog_helpers.h` | medium | `concat_all` faithful; `sha256_trunc` = identity-becomes-hash. |
| `src/Base64.v` | **low** | Orphan/dead; 2 axioms inflating CI census. |
| `src/BridgeFFI.v` | **low** | 3 bare axioms + EM_ASM; no logical content. |
| `src/BrowserEffect.v` | **low** | 18 extract directives; `fromCodePoint` RangeError; 0 props. |
| `src/CryptoSpec.v` | **low** | Crypto core **asserts its own correctness**; mislabeled HPKE. |
| `src/Decrypt­App.v` | **low** | Entry point of the app whose RangeError disproved the claim. |
| `src/DecryptPost.v` | **low** | Glue; reachable non-tail recursion; proves nothing. |
| `src/EncryptPost.v` | **low** | Sound glue; delivers ~no formal guarantee vs central claim. |
| `src/HpkeEnvelope.v` | **low** | Fully orphaned (no `.vo`, Required by nothing); 0 of everything. |
| `src/Logic.v` | **low** | Core logic, **no theorems**; fuel-truncation XSS class. |
| `src/MimeLib.v` | **low** | "Canonical single source of truth" — not one proof. |
| `src/SmtpServer.v` | **low** | 342-line effectful program, 0 proofs; O(n²) DATA accumulation. |
| `src/Spec.v` | **low** | Flagship privacy theorem **does not compile**; orphaned. |
| `Typeset/KnuthPlass.v` | **low** | T6 axiom-backed (not proven); T7 unstated; Z→int64 overflow. |

*(5 of 6 C++ shims unaudited — see §1 caveat. CrossCut/Adversarial phases produced no output.)*

---

## 6. Adversarial results

*(The 4 dedicated red-team agents all hit the session limit and produced no artifacts. The
following are concrete representable-invalid-state / broken-flagship findings extracted from the
PerFile reviews — i.e. red-team conclusions reached by other means, not independent confirmation.)*

- **Representable invalid state #1 — non-tail recursion → unbounded C++ stack (the shipped
  RangeError class, still present):** `DecryptApp.v` (`entries_to_triples`, `find_wraps`,
  `find_ct_b64`, `wrap_for_kid`, `max_qy`, `total_height`, `draw_quads_at`, `render_paras`),
  `DecryptPost.v` (`entries_to_triples` + imported `MimeBuild` cons-recursive fixpoints),
  `SmtpServer.v` (O(n²) `data_acc` left-fold over ≤1,000,000 lines). The 4000-char canvas guard in
  `DecryptApp.v` is labeled by the file itself as a "defense-in-depth" band-aid — an explicit
  admission the type system does not prevent the overflow.
- **Representable invalid state #2 — a constant "CSPRNG" type-checks:** `random_bytes : int ->
  string` is pure; `fun _ => zero32` satisfies the model and silently breaks GCM. No proof
  distinguishes it from a real CSPRNG. (critical)
- **Representable invalid state #3 — silent sentinel/empty on error:** browser `sha256` returns
  32 zero bytes on async error → `key_id`/KDF lose injectivity exactly in the failure mode;
  `blog_helpers.h` empty hash → all posts share an empty inbox label; wrong-length AEAD inputs →
  `""` success path. None are flagged as failures.
- **Representable invalid state #4 — `int63`→C `int` narrowing** everywhere (`(int)(...)` casts in
  `BrowserEffect`, `BrowserCrypto`, `random_bytes`): a 63-bit value wraps to 32 bits silently;
  `String.fromCodePoint` in `reader_glyph` throws an uncaught `RangeError` for cp <0 or >0x10FFFF
  (the Coq type bounds nothing) — a **second runtime-error class** of the same family as the one
  already shipped.
- **Vacuous/broken flagship theorems:** `Spec.v privacy` (does not compile), `KnuthPlass
  T6_optimal` (axiom-backed), `CryptoSpec hpke_roundtrip` (mislabeled + axiom). Three of the
  project's headline guarantees do not hold as advertised.

---

## 7. Prioritized recommendations

**P0 — broken claims (fix or stop advertising):**
1. **`Spec.v`:** update `render_eml_page` calls to the 2-arg signature, add `intros` to the six
   `html_escape_char` lemmas, add `Spec` to `_CoqProject`/the build, and run `Print Assumptions
   privacy` in CI. Until then, **do not claim privacy is formally verified.**
2. **`KnuthPlass.v`:** either discharge `dp_optimal_invariant_holds` (the deferred Bellman
   induction) or **rename `T6_optimal` to expose that it is conditional on an axiom**; add a `Print
   Assumptions` gate to CI so any `Theorem` resting on an axiom is surfaced. State T7 as an actual
   Prop or drop the header claim.
3. **`CryptoSpec.v`:** rename `hpke_roundtrip` (it is a body-encryption round-trip, not HPKE), and
   relabel the header from "verified" to "axiomatized against the FFI." Make the round-trip
   *axioms* visible as the TCB they are.

**P1 — close the representable-invalid-state gaps that already bit production:**
4. Add a CI lint / proof obligation that **no extracted recursion is non-tail over
   attacker-controlled data** (or prove explicit stack-depth bounds); remove the magic-number
   canvas band-aid in favor of a real bound. Audit `DecryptApp`/`DecryptPost`/`SmtpServer`.
5. Model effectful/length-constrained primitives with **refinement types or an effect/freshness
   token that the proofs actually consume**, so `random_bytes`, AEAD length pre-conditions, and
   on-error sentinels are not silently satisfiable by degenerate implementations.
6. Guard or wrap `String.fromCodePoint`, and eliminate silent `int63`→`int` narrowing on
   security/size-relevant values.

**P2 — TCB hygiene & honesty:**
7. **Audit the 5 unaudited C++ shims** (`crypto_helpers.h`, `browser_helpers.h`,
   `browser_helpers_stub.h`, `net_helpers.h`, `proc_helpers.h`) — they carry most of the real
   security burden and were not reviewed.
8. Mark `sha256_trunc`'s extraction directive distinctly from behavior-preserving overrides
   (identity-becomes-hash must not look like `concat_all`'s perf swap); add a nullptr/RAII guard on
   `EVP_MD_CTX`.
9. Delete dead/orphan files (`HpkeEnvelope.v`, retired `Base64.v` axioms, the dead `DomFFI.v`
   axioms) so the axiom census and "verified" surface area reflect reality.
10. Re-run the **CrossCut + Adversarial + remaining TCB-shim phases** that did not complete in this
    workflow; this report's adversarial section is derivative, not independent.

**Bottom line:** crane_blog gets real value from ROCQ — totality, type-safety, a genuine core of
data-model and typesetting lemmas, and policy-as-data. But it is **not** "invalid states
unrepresentable": most files prove nothing beyond well-typedness, the crypto core assumes its own
correctness, two flagship theorems are broken (one doesn't compile, one is an axiom in a `Qed`
costume), and the production-class runtime errors remain representable. The verification is
**weaker than advertised**, and the gap should be stated plainly rather than papered over.
