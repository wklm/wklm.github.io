# Crane decrypt WASM stack overflow — root-cause & prevention

> **STATUS:** historical audit report — findings partially superseded by
> subsequent commits (see `git log`); kept for provenance.

> Consolidated from the expert-team workflow `wf_dd975a22-0df` (Recon → Pinpoint →
> Analyze → Verify). **Provenance note:** the Recon (6 agents), Pinpoint (3),
> formal-methods panel (3), tail-fix (1) and recursion-audit (23) phases completed
> and their findings are harvested below. The dedicated **Prevention-design (2),
> adversarial-refute (3) and lead-synthesis (1) agents hit the session limit and
> produced no output** — so §6 is synthesized from the panel's `preventionPrinciple`
> outputs + the audit's per-function fixes, and §7 reports the two *deep-verify*
> agents that did complete plus an honest list of what was left unverified.

---

## 1. Executive summary

* **Culprit:** `InnerMime.body_to_html_aux` — `Fixpoint` at **`src/InnerMime.v:151`**,
  extracted to `InnerMime::body_to_html_aux` at
  `_build/default/FormalBlog/crane_decrypt.cpp:2412-2444`. All 3 Pinpoint agents
  converged on it independently (2 of them resolved the live WASM trace by
  disassembling the shipped binary).
* **Root cause (one line):** the recursive call sits as the **second argument to
  `StringLib::cat`** (`cat <chunk> (body_to_html_aux …)`), so it is **not in tail
  position**; `em++ -O2` cannot TCO it, and it pushes **one Asyncify-instrumented
  native frame per body byte**, bounded only by `mime_fuel = 65536` — overflowing the
  32 MB `-sSTACK_SIZE` on any decrypted body of more than a few thousand bytes.
* **Why verification didn't catch it:** ROCQ totality proves a *value* exists (a
  normal form), not that a *strict, stack-based evaluator* computes it in bounded
  stack. The fuel that **proves termination is exactly the number that overflows the
  stack.** This is a resource/refinement gap, not a soundness bug.
* **Single most important prevention:** make tail-position a **source-level**
  invariant for every input-proportional recursion (accumulator pattern), and add a
  **CI gate** that statically rejects any self-recursive call appearing in non-tail
  position in the extracted C++ — the exact, mechanically-detectable signature that
  the proofs can never see.

This is the **same class** as the four prior fixes (eb1d2ac `layout_all_tr`, 5cab40f
`scan_*`, 5acd36c body/layout, b99b788). It keeps recurring because each was a
point-fix, not a class-level gate.

---

## 2. Why a stack overflow is representable despite ROCQ totality

Synthesis of the three formal-methods panellists (type-theoretic, spec-auditor,
CompCert/CakeML-refinement).

### 2.1 What the proofs DO guarantee
* **Totality / termination.** `body_to_html_aux` decreases structurally on
  `fuel : nat` (`S f' => … f'`), so Rocq's guard checker accepts it: it is a total
  Gallina term with a normal form on **every** input. The explicit fuel
  (`mime_fuel = 65536`, `StringLib.v:38`) is itself a constructive termination
  certificate bounding the number of unfoldings.
* **Functional / partial correctness of the VALUE.** Every `@proofs` theorem that
  mentions the function constrains the *string it denotes* (escaping;
  `"\n\n"→"</p><p>"`, `"\n"→"<br>"`) — i.e. the bytes of the unique normal form. The
  privacy/`render_eml_page_only_uses_body`/`html_escape_*` lemmas are likewise
  denotational.
* **Extraction fidelity at the VALUE level + well-formedness.** `dune build
  src/wasm_checks` (`clang++ -fsyntax-only`) proves the generated C++ type-checks.

All of these are propositions about the **denotation of the term** and the bytes it
returns.

### 2.2 What the proofs DO NOT guarantee
Nothing about any **operational resource** of any evaluator — not reduction-step
count, not heap, and critically **not native call-stack depth**. Gallina/CIC has *no
notion of a call stack*; βι-reduction is defined over terms, and "how many physical
frames a C++ translation uses" is outside the object language. Specifically NOT
guaranteed:

* (a) that fuel bounds **frames** rather than **iterations** — in CIC every recursive
  call is "free"; the 65536-deep fuel chain is a *value*, not a cost;
* (b) that the extraction preserves **stack complexity** — value-equivalence (what
  `@proofs`/`wasm_checks` enforce) is invariant under mapping a non-tail Gallina
  `Fixpoint` to a non-tail C++ recursion, so **no proof can ever catch it**;
* (c) anything about `em++ -O2`'s TCO — the call isn't in tail position to begin with;
* (d) co-termination of **Asyncify**-instrumented frames against `-sSTACK_SIZE`.

### 2.3 The precise gap (a 4-layer untrusted refinement)
1. **CIC → cost model.** A fuel-bounded structural `Fixpoint` *denotes* a total
   function; "fuel = 65536" imposes **no** stack semantics. The human reads it as
   "safe iteration"; the calculus does not.
2. **Gallina → Crane C++.** The plugin transliterates `cat a (f x)` into
   `StringLib::cat(a, f(x))` (cpp:2427-2440), faithfully **preserving the non-tail
   call shape**. Under C++'s strict, eager, stack-based convention the inner call must
   return *before* `cat` runs ⇒ one activation record per input byte.
3. **C++ → em++ -O2.** `-O2` can TCO only *genuine* tail calls; the call is an
   argument to `cat`, so it is the textbook recur-then-combine counter-example. The
   shipped `func[119]` contains **zero `return_call` opcodes**.
4. **-O2 → Asyncify → WASM.** `-sASYNCIFY` spills locals into a linear-memory shadow
   stack for suspend/resume, **inflating per-frame cost**. ~65 536 inflated frames
   (each also copying a by-value `std::string s` parameter) blow past
   `-sSTACK_SIZE=33554432` → `RangeError`.

Every layer is individually correct. The crashing state is representable precisely
because **value-level equivalence — the only invariant the proofs enforce — is
preserved by a translation that does NOT preserve intensional stack-space cost, and
the very termination certificate (fuel) sizes the stack consumption.**

> One-line principle (all three panellists agreed): *prove the value in Gallina, but
> prove (or lint) the stack discipline against the operational model the proofs
> abstract away.* "Invalid states unrepresentable" was achieved only over the **value
> state space**; the **runtime stack is a parallel state space the spec never names**,
> so stack-depth > S was representable by construction.

---

## 3. The pinpointed culprit + evidence

**`InnerMime.body_to_html_aux`** — `src/InnerMime.v:151` (wrapper `body_to_html`
167-170); extracted at `crane_decrypt.cpp:2412-2444`; live call site
`src/DecryptApp.v:342` via `body_to_html`. **Confidence: high** (2 high, 1 medium;
unanimous).

### Live error trace (from the shipped artifact)
```
RangeError: Maximum call stack size exceeded
    at __emscripten_memcpy_js (crane_decrypt.mjs:9:29722)
    at crane_decrypt.wasm:0x2d934   (func151 → import _emscripten_memcpy_js)
    at crane_decrypt.wasm:0x2db4c   (func152, std::string copy)
    at crane_decrypt.wasm:0x2fe09
    at crane_decrypt.wasm:0x2ff8f
    at crane_decrypt.wasm:0x3016c   (StringLib::cat, sret + 2 std::string args)
    at crane_decrypt.wasm:0x27603   (func[119], call cat)
    at crane_decrypt.wasm:0x2783a   (func[119], `call 119` = SELF) <-- repeats
    at crane_decrypt.wasm:0x2783a   <-- deep self-recursion
```

### Evidence (resolved against the binary, not guessed)
* Two agents ran `wasm-objdump -d` on the **live** `static/crane_decrypt.wasm`:
  offsets `0x2783a` and `0x27603` are both inside **`func[119]`**; at `0x2783a` the
  instruction is `call 119` (self). The WASM has **no `name`/DWARF section** (em++ -O2
  stripped them), so the function was identified **structurally**: it (a) loads a byte
  (`i32.load8_s`) and compares to `i32.const 10` (`ch_newline`); (b) has exactly three
  `cat` branches keyed by a 0/1/2 slot — matching the three cases `"\n\n"→"</p><p>"`,
  `"\n"→"<br>"`, else `escape_byte c`. The function contains **zero `return_call`**.
* Source: all three branches are `cat <chunk> (body_to_html_aux s (pos+1|+2) f')` —
  recursive call as `cat`'s 2nd arg ⇒ non-tail. `StringLib::cat` is literally
  `_x0 + _x1` (std::string concat → `__emscripten_memcpy_js` per frame); the common
  branch also builds a fresh `std::string` via `escape_byte` each frame.

### Depth bound
`depth = min(byte-length of stripped inner body, mime_fuel = 65536)`, advancing `pos`
by +1 (or +2) per frame. **NOT gated** by `max_canvas_body = 4000`: that gate
(`DecryptApp.v:344`) guards only the canvas/typeset subtree, but `body_to_html` runs
**unconditionally first** at `DecryptApp.v:342` on the full body.

### Repro input
Decrypt any post whose inner body (after `strip_frontmatter`) is a long run of
ordinary characters — e.g. **a single ~20 000-character paragraph** (~3 300 words,
zero blank lines). `body_to_html_aux` recurses ~20 000 non-tail Asyncify frames (each
~5-6 nested `cat`/`memcpy` frames per the trace), already exceeding 32 MB; a 65 536-byte
body overflows comfortably. Newlines make it *worse* per byte.

### Strong alternative suspects named (same shape, ranked #2/#3)
`MimeBuild::strip_ws_aux` (cat-after-recurse per char over base64 ciphertext on the
`parse_envelope` path), `StringLib::split_on_char_fuel` (cons-after-recurse per line),
`MimeBuild::hex_decode_aux`. See §5 — most of these are *also* live overflows.

---

## 4. The proposed tail-recursive fix

**File touched: `src/InnerMime.v` only.** Convert the non-tail `Fixpoint` to a
tail-recursive accumulator form; keep a thin `Definition body_to_html_aux` wrapper
seeding `acc := ""`, so the wrapper `body_to_html` (line 170) and the sole call site
(`DecryptApp.v:342`) compile **unchanged**. (Grep confirms **no theorem anywhere names
`body_to_html_aux`** — the only reference is the wrapper at line 168.) Mirrors the
team's established `_tr` convention (eb1d2ac `layout_all_tr`, 5cab40f `scan_*_tr`,
`split_on_char_fuel_tr`).

```diff
--- a/src/InnerMime.v
+++ b/src/InnerMime.v
-Fixpoint body_to_html_aux (s : string) (pos : int) (fuel : nat) : string :=
-  let n := PrimString.length s in
-  match fuel with
-  | O => ""
-  | S f' =>
-      if leb n pos then ""
-      else
-        let c := PrimString.get s pos in
-        if int_eqb c ch_newline then
-          if andb (ltb (add pos 1%int63) n)
-                  (int_eqb (PrimString.get s (add pos 1%int63)) ch_newline)
-          then cat "</p><p>" (body_to_html_aux s (add pos 2%int63) f')
-          else cat "<br>" (body_to_html_aux s (add pos 1%int63) f')
-        else
-          cat (escape_byte c) (body_to_html_aux s (add pos 1%int63) f')
-  end.
+Fixpoint body_to_html_aux_tr (s : string) (pos : int) (fuel : nat)
+                             (acc : string) : string :=
+  let n := PrimString.length s in
+  match fuel with
+  | O => acc
+  | S f' =>
+      if leb n pos then acc
+      else
+        let c := PrimString.get s pos in
+        if int_eqb c ch_newline then
+          if andb (ltb (add pos 1%int63) n)
+                  (int_eqb (PrimString.get s (add pos 1%int63)) ch_newline)
+          then body_to_html_aux_tr s (add pos 2%int63) f' (cat acc "</p><p>")
+          else body_to_html_aux_tr s (add pos 1%int63) f' (cat acc "<br>")
+        else
+          body_to_html_aux_tr s (add pos 1%int63) f' (cat acc (escape_byte c))
+  end.
+
+Definition body_to_html_aux (s : string) (pos : int) (fuel : nat) : string :=
+  body_to_html_aux_tr s pos fuel "".
```

After editing, **re-run `dune build`** so `crane_decrypt.cpp` / `static/crane_decrypt.wasm`
regenerate (do **not** hand-edit the `_build` artifact). Every branch now ends in the
self-call ⇒ extracted C++ becomes `return body_to_html_aux_tr(…)` which `-O2` lowers to
a loop ⇒ **O(1) stack depth**.

### Correctness (extensional equality)
Prove by induction on `fuel`, generalised over `acc`:
`body_to_html_aux_tr s pos fuel acc = cat acc (OLD s pos fuel)`, using `cat`
associativity + identity (all reachable outputs ≤ ~459 KB ≪ `PrimString` max_length
`2^40-1`, so no truncation). Instantiate at `acc := ""` ⇒ new `body_to_html_aux` ≡
old, byte-for-byte. **No terminal `rev` is needed** because chunks are emitted
left-to-right and `cat` appends on the right (unlike list `_tr` functions whose `cons`
prepends).

### Theorems affected
None break. No `Lemma/Theorem/Corollary/Example/Definition` references
`body_to_html_aux` except the preserved wrapper. An optional bridging lemma
`body_to_html_aux_tr_spec` can be added later if a privacy/escaping spec wants a proved
equivalence; nothing in the tree needs it today.

### ⚠️ Caveat (raised by the deep-verify agent, see §7)
The string accumulator with per-frame `cat acc chunk` is **O(n²) in total bytes
copied** (each append re-copies the growing prefix). It *does* fix the overflow (stack
becomes O(1)), but for a 65 KB body it does O(n²) work. The audit's alternative fix
(`a9c7d00220836a84f`) **accumulates a `list string` and concatenates once via the
native-backed `concat_all`** — O(n) and overflow-free — and is the preferred shape if
throughput matters. Either form removes the overflow.

---

## 5. OTHER latent input-proportional non-tail recursions found in the audit

23 functions were individually deep-verified. **WOULD OVERFLOW on realistic decrypt
input (fix now — same class):**

| Function | File | Depth bound | Recommended fix |
|---|---|---|---|
| `body_to_html_aux` | `src/InnerMime.v:151` | `min(body bytes, 65536)`, +1/byte | **the §4 patch** (prefer list-acc + `concat_all`) |
| `MimeBuild::hex_decode_aux` | `src/MimeBuild.v:63` | `min(65536, hexlen/2)`; ek/w hex is attacker-parsed | acc + `concat_all (rev acc)`; tail call |
| `MimeBuild::strip_ws_aux` | `src/MimeBuild.v` (cpp:2020) | `min(len(ct_b64), 65536)`, **1/char** | source already chunk-acc form — **artifact is STALE**, regenerate; else acc-chunk patch |
| `MimeBuild::split_parts_aux` | `src/MimeBuild.v` | `#MIME-part boundaries` ≤ 65536 (ordinary lines take the tail branch) | `acc : list string` + final `rev`; seed `nil` |
| `shape_aux` | `Typeset/Metrics.v:180` | `min(#words+#space-runs, 65536)` = O(body) | `shape_aux_tr` acc + `List.rev`; preserve signature |
| `shape_paragraph` (via `shape`/`shape_aux`) | `Typeset/Metrics.v` | drives two O(body) non-tail recursions + a non-tail `++` | acc form + seed terminator reversed (kills the `++` too) |
| `List::rev` (runtime) | `crane_decrypt.h:164` | `= list length`; `a1->rev().app(...)` non-tail **and O(n²)** | redefine `rev` via tail `rev_append`; fix at ROCQ `List` source, re-extract |
| `List::app` (runtime ++) | `crane_decrypt.h:210` | `= length(left)` | route through `rev`/`rev_append`; also fix `KnuthPlass::trace_back` accumulator |
| `StringLib::split_on_char_fuel` | `src/StringLib.v:135` (cpp:1563) | `#delimiters` ≤ 65536 | **source already tail (`_tr`) — artifact STALE**; regenerate + verify `_tr` present |

**Input-proportional but currently SAFE (do not regress):**

* `scan_width_tr` — already tail (O(1)).
* `scan_stretch_tr` / `scan_shrink_tr` — depth O(#items) but **call is in tail
  position** ⇒ no native frame (safe *as source*; the stale artifact may show them
  non-tail — see below).
* `legal_positions_aux` / `trace_back_aux` — tail / well-founded, depth bounded by
  paragraph items / breakpoints.
* `word_width`, `word_glyphs` — non-tail but bounded by one word/space-run; `word_glyphs`
  additionally under the `max_canvas_body=4000` gate. (A pathological 64 KB no-space
  "word" *would* overflow `word_width` — flagged as lower-priority.)
* `group_lines` — non-tail but ≤ ~1333 frames in practice.
* `nat_of_int_fuel`, `List::length`, `List::firstn` — non-tail but bounded by small
  inputs (string length as int / line items / one line slice).

> **STALE-ARTIFACT WARNING (Recon + deep-verify, high importance).** The on-disk
> `_build/.../crane_decrypt.cpp` (mtime 2026-05-31) **predates** the source tail-rec
> fixes (e.g. `src/StringLib.v` 2026-06-01). `grep _tr` finds **zero** real matches in
> it, and `scan_width/stretch/shrink` (cpp:939/963/984) still emit non-tail
> `List::cons(acc, <recurse>)`. So **reading the artifact overstates the problem**; CI's
> `dune build` will re-extract from current source. BUT the deployed decrypt WASM is
> built from `crane_decrypt.cpp` (extracted from `DecryptApp.v` which `Require`s
> `StringLib`), so a **rebuild + redeploy is required** to pick up the already-landed
> fixes — and the §4 + `body_to_html_aux`/`hex_decode_aux`/`shape_aux`/`split_parts_aux`
> source fixes still need to be written.

---

## 6. Prevention architecture

> The dedicated prevention-design agents did not run (session limit). The following is
> synthesized from the panel's `preventionPrinciple` outputs and the audit's
> per-function fixes. The brief named existing gates to extend:
> `scripts/check-shim-thinness.sh`, `check-dom-coherence.sh`, `check-single-source.sh`,
> `.githooks/pre-commit`, `.forgejo` CI, `dune build @proofs`, `dune build src/wasm_checks`
> (clang++ syntax-only). Ranked by leverage:

1. **CI gate: reject non-tail self-recursion in the extracted C++ (highest leverage).**
   Extend `src/wasm_checks` (today value/type-only) with a lint/AST pass over
   `crane_decrypt.cpp` that flags any function whose **recursive self-call is not in
   tail position** (recursive call appearing as an argument to a constructor/combinator
   — `cat`, `cons`, `+1`, `app`). This is the *exact, mechanically-detectable
   signature* the proofs can never see. Add as a `scripts/check-no-nontail-recursion.sh`
   wired into `.githooks/pre-commit` + `.forgejo`, alongside the existing checks. Gate
   on the **freshly re-extracted** artifact to defeat the stale-artifact trap.

2. **Source discipline: tail-position as an invariant for every input-proportional
   recursion.** Any `Fixpoint` whose depth is input-proportional MUST be written in the
   accumulator (`+ rev`/`concat_all`) form, recursive call as the sole expression of
   its branch. Convert the outstanding entry points **now** (§5 table). Optionally
   introduce a `TailRecursive`/`BoundedStack` predicate so deviation is a *proof*
   failure rather than a runtime failure.

3. **Defense-in-depth (formal + runtime).**
   * Entry-point obligation tying logical fuel to a **physical stack budget**: for each
     extracted root reachable from `Crane Extraction "crane_decrypt" run`, the weak-but-
     sufficient `BoundedStack entry := every reachable Fixpoint is tail-recursive OR has
     input-independent depth`.
   * **e2e/Node harness in CI**: exercise the longest realistic input (>32 KB body)
     against the 32 MB stack — mirror the typesetter stack-safety commits. Lock in a
     long-body decrypt test.
   * **Do NOT just raise `-sSTACK_SIZE`** — depth is attacker/author-input-proportional,
     so that only postpones the crash.

> Principle in one line: *any property you want true at runtime must be quantified over
> the runtime's state space and re-checked by the build; extraction crosses a trust
> boundary (CIC has no stack), so denotational correctness must be paired with an
> operational resource check, or the unconstrained machine state stays representable.*

---

## 7. Adversarial verification results

**The Verify phase did not complete.** The 3 adversarial-refuter agents (culprit /
patch-correctness / prevention-gate) and the lead-synthesis agent **hit the session
limit and produced no output** — they cannot be reported as confirming or refuting.
Treat the claims below as **un-refuted-by-an-adversary**, pending a re-run.

What *did* complete were two **deep-verify** agents, which surfaced two important
caveats the headline fix should heed:

* **`StringLib::split_on_char_fuel` / `aca562ace795cdf0e`:** confirmed the deployed
  artifact is **stale** (still the old non-tail cons form) while the source is already
  tail (`split_on_char_fuel_tr`). **Critical secondary finding:** even after the tail
  fix, the finalization `rev acc` extracts to ROCQ stdlib **`List::rev` = `a1->rev().app(…)`,
  which is itself non-tail AND O(n²)** (cpp `decrypt_post.h:129-134`). So a "tail-rec
  fix" that calls `rev`/`++` merely **relocates** the O(N-pieces) stack depth into
  `List::rev`. The authors had already made the `List` *destructor* iterative but left
  `rev`/`app` recursive — fix `List.rev` at the ROCQ source via `rev_append` and
  re-extract (this also fixes `decrypt_post.h`, `encrypt_post.h`, `smtp_listener.h`).
  → This is why §4 prefers list-acc + native `concat_all` and §5 lists `List::rev`/`app`.

* **`MimeBuild::split_parts_aux` / `a5f7e42bd197e6055`:** confirmed non-tail via call
  site #1 (`cons`-wrapped) but established it fires **per MIME boundary, not per line**
  (ordinary lines take the tail branch, TCO'd by `-O2`), so its realistic depth is
  shallower than `body_to_html_aux`'s per-byte depth. Still worth the accumulator fix.

### Open caveats / blockers for the implementer
* **Full pipeline is not locally reproducible:** `dune`/`rocq`/`coqc` and `em++`/`emcc`
  are **not** in PATH on the build host (only inside Docker stages). Only `clang++
  -fsyntax-only` is runnable locally. WASM rebuild + Playwright e2e = CI/Docker path.
* **Stale artifact** must be regenerated and **redeployed** (Cloudflare
  stale-while-revalidate edge-caches — cache-bust after deploy).
* **The §4 string-acc patch is O(n²) in bytes copied** — fixes the crash but prefer the
  list-acc + `concat_all` variant for performance.
* **Re-run the Verify phase** (adversarial refute + lead synthesis) to close the audit.

---

## Appendix — full recursion inventory

Recon mapped **102** recursive functions across `src/` + `Typeset/` + runtime headers.
Non-tail, input-proportional ones on the decrypt path are the risk surface; the §5
table lists the live and latent ones. Notable additional non-tail functions the audit
did not individually deep-verify (candidates for the same accumulator treatment):
`collect_text` / `collect_image_names` (`src/InnerMime.v`), `flatten_ws_aux` /
`b64_decode_aux` / `collect_text_parts` / `join_blank` (`src/MimeIngest.v`),
`parse_wraps_entries_aux` and the inner `join`/`join_wraps` fixes (`src/HpkeEnvelope.v`),
`concat_all` / `join_comma` (`src/MimeBuild.v`), `entries_to_triples` (`src/DecryptApp.v`),
`hex_encode_aux` / `upcase_aux` / `downcase_aux` (`src/StringLib.v`), and the runtime
`List::filter` / `List::map` (`blog.h`). Most are bounded by small fields, but each
should be checked against the §6 CI gate once it exists.
