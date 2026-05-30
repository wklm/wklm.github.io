# TRUSTED.md — crane_blog trusted-boundary registry

## The single-source contract

crane_blog's design contract is that **every behavioral decision — the exact
bytes produced, all control flow, every accept/reject — lives in a ROCQ `.v`
file**, Crane-extracted to C++23 and compiled two ways: native (the
`blog_generator` / `encrypt_post` / `decrypt_post` / `smtp_server`
executables, linking OpenSSL) and WASM (`crane_decrypt` / `crane_enroll`, built
with `em++`). The protocol layer, the MIME construction, the parsing, the
policy — all of it is proven ROCQ.

The ONLY permitted non-`.v` artifacts are:

- **(a) thin FFI shims** that realize a ROCQ-declared axiom or effect by pure
  delegation to a platform syscall/library plus value marshalling — with **no**
  domain branching, string/MIME/protocol construction, or policy; and
- **(b) build configuration** (dune, Dockerfiles, CI workflows, hooks, scripts,
  test harness).

This file is the registry of the **(a)** boundaries: each is *trusted, not
proven*. For each we record the ROCQ axiom/effect it realizes, where that is
declared, the file that realizes it with real symbols, and why it passes the
thin-shim test.

### The thin-shim test (all four required)

1. **Total platform delegation** — the body is a syscall / library call /
   browser API call, nothing more.
2. **No branching on domain values** — error-vs-success plumbing and byte
   marshalling are allowed (e.g. `b & 0xff` byte masks, base64 framing,
   NUL-joined argv splitting, `nonce||ct||tag` slicing); branching on *what a
   value means* in the blog/MIME/SMTP/crypto-protocol sense is NOT.
3. **ROCQ-declared signature** — every entry point matches an `Axiom` or
   `Crane Extract Inductive` constructor declared in a `.v` file.
4. **Swappable without changing observable output** — a different correct
   implementation of the same primitive (OpenSSL ⇄ WebCrypto, POSIX ⇄ any other
   socket layer) yields byte-identical observable results.

> **Key asymmetry.** The shared `CryptoSpec.v` protocol layer — HPKE base mode,
> CEK wrap/unwrap, the SHA-256-based KDF (`custom_kdf_sha256`), AES-GCM
> packaging, P-256 point compression, key-id derivation — is **pure ROCQ** and
> identical across native and browser. Only the **nine primitives** cross the
> FFI. Natively they are OpenSSL EVP (**C1**); in the browser the *same nine
> axioms* are re-pointed (by `BrowserCrypto.v`, which re-issues every
> `Crane Extract Inlined Constant … From "browser_helpers.h"`) to
> `crypto.subtle` / `getRandomValues` (**C2**).

---

## C1 — Native crypto (OpenSSL EVP)

- **ROCQ side.** Nine axioms in `src/CryptoSpec.v`: `ecdh_p256_generate`,
  `ecdh_p256_public_key`, `ecdh_p256_agree`, `random_bytes`,
  `aes_256_gcm_encrypt`, `aes_256_gcm_decrypt`, `sha256`, `base64_encode`,
  `base64_decode`. Each carries a `Crane Extract Inlined Constant … =>
  "…" From "crypto_helpers.h"` directive (CryptoSpec.v lines ~262–284). The
  protocol composition over them (`hpke_encrypt` / `hpke_decrypt`, `wrap_cek` /
  `unwrap_cek`, `encrypt_body` / `decrypt_body`, `custom_kdf_sha256`) is pure
  ROCQ in the same file. `IoEffects.v`'s `toolE` (argv/getenv/stderr/exit) also
  resolves here.
- **Realized by.** `src/crypto_helpers.h` (OpenSSL EVP/EC/RAND/SHA). Real
  symbols: `ecdh_p256_generate(std::monostate)`, `ecdh_p256_agree`,
  `aes_256_gcm_encrypt`/`aes_256_gcm_decrypt` (EVP_aes_256_gcm, GCM tag
  get/set), `sha256` (SHA256), `random_bytes` (RAND_bytes), `base64_encode`/
  `base64_decode` (table-driven), plus the process-IO shim
  `tool_set_args`/`tool_arg_count`/`tool_arg_get`/`tool_getenv`/`tool_eprint`/
  `tool_exit`. Linked only into native builds (`-lssl -lcrypto`).
- **Thin-shim justification.** (1) Pure OpenSSL/libc delegation. (2) Branching
  is only well-formedness/error plumbing (key/nonce/tag length checks → `""`,
  tag-mismatch → `""`) and byte marshalling (SEC1 65-byte pubkeys, 32-byte
  scalar left-pad, base64 6-bit framing) — no MIME/protocol/policy. (3)
  Signatures match the nine axioms; the two tuple primitives return
  `std::pair` directly (Crane's `prod`). (4) Semantics deliberately match the
  retired `crane_crypto.ml` and the WebCrypto leg byte-for-byte, so it is
  swappable.
- **Trusted-not-proven.** OpenSSL's correctness, the round-trip/AEAD axioms
  (`hpke_roundtrip`, `cek_wrap_roundtrip`, `aes_gcm_roundtrip`,
  `base64_roundtrip` — *stated as axioms* in CryptoSpec.v), and that this header
  carries no domain logic.

## C2 — Browser crypto / auth (WebCrypto + WebAuthn + IndexedDB)

- **ROCQ side.** `src/BrowserCrypto.v` re-issues the **same nine** CryptoSpec
  directives re-pointed `From "browser_helpers.h"` (lines ~67–91) — Crane
  applies the *last* registered directive, so importing `CryptoSpec` then
  `BrowserCrypto` yields an extracted unit that includes only
  `browser_helpers.h` (never OpenSSL). Point compression (`compress_pubkey`,
  `compressed_prefix`) and `browser_key_id` are pure ROCQ here. The
  capability *effects* — WebAuthn, IndexedDB, sessionStorage, CSPRNG — are the
  `brE` constructors `WaCreate`/`WaGet`, `IdbGetAll`/`IdbPut`,
  `SsGet`/`SsSet`/`SsRemove`, `RandomBytes` in `src/BrowserEffect.v`, mapped via
  one `Crane Extract Inductive brE … From "browser_helpers.h"` table.
- **Realized by.** `src/browser_helpers.h` (Emscripten, 29 `EM_ASM` blocks; the
  literal `EM_ASM` text lives in this **header**, not in the `.v` files for
  C2/C3). Real symbols: `random_bytes` (`crypto.getRandomValues`), `sha256` /
  `ecdh_p256_generate` / `ecdh_p256_public_key` / `ecdh_p256_agree` /
  `aes_256_gcm_encrypt` / `aes_256_gcm_decrypt` (`crypto.subtle.*`),
  `webauthn_create` / `webauthn_get` (`navigator.credentials.create/get`),
  `idb_get_all` / `idb_put` (`indexedDB`), `ss_get`/`ss_set`/`ss_remove`. Async
  primitives suspend the WASM stack via `Asyncify.handleAsync` (built with
  `-sASYNCIFY`), so the pure-ROCQ caller sees ordinary synchronous effects. A
  signature-identical native fallback, `src/browser_helpers_stub.h`, is used
  when `__EMSCRIPTEN__` is undefined (powers the `crane_*.check` compile gates).
- **Thin-shim justification.** (1) Each body is a single WebCrypto/WebAuthn/
  IndexedDB call. (2) The one representational quirk — a browser `privkey`
  carries a WebCrypto JWK string instead of a raw 32-byte scalar — is internal
  marshalling, produced and consumed only by the two ECDH primitives, invisible
  to the protocol; all record-matching/branching is ROCQ. (3) Signatures match
  the nine axioms and the `brE` table. (4) Swappable: byte-for-byte equal to the
  OpenSSL leg (same packaging, same `""`-on-error contract).
- **Trusted-not-proven.** The browser engine's WebCrypto/WebAuthn/IndexedDB
  implementations, Asyncify suspension correctness, and JWK⇄raw equivalence.

## C3 — Browser DOM

- **ROCQ side.** `brE` DOM constructors in `src/BrowserEffect.v`: `DomGetText`,
  `DomSetText`, `DomSetHtml`, `DomShow`, `DomHide`, `DomPathSlug` (plus the
  keepalive `BindInvoke` / `ActionFlag` click re-entry). `src/DomFFI.v` is the
  documented home of the seam, restating standalone axioms `el_text`,
  `set_text_content`, `set_inner_html`, `show_el`, `hide_el` with matching
  directives. `src/BridgeFFI.v` holds non-effect JSON marshalling
  (`json_array_len`, `json_array_field`, `json_object4`).
- **Realized by.** `EM_ASM` wrappers in `src/browser_helpers.h`:
  `dom_get_text` (textContent), `dom_set_text` (`textContent =`),
  `dom_set_inner_html` (`innerHTML =`), `dom_show`/`dom_hide` (style.display),
  `dom_path_slug` (`location.pathname` last segment), `bind_invoke` /
  `crane_action_flag`, and the JSON helpers. (Again, the `EM_ASM` bodies are in
  the header; the C3 `.v` files only carry `From "browser_helpers.h"`
  directives.)
- **Thin-shim justification.** (1) Direct DOM property reads/writes. (2) No
  domain branching — which element gets which text is decided in ROCQ; the shim
  takes an id + string. (3) Signatures match the `brE` table / DomFFI axioms.
  (4) Swappable DOM glue.
- **Trusted-not-proven.** That `dom_set_text` writes `textContent` (never
  `innerHTML`) and `dom_set_inner_html` is only ever fed ROCQ-escaped HTML —
  the realization side of the **T1** privacy/XSS argument (see DomFFI.v and
  InnerMime.v notes).

## C4 — Filesystem / directory IO

- **ROCQ side.** Crane's `Monads.IO` / `Monads.Dir` prelude effects — `read`,
  `write_file`, `create_directory`, `list_directory` (the `dirE` / `ioE`
  algebra) — combined in `Logic.v` as `itree (dirE +' ioE)` and in
  `IoEffects.v` as `dirE +' ioE +' toolE`.
- **Realized by.** The Crane prelude's IO/Dir realization, supplemented by
  `src/blog_helpers.h` for two extraction overrides registered in `Logic.v`:
  `concat_all_std` (single-pass `list string` concat, replacing the O(n²)
  default fixpoint) and `sha256_trunc_std` (first-12-hex-char SHA-256 for
  content-addressed inbox labels, via OpenSSL EVP).
- **Thin-shim justification.** (1) `concat_all_std` is a pure
  reserve-then-append over Crane's `List<T>` representation; `sha256_trunc_std`
  is a single EVP digest. (2) No domain branching — concatenation order and
  what gets hashed are decided in ROCQ. (3) Registered via
  `Crane Extract Inlined Constant` in Logic.v. (4) Each is an asymptotic/locality
  optimization of a behavior ROCQ already specifies, hence swappable.
- **Trusted-not-proven.** The prelude IO realization and that these two
  overrides are observably equal to the ROCQ definitions they replace.

## C5 — Network sockets (POSIX)

- **ROCQ side.** `src/NetFFI.v` defines the `netE` effect — `Listen`, `Accept`,
  `RecvLine`, `RecvBytes`, `Send`, `Close` — with one
  `Crane Extract Inductive netE … From "net_helpers.h"` table. SMTP framing and
  all parsing live in `SmtpServer.v` / `Smtp.v`, not here.
- **Realized by.** `src/net_helpers.h` (POSIX sockets). Real symbols:
  `net_listen` (socket/setsockopt/bind/listen), `net_accept`, `net_recv_line`
  (one byte at a time up to `\n`), `net_recv_bytes`, `net_send`, `net_close`.
- **Thin-shim justification.** (1) Pure socket syscalls. (2) `recv_line` reads
  byte-at-a-time precisely to keep *all* buffering/framing policy in ROCQ; fds
  are plain ints. (3) Signatures match the six `netE` constructors. (4)
  Swappable transport plumbing.
- **Trusted-not-proven.** The OS socket stack and the sequential one-connection
  accept-loop model.

## C6 — Subprocess (`posix_spawn`-class; fork+execvp)

- **ROCQ side.** `src/ProcFFI.v` defines `procE` with the single constructor
  `RunProc : string -> string -> procE string` and smart constructor
  `raw_run_proc argv stdin`. Packed-result parsing (`proc_exit_code`,
  `proc_output`, `proc_ok`) and NUL-joined argv construction (`join_nul`) are
  pure ROCQ in the same file.
- **Realized by.** `src/proc_helpers.h` — `run_proc(argv_joined, stdin_data)`:
  `split_nul` → `pipe`/`fork`/`dup2`/`execvp` (no shell) → `drain_fd` →
  `waitpid`, returning the packed string `"exit\nstdout\nstderr"`.
- **Thin-shim justification.** (1) Pure fork/exec/pipe delegation, no shell
  interpolation. (2) Splitting NUL-joined argv and packing the result string are
  marshalling; the git command line itself is built in ROCQ. (3) Signature
  matches the single `procE` constructor. (4) Swappable spawn mechanism.
- **Trusted-not-proven.** The OS process model and that `run_proc` performs no
  git/SMTP/MIME interpretation.

## C7 — WASM loader (generated; no hand-written logic)

- **ROCQ side.** None — generated artifacts.
- **Realized by.** Emscripten ES6 module loaders `crane_decrypt.mjs` /
  `crane_enroll.mjs` (+ the paired `.wasm`), emitted by the Dockerfile `wasm`
  stage (`FROM emscripten/emsdk:3.1.61`) from the Crane-extracted
  `crane_decrypt.cpp` / `crane_enroll.cpp`, with `em++ … -sMODULARIZE=1
  -sEXPORT_ES6=1 -sINVOKE_RUN=0 -sASYNCIFY`. The built `.mjs`/`.wasm` for both
  apps are present under `static/`.
- **Thin-shim justification.** (1) Pure Emscripten runtime glue
  (instantiate/marshal/Asyncify). (2) Carries no domain logic — all behavior is
  in the embedded ROCQ-derived WASM. (3) N/A (generated, not an axiom). (4)
  Swappable for any conformant loader.
- **Trusted-not-proven.** The Emscripten toolchain (pinned 3.1.61) and its
  generated glue.

## C8 — TLS / transport

- **ROCQ side / realization.** **Explicitly out of scope.** The SMTP listener
  binds its Tailscale IP only (`compose.yml`: `network_mode: host`,
  `SMTP_HOST` pinned to the tailnet address, never `0.0.0.0`); confidentiality
  of the link is delegated to the **Tailscale (WireGuard)** mesh. There is no
  TLS code in this repo to trust.
- **Trusted-not-proven.** Tailscale/WireGuard, and the operational guarantee
  that port 2525 is never exposed on a non-tailnet interface.

## C9 — entry shims (dune `echo`-generated `main.cpp`)

- **ROCQ side.** None — the extracted units export `run()` (and `tool_set_args`
  for the CLIs); they have no `main`.
- **Realized by.** `dune` `(rule (with-stdout-to … (echo …)))` stanzas:
  `src/dune` emits `main.cpp` (`run();`) for `blog_generator.exe` and
  `smtp_main.cpp` for `smtp_server.exe`; `tools/dune` emits `encrypt_main.cpp` /
  `decrypt_main.cpp` (`tool_set_args(argc, argv); run();`). The Dockerfile
  `wasm` stage `printf`s the analogous `decrypt_main.cpp` / `enroll_main.cpp`.
- **Thin-shim justification.** (1) The entry literally captures argv (CLI only)
  and calls `run()`. (2) No branching at all. (3) Calls the ROCQ-exported
  `run`/`tool_set_args`. (4) Trivially swappable.
- **Trusted-not-proven.** That these one-line shims do nothing but forward argv
  and invoke `run`.

## C10 — Build configuration

- **ROCQ side / realization.** Category **(b)**, not an FFI seam. Inventory:
  `dune-project`, `src/dune`, `tools/dune`, `src/Typeset/dune`; `Dockerfile`
  (builder + `wasm` + smtp stages) and `smtp/`; CI workflows
  `.forgejo/workflows/{e2e,deploy}.yml` and `.github/workflows/deploy.yml`;
  `compose.yml`; the `.githooks/pre-commit` hook; `scripts/` (`new-post.sh`,
  `setup-hooks.sh`, `setup_fuji.sh`, `test-roundtrip.sh`); and the
  `tests/e2e/` Playwright harness (`playwright.config.ts`, `package.json`).
- **Thin-shim justification.** Build/test orchestration only; produces no
  shipped runtime behavior beyond invoking the compilers and the proven units.
- **Trusted-not-proven.** That the build wiring compiles the proven `.v`-derived
  sources faithfully and adds no behavior (the `crane_*.check` syntax gates and
  `test-roundtrip.sh` guard this).

---

## Verified-Reader typesetter (C11–C13) — PLANNED, not yet realized

The typesetter **engine** exists and is pure ROCQ under `src/Typeset/`:
`Boxes.v`, `Metrics.v`, `KnuthPlass.v`, `Hyphenation.v`, `Microtype.v`,
`GlyphLayout.v`, `Tests.v`, and the extraction sanity driver `Extract.v`. It
is **not yet wired into the browser reading view** (the served pages use the
C2/C3 decrypt path; `static/` holds only the `crane_decrypt`/`crane_enroll`
artifacts and no glyph/MSDF assets). Accordingly, C11–C13 are documented for
completeness but are **not active trusted boundaries today**.

## C11 — Glyph metric / kern / ligature tables

- **Status: PLANNED data (already present, pure ROCQ — not an FFI shim).**
- `src/Typeset/Metrics.v` holds the trusted Latin metric table as ordinary ROCQ
  data: per-glyph advance widths (`w_space`, `w_narrow`, `w_normal`, `w_wide`,
  `w_digit`, classified by `is_narrow_cp` / `is_wide_cp` / `is_digit_cp` →
  `advance_of`), the `kern_pairs` list with `kern_of`, and the `interword`
  glue. This is *trusted offline data*, not a platform call — it crosses no
  FFI. It is "trusted" only in that the numbers are asserted, not derived from a
  font file in-proof.

## C12 — MSDF glyph atlas

- **Status: PLANNED asset — does NOT exist.** No MSDF/atlas asset is present
  anywhere in the repo. When the reading view is wired up, an offline
  `msdfgen`-produced atlas texture would be the trusted asset paired with C13.

## C13 — GPU draw shim (`draw_glyph_quads`)

- **Status: PLANNED — declared, not realized.** `src/Typeset/GlyphLayout.v`
  declares `Axiom draw_glyph_quads : quad_buffer -> unit` (the *single* intended
  FFI of the whole typesetter) but deliberately leaves it unrealized in the pure
  theory; the real `Crane Extract Inlined Constant draw_glyph_quads =>
  "draw_glyph_quads(%a0)"` directive is present only as a commented AIDEV-NOTE.
  The sole place it is currently realized is `src/Typeset/Extract.v`, as a
  **no-op** (`=> "((void)%a0, std::monostate{})"`) purely to drive a native
  clang++ compile-check. No `EM_ASM`/Embind GL upload exists yet, and there is
  **no `draw_segments` axiom** anywhere in the repo.
- **Intended thin-shim justification (when built).** A logic-free upload of the
  already-final integer `quad_buffer` to a VBO + one indexed draw against the
  MSDF atlas — no typesetting logic crosses the seam (all line-breaking /
  layout is the proven Knuth-Plass + GlyphLayout pipeline). Until the WASM
  integration step ships it, it is a no-op and trusts nothing at runtime.

---

> **Governing theorems.** What is *allowed* to cross these boundaries is
> constrained by the proven privacy/leakage results in `src/Spec.v` — notably
> **T1** (the `privacy` theorem: a public post page renders only the ciphertext
> body and fixed template strings; `parse_eml` provably discards `Subject` /
> `From` / `To`, and untrusted decrypted text reaches the DOM only via
> `textContent`) together with the `html_escape_char` case lemmas. The FFI
> shims above are trusted to *realize* those boundaries faithfully; the `.v`
> theorems are what prove the boundaries are safe in the first place.
