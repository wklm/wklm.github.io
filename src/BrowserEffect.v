(* BrowserEffect.v — browser-side effect algebra [brE] for the WASM decrypt /
   enroll apps, plus the [BIO := itree brE] monad they run in.

   This is the browser analogue of Logic.v's [dirE +' ioE] and IoEffects.v's
   [toolE]: an inductive effect with one constructor per browser capability and
   a per-constructor [Crane Extract Inlined Constant] directive.  The C++
   realization lives in src/browser_helpers.h (FFI boundary C2/C3): DOM,
   sessionStorage, IndexedDB, WebAuthn, and a CSPRNG, all via EM_ASM.  Async
   capabilities (IndexedDB / WebAuthn) suspend the WASM stack with
   Asyncify.handleAsync, so they present here as ordinary synchronous effects.

   Crane extraction is per-operation, not per-sum-shape, and this module's apps
   run over the *single* effect [brE] (no [+'] sum needed), keeping the monad
   table trivial.

   NO directive here pulls crypto_helpers.h / OpenSSL — browser_helpers.h is
   Emscripten-only (per crane-extraction-gotchas: WASM headers must never drag
   in OpenSSL). *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree.
(* Mapping.ZInt realizes [Z] (= Typeset's [sp]) as [int64_t] with native C++
   arithmetic; without it Crane emits [Z] as an unreadable positive/N bit-tree.
   The Verified-Reader glyph effects (ReaderGlyph) carry [Z] pen coordinates, so
   this module must import ZInt for them to extract as plain int64.  SAFE here:
   the crane_decrypt dependency graph (CryptoSpec / MimeBuild / BrowserCrypto /
   ...) does NO ROCQ-side N/Z/positive arithmetic — P-256 lives entirely behind
   the string-typed crypto FFI — so ZInt (which also maps N/positive ->
   unsigned int) cannot truncate any existing big-int math.  See
   crane-extraction-gotchas: verified zero BinNat/BinPos/ZArith use in the
   decrypt graph.  We import [BinInt] (just the [Z] type + Z_scope) for the
   ReaderGlyph coordinate args; we deliberately do NOT [Require Import ZArith]
   — its nat [leb]/[ltb] re-exports shadow the unqualified PrimInt63 ones the
   decrypt modules rely on (BinInt's are all qualified [Z.leb], so safe). *)
From Stdlib Require Import BinInt.
From Crane Require Import Mapping.ZInt.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.

Open Scope pstring_scope.

(* ---- The brE effect ------------------------------------------------- *)

Inductive brE : Type -> Type :=
(* DOM *)
| DomGetText    : string -> brE string          (* element textContent *)
| DomSetText    : string -> string -> brE unit  (* set textContent (safe) *)
| DomSetHtml    : string -> string -> brE unit   (* set innerHTML (escaped only) *)
| DomShow       : string -> brE unit
| DomHide       : string -> brE unit
| DomPathSlug   : brE string                      (* location.pathname last seg *)
| RenderLatexCanvas : string -> Z -> Z -> brE Z
(* sessionStorage *)
| SsGet         : string -> brE string
| SsSet         : string -> string -> brE unit
| SsRemove      : string -> brE unit
(* IndexedDB *)
| IdbGetAll     : string -> brE string             (* store -> JSON array str *)
| IdbPut        : string -> string -> brE string   (* store, json record -> "1"/"" *)
(* WebAuthn.  The ceremony POLICY (which COSE algs to offer, resident-key /
   user-verification requirements, timeouts) is supplied by the caller as
   ARGUMENTS — it lives in BrowserPolicy.v (reviewable ROCQ), NOT in the shim.
   alg_csv is the comma-joined offered-algorithm list (the shim splits it and
   maps each token to a pubKeyCredParams entry); rk/uv are the residentKey /
   userVerification strings; timeout is in ms.  See BrowserPolicy.v for why
   (the residentKey:'required' thin-shim contract-violation bug). *)
| WaCreate      : string -> string -> string ->
                  string -> string -> string -> int -> brE string
                  (* challenge, rp, disp, alg_csv, residentKey, uv, timeout -> credId hex/"" *)
| WaGet         : string -> string -> string -> int -> brE string
                  (* credIdHex, challenge, uv, timeout -> "1"/"" *)
(* CSPRNG *)
| RandomBytes   : int -> brE string
(* keepalive click re-entry (binding only) *)
| BindInvoke    : string -> brE unit              (* arm a button to re-run main *)
| ActionFlag    : brE string                       (* read-and-clear the click flag *)
(* Verified-Reader canvas (Wave 1).  ReaderBegin initialises the 2D context of
   the canvas with the given id (font/colour/clear + stashes ctx+scale); each
   ReaderGlyph paints one glyph (codepoint [cp]) at pen (x,y) in sp.  The args
   are [Z] (= Typeset [sp]) for the coordinates, realized as int64 via ZInt. *)
| ReaderBegin   : string -> Z -> brE unit         (* canvas id, total height (sp) -> init+size 2D ctx *)
| ReaderGlyph   : Z -> Z -> int -> brE unit       (* x_sp, y_sp, codepoint -> fillText *)
(* ReaderStyle selects the font (and scale id) for subsequent ReaderGlyph
   calls: 0=body serif 10pt, 1..6 = h1..h6 (sizes matched to the ROCQ
   heading_k table in DecryptApp.v), 7 = monospace code.  The ROCQ side
   scales the quad coordinates by heading_k for the same id, so size and
   spacing stay consistent. *)
| ReaderStyle   : int -> brE unit                 (* font style id *)
(* Key directory (public Cloudflare Worker + KV; see EnrollApp.keydir_url).
   RegKey posts the reader's fresh public key so the author can encrypt to
   the reader by the short ID alone.  url = full directory endpoint,
   body = JSON {"kid", "pubkey"} chosen by ROCQ (EnrollApp.v) -> "1"/"". *)
| RegKey        : string -> string -> brE string. (* url, JSON body -> "1"/"" *)

(* ---- Smart constructors (mirror IODefs.v's [print]/[read] style) ---- *)

Definition dom_get_text {E} `{brE -< E} (id : string) : itree E string :=
  embed (DomGetText id).
Definition dom_set_text {E} `{brE -< E} (id text : string) : itree E unit :=
  embed (DomSetText id text).
Definition dom_set_html {E} `{brE -< E} (id html : string) : itree E unit :=
  embed (DomSetHtml id html).
Definition dom_show {E} `{brE -< E} (id : string) : itree E unit :=
  embed (DomShow id).
Definition dom_hide {E} `{brE -< E} (id : string) : itree E unit :=
  embed (DomHide id).
Definition dom_path_slug {E} `{brE -< E} : itree E string :=
  embed DomPathSlug.

Definition ss_get {E} `{brE -< E} (key : string) : itree E string :=
  embed (SsGet key).
Definition ss_set {E} `{brE -< E} (key value : string) : itree E unit :=
  embed (SsSet key value).
Definition ss_remove {E} `{brE -< E} (key : string) : itree E unit :=
  embed (SsRemove key).

Definition idb_get_all {E} `{brE -< E} (store : string) : itree E string :=
  embed (IdbGetAll store).
Definition idb_put {E} `{brE -< E} (store record : string) : itree E string :=
  embed (IdbPut store record).

Definition wa_create {E} `{brE -< E}
  (challenge rp disp alg_csv residentKey uv : string) (timeout : int)
  : itree E string :=
  embed (WaCreate challenge rp disp alg_csv residentKey uv timeout).
Definition wa_get {E} `{brE -< E}
  (cred_id challenge uv : string) (timeout : int) : itree E string :=
  embed (WaGet cred_id challenge uv timeout).

Definition random_bytes_e {E} `{brE -< E} (n : int) : itree E string :=
  embed (RandomBytes n).

Definition bind_invoke {E} `{brE -< E} (id : string) : itree E unit :=
  embed (BindInvoke id).
Definition action_flag {E} `{brE -< E} : itree E string :=
  embed ActionFlag.

Definition reader_begin {E} `{brE -< E} (id : string) (h : Z) : itree E unit :=
  embed (ReaderBegin id h).
Definition reader_glyph {E} `{brE -< E} (x y : Z) (cp : int) : itree E unit :=
  embed (ReaderGlyph x y cp).
Definition reader_style {E} `{brE -< E} (s : int) : itree E unit :=
  embed (ReaderStyle s).
Definition render_latex_canvas {E} `{brE -< E} (latex : string) (x y : Z) : itree E Z :=
  embed (RenderLatexCanvas latex x y).

Definition reg_key {E} `{brE -< E} (url body : string) : itree E string :=
  embed (RegKey url body).

(* ---- The browser IO monad ------------------------------------------- *)

(* As in Logic.v / IoEffects.v, [BIO] is a [Notation] (not a [Definition]) so it
   unfolds at extraction time, preserving Crane's monad-table dispatch. *)
Notation BIO := (itree brE).

(* ---- Crane C++ extraction for brE ----------------------------------- *)

(* Positional mapping of the constructors, in declaration order.  Each maps to
   an inline EM_ASM-backed wrapper in browser_helpers.h.  unit-returning ops
   are realized by functions returning std::monostate (Crane's [unit]); Crane
   applies the arg list positionally. *)
Crane Extract Inductive brE => ""
  [ "dom_get_text(%a0)"
    "dom_set_text(%a0, %a1)"
    "dom_set_inner_html(%a0, %a1)"
    "dom_show(%a0)"
    "dom_hide(%a0)"
    "dom_path_slug(std::monostate{})"
    "render_latex_canvas(%a0, (int64_t)%a1, (int64_t)%a2)"
    "ss_get(%a0)"
    "ss_set(%a0, %a1)"
    "ss_remove(%a0)"
    "idb_get_all(%a0)"
    "idb_put(%a0, %a1)"
    "webauthn_create(%a0, %a1, %a2, %a3, %a4, %a5, (int)(%a6))"
    "webauthn_get(%a0, %a1, %a2, (int)(%a3))"
    "random_bytes((int)(%a0))"
    "bind_invoke(%a0)"
    "crane_action_flag(std::monostate{})"
    "reader_begin(%a0, (double)%a1)"
    "reader_glyph((double)%a0, (double)%a1, (int)%a2)"
    "reader_style((int)%a0)"
    "keydir_register(%a0, %a1)" ]
  From "browser_helpers.h".

Crane Extract Inlined Constant render_latex_canvas =>
  "render_latex_canvas(%a0, (int64_t)%a1, (int64_t)%a2)" From "browser_helpers.h".

Crane Extract Inlined Constant dom_get_text =>
  "dom_get_text(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant dom_set_text =>
  "dom_set_text(%a0, %a1)" From "browser_helpers.h".
Crane Extract Inlined Constant dom_set_html =>
  "dom_set_inner_html(%a0, %a1)" From "browser_helpers.h".
Crane Extract Inlined Constant dom_show =>
  "dom_show(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant dom_hide =>
  "dom_hide(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant dom_path_slug =>
  "dom_path_slug(std::monostate{})" From "browser_helpers.h".
Crane Extract Inlined Constant ss_get =>
  "ss_get(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant ss_set =>
  "ss_set(%a0, %a1)" From "browser_helpers.h".
Crane Extract Inlined Constant ss_remove =>
  "ss_remove(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant idb_get_all =>
  "idb_get_all(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant idb_put =>
  "idb_put(%a0, %a1)" From "browser_helpers.h".
Crane Extract Inlined Constant wa_create =>
  "webauthn_create(%a0, %a1, %a2, %a3, %a4, %a5, (int)(%a6))" From "browser_helpers.h".
Crane Extract Inlined Constant wa_get =>
  "webauthn_get(%a0, %a1, %a2, (int)(%a3))" From "browser_helpers.h".
Crane Extract Inlined Constant random_bytes_e =>
  "random_bytes((int)(%a0))" From "browser_helpers.h".
Crane Extract Inlined Constant bind_invoke =>
  "bind_invoke(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant action_flag =>
  "crane_action_flag(std::monostate{})" From "browser_helpers.h".
Crane Extract Inlined Constant reader_begin =>
  "reader_begin(%a0, (double)%a1)" From "browser_helpers.h".
Crane Extract Inlined Constant reader_glyph =>
  "reader_glyph((double)%a0, (double)%a1, (int)%a2)" From "browser_helpers.h".
Crane Extract Inlined Constant reader_style =>
  "reader_style((int)%a0)" From "browser_helpers.h".

Crane Extract Inlined Constant reg_key =>
  "keydir_register(%a0, %a1)" From "browser_helpers.h".
