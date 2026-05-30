(* BridgeFFI.v — browser marshalling + keepalive shims for the WASM apps.

   REWRITTEN for Facet A: the old js_of_ocaml [Extract Constant => "Bridge_ffi.*"]
   directives (compiled OCaml + crane_bridge.js) are gone.  This module now hosts
   the small, *non-effect* marshalling and click-binding axioms shared by
   DecryptApp.v / EnrollApp.v, realized by EM_ASM wrappers in
   src/browser_helpers.h:

     - json_array_len / json_array_field : project fields out of an IndexedDB
       getAll() JSON-array string (the ROCQ side does all record matching);
     - json_object4 : assemble an idb_put record JSON string.

   The DOM / sessionStorage / IndexedDB / WebAuthn / RNG *effects* — and the
   keepalive click re-entry (bind_invoke / action_flag) — live in
   BrowserEffect.v ([brE]); the nine crypto primitives in BrowserCrypto.v.  None
   of these directives carries a [From "crypto_helpers.h"] clause — browser
   builds must never pull OpenSSL (crane-extraction-gotchas). *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd.

Open Scope pstring_scope.

(* ---- JSON marshalling over IndexedDB getAll() strings -------------- *)

Axiom json_array_len : string -> int.
(* Number of records in a JSON array string ("[]" or malformed -> 0). *)

Axiom json_array_field : string -> int -> string -> string.
(* String field [f] of the [i]-th element of a JSON array string; nested object
   values (e.g. privkeyJwk) are re-stringified.  "" if absent. *)

Axiom json_object4 :
  string -> string -> string -> string ->
  string -> string -> string -> string -> string.
(* Assemble {k0:v0, ..., k3:v3} skipping empty keys; for idb_put records. *)

(* ---- Crane C++ extraction (browser_helpers.h, From-clauses only for the
        single Emscripten-only header — never crypto_helpers.h) ---------- *)

Crane Extract Inlined Constant json_array_len =>
  "json_array_len(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant json_array_field =>
  "json_array_field(%a0, (int)(%a1), %a2)" From "browser_helpers.h".
Crane Extract Inlined Constant json_object4 =>
  "json_object4(%a0, %a1, %a2, %a3, %a4, %a5, %a6, %a7)" From "browser_helpers.h".
