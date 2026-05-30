(* DomFFI.v — browser DOM primitives, REWRITTEN for Facet A.

   The old js_of_ocaml realization ([Extraction Language OCaml] +
   [Extract Constant => "Dom_ffi.*"], compiled to JS and linked against
   crane_bridge.js) is gone.  The DOM is now a set of [brE] effects in
   BrowserEffect.v (DomGetText / DomSetText / DomSetHtml / DomShow / DomHide /
   DomPathSlug), realized by EM_ASM wrappers in src/browser_helpers.h and run
   inside the WASM module via Asyncify where needed.

   This module is kept as the *documented home* of the DOM FFI boundary (C3) and
   provides standalone (non-itree) axioms + their From-clause Crane directives
   for any pure helper that wants a direct DOM call.  DecryptApp.v / EnrollApp.v
   use the [brE] effects, not these axioms, but re-issuing the directives here is
   harmless (Crane applies the last directive registered for a constant) and
   documents the seam.

   Safety (T1): untrusted decrypted text is written only via set_text_content
   (textContent); set_inner_html receives only ROCQ-escaped HTML
   (InnerMime.body_to_html escapes amp, lt, gt, dquote). *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std.
Require Import StringLib.

Open Scope pstring_scope.

Axiom el_text          : string -> string.        (* element textContent *)
Axiom set_text_content : string -> string -> unit. (* set textContent (safe) *)
Axiom set_inner_html   : string -> string -> unit. (* set innerHTML (escaped only) *)
Axiom show_el          : string -> unit.
Axiom hide_el          : string -> unit.

(* ---- Crane C++ extraction (browser_helpers.h; no OpenSSL) ---------- *)

Crane Extract Inlined Constant el_text =>
  "dom_get_text(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant set_text_content =>
  "dom_set_text(%a0, %a1)" From "browser_helpers.h".
Crane Extract Inlined Constant set_inner_html =>
  "dom_set_inner_html(%a0, %a1)" From "browser_helpers.h".
Crane Extract Inlined Constant show_el =>
  "dom_show(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant hide_el =>
  "dom_hide(%a0)" From "browser_helpers.h".
