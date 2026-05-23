(* DomFFI.v — Axiomatized DOM manipulation primitives.
   These axioms model the browser-side DOM API used by decrypt.ml
   and enroll.ml.  Extracted to OCaml via standard Coq extraction,
   then compiled to JavaScript by js_of_ocaml.

   Safety: all text-insertion goes through textContent (not innerHTML)
   to prevent XSS via attacker-controlled post content. *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.

Open Scope pstring_scope.

Axiom el_by_id : string -> string.
(* Get element by ID.  Returns element reference as a tag string.
   Extraction: Js.Unsafe.get_by_id *)

Axiom set_text_content : string -> string -> unit.
(* Set textContent of element.  Safe — no HTML parsing. *)

Axiom set_inner_html : string -> string -> unit.
(* Set innerHTML of element.  Only used for body_to_html output
   which strips all HTML from the decrypted markdown. *)

Axiom show_el : string -> unit.
(* Set element display style to "block". *)

Axiom hide_el : string -> unit.
(* Set element display style to "none". *)

Axiom el_text : string -> string.
(* Get textContent of element. *)

Axiom el_value : string -> string.
(* Get value property of input element. *)

Axiom add_event_listener : string -> string -> (unit -> unit) -> unit.
(* Attach an event listener to an element.  The string is the event
   type (e.g. "click"). *)

(* Extraction to js_of_ocaml externals:
   These axioms map to thin OCaml wrapper functions that call
   js_of_ocaml's Dom and Dom_html modules. *)

Extraction Language OCaml.

Extract Constant el_by_id           => "Dom_ffi.el_by_id".
Extract Constant set_text_content   => "Dom_ffi.set_text_content".
Extract Constant set_inner_html     => "Dom_ffi.set_inner_html".
Extract Constant show_el            => "Dom_ffi.show_el".
Extract Constant hide_el            => "Dom_ffi.hide_el".
Extract Constant el_text            => "Dom_ffi.el_text".
Extract Constant el_value           => "Dom_ffi.el_value".
Extract Constant add_event_listener => "Dom_ffi.add_event_listener".
