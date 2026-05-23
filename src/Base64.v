(* Base64.v — Base64 encode/decode.
   Both are axiomatic; the OCaml/JS backends use optimized libraries
   (Base64 opam package, browser builtins).

   TODO: Implement decode in pure Rocq for verifiability.  The encode
   can remain axiomatic for performance.

   Extracted to OCaml via standard Coq extraction. *)

From Corelib Require Import PrimString PrimInt63.

Open Scope pstring_scope.

Axiom base64_encode : string -> string.
(* Encode arbitrary bytes to base64 ascii (no line wrapping). *)

Axiom base64_decode : string -> string.
(* Decode base64 ascii to bytes.  Returns empty string on parse error. *)

Extract Constant base64_encode => "Crane_crypto.base64_encode".
Extract Constant base64_decode => "Crane_crypto.base64_decode".
