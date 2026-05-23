(* Decrypt.v — Compatibility shim for the browser-side MIME envelope
   parser.  All MIME parsing functions (split_headers_body, parse_headers,
   extract_boundary, split_multipart, trim_part_terminator, header_lookup)
   now live in MimeLib.v with fixes for C1, H5, and M4.

   This file re-exports MimeLib for any code that previously required
   Decrypt.v.  The browser-side OCaml (static/decrypt.ml) and the new
   extraction pipeline use MimeLib.v directly. *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.
Require Import MimeLib.

Open Scope pstring_scope.

(* Fuel constant kept for backward compatibility with any code that
   references [Decrypt.fuel].  Equivalent to MimeLib's [mime_fuel]. *)
Definition fuel : nat := mime_fuel.
