(* PublicEnvelope.v — shared PUBLIC (keyless) envelope detection for the CLI
   and browser decryptors (feature 2).

   Single source of truth for the two envelope-kind predicates that BOTH
   DecryptPost.v (native CLI) and DecryptApp.v (browser WASM) need, so the
   M1/A4 byte-contract can never drift between the two decryptors:

     is_public_eml    — the OUTER Public-Keys header value is exactly "*"
                        (after trim); mirrors Recipients.is_public_marker at
                        the envelope level (D3).
     find_public_body — recover the application/x-crane-public part body with
                        EXACTLY ONE trim (split_headers_body2 on the RAW part,
                        then trim_part_terminator once), restoring the exact
                        build_inner_mime bytes the encrypt side signed
                        (canonical parse contract, A4/M1).

   The Examples are machine-checked eq_refl pins (house style): detection is
   exact, an encrypted envelope has no public body, and the single-trim
   contract restores byte identity. *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Stdlib Require Import Lists.List.
Import ListNotations.

Require Import StringLib.
Require Import MimeLib.
Require Import MimeBuild.   (* crlf, outer_boundary, split_parts, split_headers_body2, concat_all *)

Open Scope pstring_scope.

(* True iff the outer Public-Keys header value is EXACTLY "*" after trim
   (D3).  Read from the RAW envelope via the canonical
   split_headers_body2 -> parse_headers contract, so detection never depends
   on how the parts were split. *)
Definition is_public_eml (eml : string) : bool :=
  let '(hdrs_block, _body) := split_headers_body2 eml in
  let hdrs := parse_headers hdrs_block in
  string_eqb (trim (header_lookup "Public-Keys" hdrs)) "*".

(* The public body part: the part whose Content-Type starts with
   application/x-crane-public.  EXACTLY ONE trim (A4/M1 canonical parse
   contract): split the headers off the RAW part (NO pre-trim — a
   split_headers_body2 (trim_part_terminator part) double-trim would strip
   the inner MIME's own final CRLF and break byte identity with what the
   encrypt side signed), then trim_part_terminator the part body once to
   strip exactly the writer's wire CRLF, restoring the exact
   build_inner_mime bytes.  Tail-recursive in the find_wraps / find_ct_b64
   shape (check-tail-position.sh accepts this form).  "" when absent. *)
Fixpoint find_public_body (parts : list string) : string :=
  match parts with
  | nil => ""
  | part :: rest =>
      let '(ph, pb) := split_headers_body2 part in
      let phdrs := parse_headers ph in
      let pct := header_lookup "Content-Type" phdrs in
      if starts_with pct "application/x-crane-public"
      then trim_part_terminator pb
      else find_public_body rest
  end.

(* ---- machine-checked pins (A4/M1, eq_refl house style) ------------- *)

(* A public envelope is detected as such; an encrypted one is not. *)
Example is_public_eml_public :
  is_public_eml (build_public_outer_envelope "INNER" "SIG" "PK") = true := eq_refl.

Example is_public_eml_encrypted :
  is_public_eml (build_outer_envelope ("kid1" :: nil) (("kid1", "ek", "w") :: nil)
                                     "CTB64" "SIG" "PK") = false := eq_refl.

(* M1/A4 byte identity: the recovered body of the wire part (inner MIME +
   the writer's one wire CRLF) is EXACTLY the inner MIME the encrypt side
   signed — one trim strips the wire terminator, and a second trim would
   over-strip.  The inner MIME below ends in CRLF (like every real
   build_inner_mime, which ends "--=_cb_inner_0_=--\r\n"); the assertion
   pins that find_public_body returns the full "INNER\r\n", NOT "INNER". *)
Example find_public_body_roundtrip :
  find_public_body
    (split_parts
      (concat_all (
         "This is an HPKE encrypted message for Crane Blog readers." :: crlf ::
         cat "--" (cat outer_boundary crlf) ::
         "Content-Type: application/x-crane-public" :: crlf ::
         "Content-Transfer-Encoding: 8bit" :: crlf ::
         crlf ::
         (cat "INNER" crlf) :: crlf ::
         cat "--" (cat outer_boundary (cat "--" crlf)) :: nil))
      outer_boundary)
  = cat "INNER" crlf := eq_refl.

(* A plain (no trailing-CRLF) body round-trips identically. *)
Example find_public_body_roundtrip_plain :
  find_public_body
    (split_parts
      (concat_all (
         "This is an HPKE encrypted message for Crane Blog readers." :: crlf ::
         cat "--" (cat outer_boundary crlf) ::
         "Content-Type: application/x-crane-public" :: crlf ::
         "Content-Transfer-Encoding: 8bit" :: crlf ::
         crlf ::
         "INNER" :: crlf ::
         cat "--" (cat outer_boundary (cat "--" crlf)) :: nil))
      outer_boundary)
  = "INNER" := eq_refl.

(* An encrypted envelope's parts carry no public body — "" (absent). *)
Example find_public_body_absent :
  find_public_body
    (split_parts
      (concat_all (
         "This is an HPKE encrypted message for Crane Blog readers." :: crlf ::
         cat "--" (cat outer_boundary crlf) ::
         "Content-Type: application/wrapped-keys" :: crlf ::
         "Wraps: kid1:ek:w" :: crlf ::
         crlf ::
         cat "--" (cat outer_boundary crlf) ::
         "Content-Type: application/aes-gcm" :: crlf ::
         "Content-Transfer-Encoding: base64" :: crlf ::
         crlf ::
         "CTB64" ::
         cat "--" (cat outer_boundary (cat "--" crlf)) :: nil))
      outer_boundary)
  = "" := eq_refl.
