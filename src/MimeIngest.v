(* MimeIngest.v — pure inbound MIME parse for the SMTP listener.

   Mirrors smtp/listener.py's [_header] and [_plain_body]: extract the Subject
   (newlines collapsed to spaces, trimmed; "Untitled" fallback), the
   X-Crane-Public-Keys header, and a plain-text body.

   Body extraction mirrors [_plain_body]'s preference order:
     1. if the message is multipart, concatenate the bodies of every non-
        attachment text/* part (joined by a blank line), preferring text/plain;
     2. otherwise the body is the bytes after the header/body split, decoded
        per Content-Transfer-Encoding (base64 / quoted-printable / identity).

   Reuses StringLib.v, MimeLib.v (header/body split, header parse, boundary
   extract) and MimeBuild.v (multipart splitter, base64/ws helpers).  Crypto-
   free: base64 *decode* of bodies is done via a local table here so MimeIngest
   need not import CryptoSpec (the SMTP server imports both anyway, but keeping
   the dependency minimal mirrors MimeBuild's crypto-free stance). *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.
Require Import MimeLib.
Require Import MimeBuild.
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* ---- header value sanitisation (mirror _header) -------------------- *)
(* Replace CR and LF with spaces, then trim.  Used for the Subject line so a
   folded/multiline subject becomes a single frontmatter-safe line. *)
Fixpoint flatten_ws_aux (s : string) (pos : int) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then ""
      else
        let c := PrimString.get s pos in
        let c' := if orb (int_eqb c ch_cr) (int_eqb c ch_newline) then ch_space else c in
        cat (PrimString.make 1%int63 c') (flatten_ws_aux s (add pos 1%int63) f')
  end.
Definition flatten_ws (s : string) : string := flatten_ws_aux s 0%int63 mime_fuel.

Definition header_value (key : string) (hdrs : list (string * string))
                        (fallback : string) : string :=
  let v := header_lookup key hdrs in
  if is_empty v then fallback else trim (flatten_ws v).

(* ---- Content-Transfer-Encoding decode ------------------------------ *)
(* Local base64 decoder (table-driven; ignores whitespace; "" on invalid) so
   this module stays independent of CryptoSpec.  Matches crypto_helpers.h's
   base64_decode contract. *)
Definition b64_val (c : int) : int :=
  if andb (leb 65%int63 c) (leb c 90%int63) then sub c 65%int63              (* A-Z -> 0..25 *)
  else if andb (leb 97%int63 c) (leb c 122%int63) then add (sub c 97%int63) 26%int63  (* a-z -> 26..51 *)
  else if andb (leb 48%int63 c) (leb c 57%int63) then add (sub c 48%int63) 52%int63   (* 0-9 -> 52..61 *)
  else if int_eqb c 43%int63 then 62%int63                                   (* + *)
  else if int_eqb c 47%int63 then 63%int63                                   (* / *)
  else 255%int63.                                                            (* invalid/skip *)

(* Fold base64 chars into output bytes carrying (acc, nbits).  We process the
   pre-stripped (whitespace/'='-free) string. *)
Fixpoint b64_decode_aux (s : string) (pos acc nbits : int) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then ""
      else
        let c := PrimString.get s pos in
        let v := b64_val c in
        if leb 64%int63 v then b64_decode_aux s (add pos 1%int63) acc nbits f'  (* skip invalid *)
        else
          let acc' := lor (lsl acc 6%int63) v in
          let nb' := add nbits 6%int63 in
          if leb 8%int63 nb' then
            let nb2 := sub nb' 8%int63 in
            let byte := land (lsr acc' nb2) 255%int63 in
            cat (PrimString.make 1%int63 byte)
                (b64_decode_aux s (add pos 1%int63) acc' nb2 f')
          else b64_decode_aux s (add pos 1%int63) acc' nb' f'
  end.

Definition b64_decode (s : string) : string :=
  b64_decode_aux (strip_ws s) 0%int63 0%int63 0%int63 mime_fuel.

(* Decode a part body per its Content-Transfer-Encoding header value. *)
Definition decode_body (cte body : string) : string :=
  let e := downcase (trim cte) in
  if string_eqb e "base64" then b64_decode body
  else body.   (* 7bit / 8bit / binary / quoted-printable(ascii) -> as-is *)

(* ---- content-type helpers ------------------------------------------ *)
Definition ct_is_text (ct : string) : bool :=
  orb (starts_with (downcase ct) "text/plain")
      (starts_with (downcase ct) "text/html").
Definition ct_is_plain (ct : string) : bool :=
  starts_with (downcase ct) "text/plain".
Definition is_multipart_ct (ct : string) : bool :=
  starts_with (downcase ct) "multipart/".

(* A part is an attachment iff its Content-Disposition starts with "attachment". *)
Definition is_attachment (phdrs : list (string * string)) : bool :=
  starts_with (downcase (header_lookup "Content-Disposition" phdrs)) "attachment".

(* ---- multipart body collection ------------------------------------- *)
(* Collect the decoded text of each non-attachment text/* part.  We make two
   passes so text/plain parts win (mirrors preferencelist=("plain","html")):
   first gather plain parts; if any, use them, else gather html parts. *)

Fixpoint collect_text_parts (parts : list string) (want_plain : bool) : list string :=
  match parts with
  | [] => []
  | part :: rest =>
      let part' := trim_part_terminator part in
      let '(ph, pb) := split_headers_body2 part' in
      let phdrs := parse_headers ph in
      let ct := header_lookup "Content-Type" phdrs in
      let cte := header_lookup "Content-Transfer-Encoding" phdrs in
      let keep :=
        andb (negb (is_attachment phdrs))
             (if want_plain then ct_is_plain ct else ct_is_text ct) in
      if keep then decode_body cte pb :: collect_text_parts rest want_plain
      else collect_text_parts rest want_plain
  end.

(* Join parts with a blank line between them (mirror "\n\n".join). *)
Fixpoint join_blank (xs : list string) : string :=
  match xs with
  | [] => ""
  | [x] => x
  | x :: rest => cat x (cat (cat lf lf) (join_blank rest))
  end.

(* ---- top-level body extraction ------------------------------------- *)

Definition ingest_body (hdrs : list (string * string)) (body : string) : string :=
  let ct := header_lookup "Content-Type" hdrs in
  if is_multipart_ct ct then
    let boundary := extract_boundary ct in
    let parts := split_parts body boundary in
    let plain := collect_text_parts parts true in
    match plain with
    | _ :: _ => join_blank plain
    | [] => join_blank (collect_text_parts parts false)
    end
  else
    (* single part: decode the body per the top-level CTE. *)
    decode_body (header_lookup "Content-Transfer-Encoding" hdrs) body.

(* ---- the full inbound parse ---------------------------------------- *)

Record ingested : Type := MkIngest {
  in_subject     : string;
  in_body        : string;
  in_public_keys : string;
}.

Definition ingest (raw : string) : ingested :=
  let '(hblock, body) := split_headers_body2 raw in
  let hdrs := parse_headers hblock in
  MkIngest
    (header_value "Subject" hdrs "Untitled")
    (ingest_body hdrs body)
    (header_value "X-Crane-Public-Keys" hdrs "").
