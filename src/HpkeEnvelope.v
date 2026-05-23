(* HpkeEnvelope.v — HPKE MIME envelope parsing and construction.
   Ports the OCaml logic from encrypt_post.ml (build_hpke_envelope) and
   decrypt.ml (parse_hpke_envelope) into a single Rocq specification.

   Uses MimeLib.v for MIME parsing and StringLib.v for string
   operations.  Extracted to OCaml for both CLI tools and browser. *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.
Require Import MimeLib.
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* ---- Envelope fields ----------------------------------------------- *)

Record hpke_envelope := mkHpkeEnvelope {
  env_public_keys : string;          (* comma-separated key IDs *)
  env_wraps : list (string * string * string);
    (* list of (key_id, ek_hex, wrapped_hex) *)
  env_ct_b64 : string               (* base64-encoded ciphertext package *)
}.

(* ---- Parse HPKE envelope from .eml body --------------------------- *)

Definition parse_hpke_envelope (eml_body : string) : hpke_envelope :=
  let '(hdrs_block, body) := split_headers_body eml_body in
  let hdrs := parse_headers hdrs_block in
  let ct := header_lookup "Content-Type" hdrs in
  let boundary := extract_boundary ct in
  if is_empty boundary then {| env_public_keys := ""; env_wraps := []; env_ct_b64 := "" |}
  else
    let parts := split_multipart (trim body) (cat "--" boundary) (cat "--" boundary "--") in
    let wraps_ref := "" in
    let ct_ref := "" in
    let _ := fold_parts parts hdrs wraps_ref ct_ref in
    {|
      env_public_keys := header_lookup "Public-Keys" hdrs;
      env_wraps := parse_wraps_entry wraps_ref;
      env_ct_b64 := ct_ref
    |}.

Fixpoint fold_parts (parts : list string) (hdrs : list (string * string))
  (wraps_acc ct_acc : string) : string * string :=
  match parts with
  | [] => (wraps_acc, ct_acc)
  | part :: rest =>
      let part' := trim_part_terminator part in
      let '(ph, pb) := split_headers_body part' in
      let phdrs := parse_headers ph in
      let pct := header_lookup "Content-Type" phdrs in
      if string_eqb pct "application/wrapped-keys" then
        let wraps_val := header_lookup "Wraps" phdrs in
        fold_parts rest hdrs wraps_val ct_acc
      else if starts_with pct "application/aes-gcm" then
        let cte := header_lookup "Content-Transfer-Encoding" phdrs in
        let pb_val := trim pb in
        fold_parts rest hdrs wraps_acc pb_val
      else
        fold_parts rest hdrs wraps_acc ct_acc
  end.

(* Parse the comma-separated wraps line into a list of
   (key_id, ek_hex, wrapped_hex) triples.  This is a simplified
   version; the OCaml extraction uses String.split_on_char for
   efficiency. *)

Fixpoint parse_wraps_entries_aux (s : string) (pos : int) (fuel : nat) : list string :=
  match fuel with
  | O => []
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then []
      else
        let comma_pos := find_char s ch_comma pos mime_fuel in
        let entry := trim (PrimString.sub s pos (sub comma_pos pos)) in
        entry :: parse_wraps_entries_aux s (add comma_pos 1%int63) f'
  end.

(* Split a wraps entry "keyid:ekhex:wrappedhex" into components *)
Fixpoint split_colon_entry (s : string) (pos : int) (fuel : nat) : list string :=
  match fuel with
  | O => []
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then []
      else
        let colon_pos := find_char s ch_colon pos mime_fuel in
        let piece := PrimString.sub s pos (sub colon_pos pos) in
        piece :: split_colon_entry s (add colon_pos 1%int63) f'
  end.

Definition parse_wraps_entry (wraps_line : string) : list (string * string * string) :=
  let entries := parse_wraps_entries_aux wraps_line 0%int63 mime_fuel in
  let rec go (e : list string) : list (string * string * string) :=
    match e with
    | [] => []
    | s :: rest =>
        let parts := split_colon_entry s 0%int63 16%nat in
        match parts with
        | [kid; ek_hex; w_hex] => (trim kid, trim ek_hex, trim w_hex) :: go rest
        | _ => []
        end
    end
  in
  go entries.

(* ---- Build HPKE envelope (simplified — OCaml performs IO) --------- *)

(* Construct the outer HPKE MIME envelope.  This is a pure function
   that builds the string representation; key generation and AES-GCM
   encryption happen at the call site.

   Parameters:
   - public_keys: list of (key_id, hex_pubkey) for the Public-Keys header
   - wrapped_entries: list of (key_id, ek_hex, wrapped_hex) for the wraps part
   - ct_package_b64: base64-encoded ciphertext package
   - boundary: MIME boundary string *)
Definition build_hpke_envelope
  (public_keys : list string)
  (wrapped_entries : list (string * string * string))
  (ct_package_b64 : string)
  (boundary : string) : string :=
  let pkeys_line :=
    let rec join (ks : list string) : string :=
      match ks with
      | [] => ""
      | [k] => k
      | k :: rest => cat k (cat ", " (join rest))
      end
    in join public_keys
  in
  let wraps_line :=
    let rec join_wraps (es : list (string * string * string)) : string :=
      match es with
      | [] => ""
      | [(k, ek, w)] => cat k (cat ":" (cat ek (cat ":" w)))
      | (k, ek, w) :: rest =>
          cat k (cat ":" (cat ek (cat ":" (cat w (cat ", " (join_wraps rest))))))
      end
    in join_wraps wrapped_entries
  in
  cat "Subject: ..." (cat "\r\n"
  (cat "MIME-Version: 1.0" (cat "\r\n"
  (cat "Public-Keys: " (cat pkeys_line (cat "\r\n"
  (cat "Content-Type: multipart/hpke+wrapped; boundary=\"" (cat boundary (cat "\"" (cat "\r\n"
  (cat "\r\n"
  (cat "This is an HPKE encrypted message for Crane Blog readers." (cat "\r\n"
  (cat "\r\n"
  (cat "--" (cat boundary (cat "\r\n"
  (cat "Content-Type: application/wrapped-keys" (cat "\r\n"
  (cat "Wraps: " (cat wraps_line (cat "\r\n"
  (cat "\r\n"
  (cat "--" (cat boundary (cat "\r\n"
  (cat "Content-Type: application/aes-gcm" (cat "\r\n"
  (cat "Content-Transfer-Encoding: base64" (cat "\r\n"
  (cat "\r\n"
  (cat ct_package_b64 (cat "\r\n"
  (cat "\r\n"
  (cat "--" (cat boundary "--" (cat "\r\n"
  ""))))))))))))))))))))))))))))))))))).
