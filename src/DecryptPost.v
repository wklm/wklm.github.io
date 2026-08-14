(* DecryptPost.v — the [decrypt_post] CLI tool, authored in ROCQ and extracted
   to C++23 via Crane.  Replaces the hand-written tools/decrypt_post.ml.

   Inverse of EncryptPost.v:
     - read posts-encrypted/<slug>.eml; parse the outer multipart/hpke+wrapped
       envelope (Wraps triples + base64 ciphertext part);
     - load the 32-byte private scalar from CRANE_BLOG_PRIVATE_KEY (hex; only
       needed for encrypted envelopes — public ones skip key resolution);
     - unwrap the CEK (AAD = kid) from the first wrap that succeeds; decrypt
       the body (AAD = slug);
     - OR, when the envelope is PUBLIC (outer Public-Keys header is "*"),
       verify
       sha256(sign_info_public || slug || normalize_crlf inner_mime) against
       the trusted signing key and recover the inner MIME from the
       application/x-crane-public part (feature 2);
     - parse the recovered inner multipart/mixed: write the markdown to
       posts/<slug>.md (exactly one trailing newline) and each attachment to
       posts/<filename> (base64-decoded);
     - print "Decrypted <eml> -> posts/<slug>.md" (encrypted) or
       "Verified public post <eml> -> posts/<slug>.md" (public) to stdout.

   Paths are CWD-relative (test-roundtrip.sh runs from the repo root). *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree Monads.IO Monads.Dir.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.
From Stdlib Require Import Lists.List.
Import ListNotations.

Require Import StringLib.
Require Import MimeLib.
Require Import MimeBuild.
Require Import CryptoSpec.
Require Import IoEffects.
Require Import PublicEnvelope.   (* is_public_eml / find_public_body — single source with DecryptApp.v *)

Open Scope pstring_scope.

(* ---- argv: first non-flag argument (the .eml path) ----------------- *)
(* The acceptance test passes no flags; --key-file <path> would consume the
   next arg, but it is unused here, so we just take the first '-'-free arg. *)
Fixpoint first_path_aux (argc : int) (i : int) (fuel : nat) : IO string :=
  match fuel with
  | O => Ret ""
  | S f' =>
      if leb argc i then Ret ""
      else
        a <- arg_get i ;;
        if is_empty a then first_path_aux argc (add i 1%int63) f'
        else if int_eqb (PrimString.get a 0%int63) 45%int63
             then first_path_aux argc (add i 1%int63) f'
             else Ret a
  end.

Definition first_path : IO string :=
  argc <- arg_count ;;
  first_path_aux argc 1%int63 64%nat.

(* ---- basename / slug ----------------------------------------------- *)

Definition has_suffix_eml (s : string) : bool :=
  let n := PrimString.length s in
  if ltb n 4%int63 then false
  else string_eqb (PrimString.sub s (sub n 4%int63) 4%int63) ".eml".

Definition slug_of_eml (path : string) : string :=
  let name := basename_of path in
  if has_suffix_eml name
  then PrimString.sub name 0%int63 (sub (PrimString.length name) 4%int63)
  else name.

(* ---- Wraps line -> (kid, ek_bytes, wrapped_bytes) triples ---------- *)
(* The Wraps header value is "kid:ekhex:whex, kid2:...".  Split on ',' then
   each entry on ':'.  hex-decode ek and wrapped here so unwrap_cek gets raw
   bytes.  Top-level helpers (no nested let fix) to avoid std::any. *)

Definition entry_to_triple (entry : string) : option (string * string * string) :=
  match split_on_char_fuel (trim entry) ch_colon 0%int63 16%nat with
  | kid :: ek :: w :: nil =>
      Some (trim kid, hex_decode (trim ek), hex_decode (trim w))
  | _ => None
  end.

Fixpoint entries_to_triples (entries : list string)
  : list (string * string * string) :=
  match entries with
  | nil => nil
  | e :: rest =>
      match entry_to_triple e with
      | Some t => t :: entries_to_triples rest
      | None => entries_to_triples rest
      end
  end.

Definition parse_wraps (wraps_line : string) : list (string * string * string) :=
  entries_to_triples (split_on_char_fuel wraps_line ch_comma 0%int63 mime_fuel).

(* ---- outer envelope parsing ---------------------------------------- *)
(* Walk the outer parts; collect the Wraps line and the aes-gcm base64 body. *)

Fixpoint find_wraps (parts : list string) : string :=
  match parts with
  | nil => ""
  | part :: rest =>
      let '(ph, _pb) := split_headers_body2 (trim_part_terminator part) in
      let phdrs := parse_headers ph in
      let pct := header_lookup "Content-Type" phdrs in
      if starts_with pct "application/wrapped-keys"
      then header_lookup "Wraps" phdrs
      else find_wraps rest
  end.

Fixpoint find_ct_b64 (parts : list string) : string :=
  match parts with
  | nil => ""
  | part :: rest =>
      let '(ph, pb) := split_headers_body2 (trim_part_terminator part) in
      let phdrs := parse_headers ph in
      let pct := header_lookup "Content-Type" phdrs in
      if starts_with pct "application/aes-gcm"
      then trim pb
      else find_ct_b64 rest
  end.

(* ---- public (keyless) envelope detection — feature 2 ---------------- *)
(* is_public_eml / find_public_body now live in PublicEnvelope.v — the
   single source of truth shared with DecryptApp.v (the M1/A4 byte-contract
   must never drift between the CLI and browser decryptors). *)

(* ---- CEK unwrap (no fallback — AAD = kid only) --------------------- *)
(* Try each wrap triple; return the first non-empty CEK ("" if none). *)
Fixpoint try_unwrap (sk : string) (triples : list (string * string * string))
  : string :=
  match triples with
  | nil => ""
  | (kid, ek, wrapped) :: rest =>
      let cek := unwrap_cek sk ek wrapped kid in
      if is_empty cek then try_unwrap sk rest else cek
  end.

(* ---- body decrypt (no fallback — AAD = slug only) ------------------ *)

(* ---- writing the recovered attachments ----------------------------- *)
(* Each attachment is (filename, raw-base64-body); decode (after stripping
   whitespace) and write to posts/<filename>. *)
Fixpoint write_attachments (atts : list (string * string)) : IO unit :=
  match atts with
  | nil => Ret tt
  | (name, b64) :: rest =>
      _ <- write_file (cat "posts/" name) (base64_decode (strip_ws b64)) ;;
      write_attachments rest
  end.

(* ---- the decrypt pipeline ------------------------------------------ *)

(* Write the recovered post out: posts/<slug>.md (exactly one trailing LF)
   and each attachment under posts/.  Shared by the encrypted and public
   branches — the inner MIME is byte-identical in both (D4).  [label]
   prefixes the stdout success line ("Decrypted " for the encrypted branch,
   "Verified public post " for the public one). *)
Definition write_recovered (label eml_path slug inner_mime : string) : IO unit :=
  let inner_parts := split_parts inner_mime inner_boundary in
  let md_part := inner_md inner_parts in
  let md := if is_empty md_part then normalize_md inner_mime else md_part in
  let atts := inner_attachments inner_parts in
  _ <- create_directory "posts" ;;
  _ <- write_file (cat "posts/" (cat slug ".md")) md ;;
  _ <- write_attachments atts ;;
  print_endline (concat_all
    (label :: eml_path :: " -> posts/" :: slug :: ".md" :: nil)).

(* [public] is computed up front from the eml we already read (M4 — no new
   param, no double read), and the kind-specific verification is dispatched
   INSIDE the signature gate (C3/A4): on a public envelope the old gate
   computed verify_post trusted_sign_pk "" sig and exited before any public
   branch could run — dead code.  The public branch verifies the canonical
   form (verify_post_public normalizes CRLF internally, matching what the
   encrypt side signs over sign_info_public || slug || normalize_crlf
   inner_mime). *)
Definition decrypt_one (eml_path sk trusted_sign_pk : string) : IO unit :=
  eml <- read eml_path ;;
  let '(hdrs_block, body) := split_headers_body2 eml in
  let hdrs := parse_headers hdrs_block in
  let ct_hdr := header_lookup "Content-Type" hdrs in
  let boundary := extract_boundary ct_hdr in
  let parts := split_parts body boundary in
  let triples := parse_wraps (find_wraps parts) in
  let ct_b64 := find_ct_b64 parts in
  let ct_package := base64_decode (strip_ws ct_b64) in
  let public := is_public_eml eml in
  let public_body := if public then find_public_body parts else "" in
  (* Signature verification *)
  let sig_hex := header_lookup "Signature" hdrs in
  let sig := hex_decode (trim sig_hex) in
  let env_sign_key_hex := header_lookup "Signing-Key" hdrs in
  let env_sign_pk := hex_decode (trim env_sign_key_hex) in
  if is_empty sig then
    _ <- eprint (concat_all ("decrypt_post: missing Signature header" :: lf :: nil)) ;;
    exit_with 1%int63
  else if negb (string_eqb (trim env_sign_key_hex) (hex_encode trusted_sign_pk)) then
    _ <- eprint (concat_all ("decrypt_post: Signing-Key mismatch with trusted key" :: lf :: nil)) ;;
    exit_with 1%int63
  else if andb public (is_empty public_body) then
    (* A15/R4-B9: a public envelope must carry a public body part — fail
       closed rather than verify the empty body. *)
    _ <- eprint (concat_all ("decrypt_post: no public body part found" :: lf :: nil)) ;;
    exit_with 1%int63
  else if negb (if public
                then verify_post_public trusted_sign_pk (slug_of_eml eml_path) public_body sig
                else verify_post trusted_sign_pk ct_package sig) then
    _ <- eprint (concat_all ("decrypt_post: author signature verification failed" :: lf :: nil)) ;;
    exit_with 1%int63
  else
    let slug := slug_of_eml eml_path in
    if public then write_recovered "Verified public post " eml_path slug public_body
    else
      let cek := try_unwrap sk triples in
      if is_empty cek then
        _ <- eprint (concat_all
          ("decrypt_post: none of the wrapped keys could be unwrapped" :: lf :: nil)) ;;
        exit_with 1%int63
      else
        let inner_mime := decrypt_body cek ct_package slug in
        if is_empty inner_mime then
          _ <- eprint (concat_all ("decrypt_post: body decryption failed" :: lf :: nil)) ;;
          exit_with 1%int63
        else write_recovered "Decrypted " eml_path slug inner_mime.

(* ---- entry point --------------------------------------------------- *)

Definition run : IO unit :=
  path <- first_path ;;
  if is_empty path
  then
    _ <- eprint (concat_all
      ("usage: decrypt_post [--key-file <path>] <posts-encrypted/slug.eml>" :: lf :: nil)) ;;
    exit_with 2%int63
  else
    (* One extra read here only to branch the env gate on public-ness (M4):
       decrypt_one re-derives [public] from the eml it reads.  The signing
       trust anchor (keys/<CRANE_BLOG_SIGNING_KEY_ID>.sign.pub) is resolved
       BEFORE the private-key gate and is required for BOTH kinds; the
       private key is only demanded for non-public envelopes. *)
    eml <- read path ;;
    let public := is_public_eml eml in
    sign_kid0 <- getenv "CRANE_BLOG_SIGNING_KEY_ID" ;;
    let sign_kid := trim sign_kid0 in
    sign_pub_hex <- read (cat "keys/" (cat sign_kid ".sign.pub")) ;;
    let trusted_sign_pk := hex_decode (trim sign_pub_hex) in
    if negb public
    then
      hex <- getenv "CRANE_BLOG_PRIVATE_KEY" ;;
      let sk := hex_decode (trim hex) in
      if is_empty sk
      then
        _ <- eprint (concat_all ("CRANE_BLOG_PRIVATE_KEY not set" :: lf :: nil)) ;;
        exit_with 1%int63
      else decrypt_one path sk trusted_sign_pk
    else
      (* Public envelopes need no private key (unwrapping is skipped); the
         "" sk is never used on this path. *)
      decrypt_one path "" trusted_sign_pk.

Set Warnings "-crane-extraction-default-directory".

Set Crane Extraction Output Directory ".".
Crane Extraction "decrypt_post" run.
