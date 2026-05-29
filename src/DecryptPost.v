(* DecryptPost.v — the [decrypt_post] CLI tool, authored in ROCQ and extracted
   to C++23 via Crane.  Replaces the hand-written tools/decrypt_post.ml.

   Inverse of EncryptPost.v:
     - read posts-encrypted/<slug>.eml; parse the outer multipart/hpke+wrapped
       envelope (Wraps triples + base64 ciphertext part);
     - load the 32-byte private scalar from CRANE_BLOG_PRIVATE_KEY (hex);
     - unwrap the CEK (AAD = kid, then "" fallback) from the first wrap that
       succeeds; decrypt the body (AAD = slug, then "" fallback);
     - parse the recovered inner multipart/mixed: write the markdown to
       posts/<slug>.md (exactly one trailing newline) and each attachment to
       posts/<filename> (base64-decoded);
     - print "Decrypted <eml> -> posts/<slug>.md" to stdout.

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
      let '(ph, _pb) := split_headers_body (trim_part_terminator part) in
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
      let '(ph, pb) := split_headers_body (trim_part_terminator part) in
      let phdrs := parse_headers ph in
      let pct := header_lookup "Content-Type" phdrs in
      if starts_with pct "application/aes-gcm"
      then trim pb
      else find_ct_b64 rest
  end.

(* ---- CEK unwrap with AAD fallback ---------------------------------- *)
(* unwrap_cek uses AAD = kid; on "" (tag mismatch) retry with AAD = "".
   Mirrors decrypt_post.ml's backward-compat fallback. *)
Definition unwrap_fallback (sk ek wrapped kid : string) : string :=
  let r := unwrap_cek sk ek wrapped kid in
  if is_empty r then unwrap_cek sk ek wrapped "" else r.

(* Try each wrap triple; return the first non-empty CEK ("" if none). *)
Fixpoint try_unwrap (sk : string) (triples : list (string * string * string))
  : string :=
  match triples with
  | nil => ""
  | (kid, ek, wrapped) :: rest =>
      let cek := unwrap_fallback sk ek wrapped kid in
      if is_empty cek then try_unwrap sk rest else cek
  end.

(* ---- body decrypt with AAD fallback -------------------------------- *)
Definition decrypt_body_fallback (cek ct_package slug : string) : string :=
  let r := decrypt_body cek ct_package slug in
  if is_empty r then decrypt_body cek ct_package "" else r.

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

Definition decrypt_one (eml_path sk : string) : IO unit :=
  eml <- read eml_path ;;
  let '(hdrs_block, body) := split_headers_body eml in
  let hdrs := parse_headers hdrs_block in
  let ct_hdr := header_lookup "Content-Type" hdrs in
  let boundary := extract_boundary ct_hdr in
  let parts := split_parts body boundary in
  let triples := parse_wraps (find_wraps parts) in
  let ct_b64 := find_ct_b64 parts in
  let ct_package := base64_decode (strip_ws ct_b64) in
  let slug := slug_of_eml eml_path in
  let cek := try_unwrap sk triples in
  if is_empty cek then
    _ <- eprint (concat_all
      ("decrypt_post: none of the wrapped keys could be unwrapped" :: lf :: nil)) ;;
    exit_with 1%int63
  else
    let inner_mime := decrypt_body_fallback cek ct_package slug in
    if is_empty inner_mime then
      _ <- eprint (concat_all ("decrypt_post: body decryption failed" :: lf :: nil)) ;;
      exit_with 1%int63
    else
      let inner_parts := split_parts inner_mime inner_boundary in
      let md := inner_md inner_parts in
      let atts := inner_attachments inner_parts in
      _ <- create_directory "posts" ;;
      _ <- write_file (cat "posts/" (cat slug ".md")) md ;;
      _ <- write_attachments atts ;;
      print_endline (concat_all
        ("Decrypted " :: eml_path :: " -> posts/" :: slug :: ".md" :: nil)).

(* ---- entry point --------------------------------------------------- *)

Definition run : IO unit :=
  path <- first_path ;;
  if is_empty path
  then
    _ <- eprint (concat_all
      ("usage: decrypt_post [--key-file <path>] <posts-encrypted/slug.eml>" :: lf :: nil)) ;;
    exit_with 2%int63
  else
    hex <- getenv "CRANE_BLOG_PRIVATE_KEY" ;;
    let sk := hex_decode (trim hex) in
    if is_empty sk
    then
      _ <- eprint (concat_all ("CRANE_BLOG_PRIVATE_KEY not set" :: lf :: nil)) ;;
      exit_with 1%int63
    else decrypt_one path sk.

Set Warnings "-crane-extraction-default-directory".

Crane Extraction "decrypt_post" run.
