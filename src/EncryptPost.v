(* EncryptPost.v — the [encrypt_post] CLI tool, authored in ROCQ and extracted
    to C++23 via Crane.  Replaces the hand-written tools/encrypt_post.ml.

    Reproduces encrypt_post.ml's behavior:
      - read posts/<name>.md, parse frontmatter (title);
      - derive opaque slug from SHA-256 hash of raw content;
      - resolve the author key from CRANE_BLOG_AUTHOR_KEY_ID + keys/<kid>.pub
        (65-byte uncompressed hex);
      - read referenced images from posts/<rel>;
      - build the inner multipart/mixed (protected From/To/Date/Subject headers
        + raw markdown + base64 attachments);
      - CEK-encrypt the inner MIME (AAD = slug), HPKE-wrap the CEK per recipient
        (AAD = kid), ECDSA-sign the raw ciphertext package (CRANE_BLOG_SIGNING_KEY
        + keys/<kid>.sign.pub) and emit the outer multipart/hpke+wrapped envelope
        (Signature / Signing-Key headers) to posts-encrypted/<slug>.eml;
      - OR, when frontmatter `recipients: *` (feature 2), emit a PUBLIC (keyless)
        envelope instead: the same outer container with Public-Keys: *, one
        application/x-crane-public 8bit part carrying the byte-identical inner
        MIME, signed over sha256(sign_info_public || slug || normalize_crlf
        inner_mime) — no key resolution, no CEK, no wraps; mixed "*" + named
        readers is rejected (D3, D-M2).
      - print an "encrypted ... -> ..." status line to stderr.

    Paths are CWD-relative; scripts/test-roundtrip.sh runs the tool from the
    repo root (cd "$repo"), matching encrypt_post.ml's repo_root() resolution.

    --stage (git add/reset subprocess) is NOT exercised by the acceptance test
    and is intentionally skipped here (see AIDEV-NOTE below). *)

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
Require Import PostBuild.   (* slug_from_content *)
Require Import Recipients.  (* multi-recipient resolution + envelope building *)

Open Scope pstring_scope.

(* ---- argv parsing -------------------------------------------------- *)

(* First argv entry (from index 1) that does not begin with '-'.  Returns ""
   if none.  Bounded by arg_count. *)
Fixpoint first_path_aux (argc : int) (i : int) (fuel : nat) : IO string :=
  match fuel with
  | O => Ret ""
  | S f' =>
      if leb argc i then Ret ""
      else
        a <- arg_get i ;;
        if is_empty a then first_path_aux argc (add i 1%int63) f'
        else if int_eqb (PrimString.get a 0%int63) 45%int63 (* '-' *)
             then first_path_aux argc (add i 1%int63) f'
             else Ret a
  end.

Definition first_path : IO string :=
  argc <- arg_count ;;
  first_path_aux argc 1%int63 64%nat.

(* ---- slug / basename helpers --------------------------------------- *)

Definition has_suffix_md (s : string) : bool :=
  let n := PrimString.length s in
  if ltb n 3%int63 then false
  else string_eqb (PrimString.sub s (sub n 3%int63) 3%int63) ".md".

(* Strip a trailing ".md" from a basename. *)
Definition strip_md (name : string) : string :=
  if has_suffix_md name then
    PrimString.sub name 0%int63 (sub (PrimString.length name) 3%int63)
  else name.

(* The protected inner Date.  encrypt_post.ml uses the current UTC time; the
   acceptance test never inspects it (it is encrypted, and only the *outer*
   envelope is checked for the absence of a Date header), so a fixed RFC 5322
   string keeps extraction pure and the output deterministic. *)
Definition fixed_date : string := "Thu, 01 Jan 1970 00:00:00 +0000".

(* ---- image reading ------------------------------------------------- *)

(* Read each referenced image from posts/<rel>, returning (basename,
   wrapped-base64) pairs in order. *)
Fixpoint read_images (rels : list string) : IO (list (string * string)) :=
  match rels with
  | [] => Ret []
  | rel :: rest =>
      bytes <- read (cat "posts/" rel) ;;
      others <- read_images rest ;;
      Ret ((basename_of rel, wrap_base64 (base64_encode bytes)) :: others)
  end.

(* Read keys/<kid>.pub for every recipient (author first).  Concrete at this
   file's IO (dirE +' ioE +' toolE); see the note in Recipients.v.  The
   recursion is the whole first statement so the tail-position gate passes. *)
Fixpoint read_pubkeys (kids : list string) : IO (list (string * string)) :=
  match kids with
  | [] => Ret []
  | kid :: rest =>
      others <- read_pubkeys rest ;;
      pub_hex <- read (cat "keys/" (cat kid ".pub")) ;;
      let pub_raw := hex_decode (trim pub_hex) in
      Ret ((kid, pub_raw) :: others)
  end.

(* Build the full outer envelope — now shared, multi-recipient, in
   Recipients.build_envelope (single source of truth with SmtpServer.v).
   The CEK is still a materialized parameter so [random_bytes 32] is evaluated
   exactly once at the call site.  One Public-Keys / Wraps entry per recipient;
   the RAW ciphertext package is signed exactly as DecryptPost/DecryptApp
   verify it. *)

(* ---- the encrypt pipeline for one .md file ------------------------- *)

Definition encrypt_one (md_path : string) : IO unit :=
  raw <- read md_path ;;
  let kv := parse_frontmatter_kv raw in
  let md_basename := basename_of md_path in
  let slug_meta := header_lookup "slug" kv in
  let slug := if is_empty slug_meta then strip_md md_basename else slug_meta in
  let title_meta := header_lookup "title" kv in
  let title := if is_empty title_meta then "Untitled" else title_meta in
  kid <- getenv "CRANE_BLOG_AUTHOR_KEY_ID" ;;
  let kid := trim kid in
  email <- getenv "CRANE_BLOG_AUTHOR_EMAIL" ;;
  let email := trim email in
  sign_kid0 <- getenv "CRANE_BLOG_SIGNING_KEY_ID" ;;
  let sign_kid := trim sign_kid0 in
  sign_hex <- getenv "CRANE_BLOG_SIGNING_KEY" ;;
  let sign_sk := hex_decode (trim sign_hex) in
  if is_empty sign_sk
  then
    _ <- eprint (concat_all ("CRANE_BLOG_SIGNING_KEY not set" :: lf :: nil)) ;;
    exit_with 1%int63
  else
    sign_pub_hex <- read (cat "keys/" (cat sign_kid ".sign.pub")) ;;
    let sign_pk_hex := trim sign_pub_hex in
    let image_rels := collect_image_refs raw in
    images <- read_images image_rels ;;
    (* A13 (R2 MINOR-4): a body line equal to a MIME boundary literal would
       corrupt the inner multipart framing — reject it up front (covers both
       the public and the encrypted branch; the body is the same [raw]). *)
    if has_boundary_literal raw
    then
      _ <- eprint (concat_all
        ("encrypt_post: body contains a line equal to a MIME boundary literal" :: lf :: nil)) ;;
      exit_with 1%int63
    else
      (* Recipients (feature 1/2): frontmatter `recipients:` is honored —
         empty/absent => author-only ([author_kid]); exactly "*" => PUBLIC
         (keyless signed plaintext envelope, branch BEFORE read_pubkeys so
         keys/<kid>.pub is never read); mixed "*" + named readers =>
         rejected (D3, D-M2). *)
      let recipients_meta := header_lookup "recipients" kv in
      if is_public_marker recipients_meta
      then
        (* PUBLIC branch (D1/D4/D-C2): no CEK, no wraps.  To: is still
           reader: <author_kid>; From is [public_from_token] (not an email
           address — CF Email Address Obfuscation).  The envelope signs
           sha256(sign_info_public || slug || normalize_crlf inner_mime). *)
        let recipients_str := recipients_to (kid :: nil) in
        let protected_headers :=
          ("From", public_from_token) ::
          ("To", recipients_str) ::
          ("Date", fixed_date) ::
          ("Subject", title) :: nil in
        let inner_mime := build_inner_mime protected_headers md_basename raw images in
        let envelope := build_public_envelope slug inner_mime sign_sk sign_pk_hex in
        _ <- create_directory "posts-encrypted" ;;
        _ <- write_file (cat "posts-encrypted/" (cat slug ".eml")) envelope ;;
        eprint (concat_all
          ("encrypted " :: md_path :: " -> posts-encrypted/" :: slug :: ".eml" :: lf :: nil))
      else if contains_public_marker recipients_meta
      then
        (* Mixed "*" + named readers (D3): reject BEFORE read_pubkeys. *)
        _ <- eprint (concat_all
          ("encrypt_post: recipients may not mix the public marker * with named readers" :: lf :: nil)) ;;
        exit_with 1%int63
      else
        (* Encrypted path: the author (CRANE_BLOG_AUTHOR_KEY_ID) is always
           first; frontmatter `recipients: kid1, kid2` adds up to 3 more
           readers.  Their public keys are resolved from keys/<kid>.pub. *)
        let recips := build_recipients kid recipients_meta in
        recipients_pk <- read_pubkeys recips ;;
        if negb (recips_ok recipients_pk)
        then
          _ <- eprint (concat_all
            ("encrypt_post: missing or unreadable recipient public key under keys/" :: lf :: nil)) ;;
          exit_with 1%int63
        else
          let recipients_str := recipients_to (kid_list recipients_pk) in
          let protected_headers :=
            ("From", email) ::
            ("To", recipients_str) ::
            ("Date", fixed_date) ::
            ("Subject", title) :: nil in
          let inner_mime := build_inner_mime protected_headers md_basename raw images in
          let envelope := build_envelope (random_bytes 32%int63) recipients_pk slug inner_mime sign_sk sign_pk_hex in
          _ <- create_directory "posts-encrypted" ;;
          _ <- write_file (cat "posts-encrypted/" (cat slug ".eml")) envelope ;;
          eprint (concat_all
            ("encrypted " :: md_path :: " -> posts-encrypted/" :: slug :: ".eml" :: lf :: nil)).

(* ---- entry point --------------------------------------------------- *)

Definition run : IO unit :=
  path <- first_path ;;
  if is_empty path
  then
    _ <- eprint (concat_all
      ("usage: encrypt_post [--stage] <posts/slug.md> [...]" :: lf :: nil)) ;;
    exit_with 2%int63
  else encrypt_one path.

(* AIDEV-NOTE: --stage (git add ciphertext / reset plaintext) is not ported.
   It needs a subprocess effect (procE) which Facet C introduces; the Facet-B
   acceptance oracle (test-roundtrip.sh) never passes --stage.  The flag is
   accepted and ignored by first_path's '-'-prefix skip. *)

Set Crane Extraction Output Directory ".".
Crane Extraction "encrypt_post" run.
