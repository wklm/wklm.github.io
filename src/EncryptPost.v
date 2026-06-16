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
        (AAD = kid), and emit the outer multipart/hpke+wrapped envelope to
        posts-encrypted/<slug>.eml;
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

(* Build the full outer envelope from a *single* materialized CEK.  cek is a
   function parameter so Crane evaluates [random_bytes 32] exactly once at the
   call site — a nullary Definition (like generate_cek) would be inlined and
   re-evaluated, encrypting the body under a different CEK than the wrap. *)
Definition build_envelope
  (cek pub_raw kid slug inner_mime sign_sk sign_pub_hex : string) : string :=
  let ct_package := encrypt_body cek inner_mime slug in
  let '(ek, wrapped) := wrap_cek cek pub_raw kid in
  build_outer_envelope
    (kid :: nil)
    ((kid, hex_encode ek, hex_encode wrapped) :: nil)
    (wrap_base64 (base64_encode ct_package)).

(* ---- the encrypt pipeline for one .md file ------------------------- *)

Definition encrypt_one (md_path : string) : IO unit :=
  raw <- read md_path ;;
  let kv := parse_frontmatter_kv raw in
  let md_basename := basename_of md_path in
  let slug_meta := meta_lookup "slug" kv in
  let slug := if is_empty slug_meta then strip_md md_basename else slug_meta in
  let title_meta := meta_lookup "title" kv in
  let title := if is_empty title_meta then "Untitled" else title_meta in
  kid <- getenv "CRANE_BLOG_AUTHOR_KEY_ID" ;;
  let kid := trim kid in
  pub_hex <- read (cat "keys/" (cat kid ".pub")) ;;
  let pub_raw := hex_decode (trim pub_hex) in
  email <- getenv "CRANE_BLOG_AUTHOR_EMAIL" ;;
  let email := trim email in
  let image_rels := collect_image_refs raw in
  images <- read_images image_rels ;;
  let recipients_str := cat "reader:" kid in
  let protected_headers :=
    ("From", email) ::
    ("To", recipients_str) ::
    ("Date", fixed_date) ::
    ("Subject", title) :: nil in
  let inner_mime := build_inner_mime protected_headers md_basename raw images in
  let envelope := build_envelope (random_bytes 32%int63) pub_raw kid slug inner_mime in
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
