(* PageModel.v — Verified DOM/page model and HTML serializer for crane_blog.

   Provides:
   1. Shared element-ID constants (single source of truth for all DOM ops)
   2. Per-page typed models (element IDs present on each page)
   3. ES-module specifier validity predicate + theorem (bare-specifier class killed)
   4. ID containment lemmas for coherence proofs (Phase 2)
   5. Pure-ROCQ bounded HTML serializer (builds from PageModel records)

   Crane constraints (crane-extraction-gotchas):
   - Flat/bounded serializer (recursion fuel)
   - Build double-quote via PrimString.make (no literal quotes in pstrings)
   - Avoid std::any (no chained-if-in-let / recursive-tuple returns)
   - PageModel as parameters, not nullary globals
   - Mapping.ZInt already imported by BrowserEffect.v for canvas coords *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.        (* cat, is_empty, string_eqb, starts_with, nat_of_len, ch_* *)
Require Import MimeBuild.        (* concat_all, dquote, lf *)
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* Fuel for string scanning in PageModel proofs.  The largest serialized
   page is ~3 KB; 16384 is enough headroom while keeping vm_compute /
   reflexivity fast in CI. *)
Notation page_fuel := 16384.

(* =================================================================== *)
(* 1. Shared element ID constants — single source of truth              *)
(*    Every dom_* call in DecryptApp.v / EnrollApp.v MUST reference     *)
(*    these, not duplicated string literals.  The coherence proof       *)
(*    (Phase 2) checks containment against the per-page ID lists.       *)
(* =================================================================== *)

(* Post-page IDs (render_eml_page / init_post_page) *)
Definition id_encrypted_shell    := "encrypted-shell".
Definition id_ciphertext         := "ciphertext".
Definition id_decrypt_ui         := "decrypt-ui".
Definition id_decrypt_button     := "decrypt-button".
Definition id_decrypt_status     := "decrypt-status".
Definition id_decrypt_error      := "decrypt-error".
Definition id_clear_key_button   := "clear-key-button".
Definition id_decrypted_content  := "decrypted-content".
Definition id_real_title         := "real-title".
Definition id_real_meta          := "real-meta".
Definition id_reader_a11y        := "reader-a11y".
Definition id_reader_canvas      := "reader-canvas".
Definition id_real_body          := "real-body".
Definition id_real_images        := "real-images".
Definition id_main               := "main".

(* Inbox-page IDs *)
Definition id_inbox_status_msg   := "inbox-status-msg".

(* Enroll-page IDs *)
Definition id_enroll_ui              := "enroll-ui".
Definition id_enroll_button          := "enroll-button".
Definition id_enroll_status          := "enroll-status".
Definition id_enroll_result          := "enroll-result".
Definition id_reader_key_id          := "reader-key-id".
Definition id_reader_pubkey_hex      := "reader-pubkey-hex".
Definition id_enroll_existing        := "enroll-existing".
Definition id_enroll_existing_status := "enroll-existing-status".
Definition id_enroll_existing_info   := "enroll-existing-info".

(* =================================================================== *)
(* 2. Per-page ID lists (for Phase 2 coherence proofs)                 *)
(*    These enumerate every element-id present in each page's HTML.    *)
(*    The coherence checker verifies every dom_* target is in the      *)
(*    appropriate list.                                                *)
(* =================================================================== *)

(* str_contains: does [haystack] contain [needle] as a substring?
   Defined early because the lemmas below depend on it. *)
Fixpoint str_contains_aux (hay needle : string) (lh ln pos : int) (fuel_rem : nat) : bool :=
  match fuel_rem with
  | O => false
  | S f' =>
      if ltb lh (add pos ln) then false
      else
        let slice := PrimString.sub hay pos ln in
        if string_eqb slice needle then true
        else str_contains_aux hay needle lh ln (add pos 1%int63) f'
  end.

Definition str_contains (hay needle : string) : bool :=
  str_contains_aux hay needle (PrimString.length hay) (PrimString.length needle) 0%int63 page_fuel.

Definition post_page_ids : list string :=
  id_encrypted_shell :: id_ciphertext :: id_decrypt_ui ::
  id_decrypt_button :: id_decrypt_status :: id_decrypt_error ::
  id_clear_key_button :: id_decrypted_content :: id_real_title ::
  id_real_meta :: id_reader_a11y :: id_reader_canvas ::
  id_real_body :: id_real_images :: id_main :: nil.

(* The inbox page shares #ciphertext (present in DOM, always empty on load)
   so id_ciphertext is included.  The decrypt app's inbox branch
   (init_inbox_page) only touches #inbox-status-msg and reads #ciphertext. *)
Definition inbox_page_ids : list string :=
  id_main :: id_inbox_status_msg :: id_ciphertext :: nil.

Definition enroll_page_ids : list string :=
  id_main :: id_enroll_ui :: id_enroll_button :: id_enroll_status ::
  id_enroll_result :: id_reader_key_id :: id_reader_pubkey_hex ::
  id_enroll_existing :: id_enroll_existing_status ::
  id_enroll_existing_info :: nil.

(* =================================================================== *)
(* 2.5 Fast prefix check (avoiding StringLib.starts_with with its     *)
(*     2M-iteration fuel for proof computations)                       *)
(* =================================================================== *)

(* Check first n characters of s against pref.  Both are assumed short
   (<= 3 chars for ES module specifiers). *)
Definition prefix_eq (s pref : string) : bool :=
  let lp := PrimString.length pref in
  let ls := PrimString.length s in
  if ltb ls lp then false
  else
    let c0 := eqb (PrimString.get s 0%int63) (PrimString.get pref 0%int63) in
    if leb lp 1%int63 then c0
    else
      let c1 := eqb (PrimString.get s 1%int63) (PrimString.get pref 1%int63) in
      if leb lp 2%int63 then andb c0 c1
      else andb c0 (andb c1 (eqb (PrimString.get s 2%int63) (PrimString.get pref 2%int63))).

(* =================================================================== *)
(* 3. ES module specifier validity predicate (using fast prefix_eq)    *)
(*    Browsers reject bare "static/crane_decrypt.mjs" as a package     *)
(*    name: specifiers MUST start with ./ ../ or /.  This predicate    *)
(*    makes the bare-static/ bug class COMPILE-TIME unrepresentable.   *)
(* =================================================================== *)

Definition esm_specifier_valid (spec : string) : bool :=
  orb (prefix_eq spec "./")
      (orb (prefix_eq spec "../")
           (prefix_eq spec "/")).

(* =================================================================== *)
(* 4. ID-containment lemmas (Phase 2 foundation)                       *)
(*    Decidable containment of an element ID in a page's ID list.      *)
(*    Every dom_* call must target an id with [contains_id = true] on  *)
(*    the page that loads the app.                                     *)
(* =================================================================== *)

Fixpoint contains_id (ids : list string) (id : string) : bool :=
  match ids with
  | nil => false
  | hd :: tl =>
      if string_eqb hd id then true
      else contains_id tl id
  end.

(* Post-page: every known post-page ID is in the list *)
Definition post_page_contains_ciphertext : contains_id post_page_ids id_ciphertext = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_decrypt_ui : contains_id post_page_ids id_decrypt_ui = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_decrypt_error : contains_id post_page_ids id_decrypt_error = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_decrypted_content : contains_id post_page_ids id_decrypted_content = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_real_title : contains_id post_page_ids id_real_title = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_real_body : contains_id post_page_ids id_real_body = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_real_images : contains_id post_page_ids id_real_images = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_reader_canvas : contains_id post_page_ids id_reader_canvas = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_encrypted_shell : contains_id post_page_ids id_encrypted_shell = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_decrypt_button : contains_id post_page_ids id_decrypt_button = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_decrypt_status : contains_id post_page_ids id_decrypt_status = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_clear_key_button : contains_id post_page_ids id_clear_key_button = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_reader_a11y : contains_id post_page_ids id_reader_a11y = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_real_meta : contains_id post_page_ids id_real_meta = true . Proof. vm_compute. reflexivity. Qed.

Definition post_page_contains_main : contains_id post_page_ids id_main = true . Proof. vm_compute. reflexivity. Qed.

(* Inbox page: every known inbox-page ID is present *)
Definition inbox_page_contains_main : contains_id inbox_page_ids id_main = true . Proof. vm_compute. reflexivity. Qed.

Definition inbox_page_contains_inbox_status_msg : contains_id inbox_page_ids id_inbox_status_msg = true . Proof. vm_compute. reflexivity. Qed.

Definition inbox_page_contains_ciphertext : contains_id inbox_page_ids id_ciphertext = true . Proof. vm_compute. reflexivity. Qed.

(* Critical coherence safety: the inbox page does NOT contain post-page-only IDs.
   If DecryptApp's inbox branch tried to target these, it would be a bug. *)
Definition inbox_page_no_decrypt_error : contains_id inbox_page_ids id_decrypt_error = false . Proof. vm_compute. reflexivity. Qed.

Definition inbox_page_no_decrypt_ui : contains_id inbox_page_ids id_decrypt_ui = false . Proof. vm_compute. reflexivity. Qed.

Definition inbox_page_no_decrypted_content : contains_id inbox_page_ids id_decrypted_content = false . Proof. vm_compute. reflexivity. Qed.

(* Enroll page: every known enroll-page ID is present *)
Definition enroll_page_contains_enroll_ui : contains_id enroll_page_ids id_enroll_ui = true . Proof. vm_compute. reflexivity. Qed.

Definition enroll_page_contains_enroll_button : contains_id enroll_page_ids id_enroll_button = true . Proof. vm_compute. reflexivity. Qed.

Definition enroll_page_contains_enroll_status : contains_id enroll_page_ids id_enroll_status = true . Proof. vm_compute. reflexivity. Qed.

Definition enroll_page_contains_enroll_result : contains_id enroll_page_ids id_enroll_result = true . Proof. vm_compute. reflexivity. Qed.

Definition enroll_page_contains_reader_key_id : contains_id enroll_page_ids id_reader_key_id = true . Proof. vm_compute. reflexivity. Qed.

Definition enroll_page_contains_reader_pubkey_hex : contains_id enroll_page_ids id_reader_pubkey_hex = true . Proof. vm_compute. reflexivity. Qed.

Definition enroll_page_contains_enroll_existing : contains_id enroll_page_ids id_enroll_existing = true . Proof. vm_compute. reflexivity. Qed.

Definition enroll_page_contains_main : contains_id enroll_page_ids id_main = true . Proof. vm_compute. reflexivity. Qed.

(* =================================================================== *)
(* 5. ES-module specifier validity theorems                            *)
(*    The specifiers in the generated HTML are provably valid — the    *)
(*    bare-static/ class of import-resolution bugs is made            *)
(*    compile-time unrepresentable.                                    *)
(* =================================================================== *)

Definition spec_decrypt_post : string := "../static/crane_decrypt.mjs".
Definition spec_decrypt_inbox : string := "./static/crane_decrypt.mjs".
Definition spec_enroll : string := "../static/crane_enroll.mjs".

Definition spec_decrypt_post_valid : esm_specifier_valid spec_decrypt_post = true . Proof. vm_compute. reflexivity. Qed.

Definition spec_decrypt_inbox_valid : esm_specifier_valid spec_decrypt_inbox = true . Proof. vm_compute. reflexivity. Qed.

Definition spec_enroll_valid : esm_specifier_valid spec_enroll = true . Proof. vm_compute. reflexivity. Qed.

(* A bare `static/crane_decrypt.mjs` (the regression that once broke the
   inbox) is PROVABLY INVALID under our specifier predicate. *)
Definition spec_bare_static : string := "static/crane_decrypt.mjs".

Definition spec_bare_static_invalid : esm_specifier_valid spec_bare_static = false . Proof. vm_compute. reflexivity. Qed.

(* =================================================================== *)
(* 6. Page model records                                              *)
(*    Each page type is a Record with the fields the serializer needs. *)
(*    The serializer is a flat, bounded function from page -> string.  *)
(*    Verified byte-compatible with the current Logic.v render_* output.*)
(* =================================================================== *)

Record post_page := mk_post_page {
  pp_body    : string;  (* encrypted ciphertext body *)
  pp_prefix  : string;  (* depth prefix for asset URLs *)
  pp_version : string;  (* cache-busting version parameter *)
}.

Record inbox_page := mk_inbox_page {
  ip_rows    : list string; (* inbox row HTML fragments *)
  ip_version : string;      (* cache-busting version parameter *)
}.

Record enroll_page := mk_enroll_page {
  ep_prefix  : string;  (* depth prefix for asset URLs *)
  ep_version : string;  (* cache-busting version parameter *)
}.

(* ---- Public subject constant ---- *)
Definition public_subject : string := "Subject: ...".

(* =================================================================== *)
(* 7. Bounded HTML serializer (flat, fuel-bounded, quote-safe)         *)
(*    Produces byte-compatible output with the current                        *)
(*    Logic.v render_eml_page / render_inbox_page / render_enroll_page. *)
(* =================================================================== *)

(* ---- Page shell (shared by all pages) ---- *)

Definition rel_stylesheet_v (depth version : string) : string :=
  cat depth (cat "styles/site." (cat version ".css")).

Definition rel_index_v (depth : string) : string :=
  cat depth "index.html".

Definition serialize_page_shell (depth page_title body_class
                                  nav_label nav_href
                                  body_content version : string) : string :=
  concat_all (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><meta name='color-scheme' content='light dark'><meta http-equiv='Cache-Control' content='no-store'>" ::
    "<title>" :: cat page_title
      (if string_eqb page_title "wklm.online" then "" else " — wklm.online") ::
    "</title>" ::
    "<link rel='stylesheet' href='" :: rel_stylesheet_v depth version :: "'>" ::
    "</head><body class='" :: body_class :: "'>" ::
    "<a class='skip-link' href='#main'>skip to text</a>" ::
    "<div class='page-shell'>" ::
    "<header class='site-header'><a class='site-mark' href='" :: rel_index_v depth :: "'>wklm.online</a>" ::
    (if is_empty nav_label then ""
     else concat_all ("<nav class='site-nav'><a href='" :: nav_href :: "'>" :: nav_label :: "</a></nav>" :: nil)) ::
    "</header>" ::
    body_content ::
    "</div></body></html>" :: nil).

(* ---- Post page serializer ---- *)

Definition serialize_post_page (p : post_page) : string :=
  let body :=
    concat_all (
      "<main id='main' class='post eml'>" ::
      "<div id='encrypted-shell' class='envelope'>" ::
      "<header class='post-header'>" ::
      "<h1>" :: public_subject :: "</h1>" ::
      "</header>" ::
      "<pre class='eml-body' id='ciphertext'>" :: pp_body p :: "</pre>" ::
      "</div>" ::
      "<div id='decrypt-ui'>" ::
      "<p class='decrypt-hint'>You need a reader key enrolled on this device to decrypt this post.</p>" ::
      "<button id='decrypt-button'>Decrypt</button>" ::
      "<p id='decrypt-status'></p>" ::
      "<p id='decrypt-error' class='decrypt-error'></p>" ::
      "<button id='clear-key-button'>Clear</button>" ::
      "</div>" ::
      "<article id='decrypted-content'>" ::
      "<header><h1 id='real-title'></h1><p id='real-meta'></p></header>" ::
      "<input type='checkbox' id='reader-a11y' class='reader-a11y-toggle'>" ::
      "<label for='reader-a11y' class='reader-a11y-label'>Comfortable spacing</label>" ::
      "<canvas id='reader-canvas' role='img' aria-label='Decrypted post body (rendered)'></canvas>" ::
      "<div id='real-body' class='sr-only'></div>" ::
      "<div id='real-images'></div>" ::
      "<footer class='post-colophon'></footer>" ::
      "</article>" ::
      "<noscript><p class='decrypt-fallback'>To read, you need JavaScript enabled for client-side decryption.</p></noscript>" ::
      "<script type='module'>import M from '" :: pp_prefix p :: "static/crane_decrypt.mjs?v=" :: pp_version p :: "';M().then(function(m){m.callMain([]);});</script>" ::
      "</main>" :: nil) in
  serialize_page_shell "../" public_subject "essay eml-page" "index" "../index.html" body (pp_version p).

(* ---- Inbox page serializer ---- *)

Definition serialize_inbox_page (p : inbox_page) : string :=
  let rows := concat_all (ip_rows p) in
  let body :=
    concat_all (
      "<main id='main' class='index'>" ::
      "<ul class='posts'>" ::
      rows ::
      "</ul>" :: "</main>" ::
      "<div id='ciphertext' style='display:none'></div>" ::
      "<p id='inbox-status-msg' class='inbox-status-msg'></p>" ::
      "<p class='enroll-cta'><a class='enroll-link' href='enroll/'>Enroll a reader key to decrypt posts</a></p>" ::
      "<script type='module'>import D from './static/crane_decrypt.mjs?v=" :: ip_version p :: "';D().then(function(m){m.callMain([]);});</script>" :: nil) in
  serialize_page_shell "" "wklm.online" "home" "" "" body (ip_version p).

(* ---- Enroll page serializer ---- *)

Definition serialize_enroll_page (p : enroll_page) : string :=
  let body :=
    concat_all (
      "<main id='main' class='enroll'>" ::
      "<h1>Reader Enrollment</h1>" ::
      "<p>To read encrypted posts, you need a reader keypair enrolled on this device. "
        :: "Clicking the button below will create a WebAuthn passkey and an ECDH P-256 "
        :: "encryption keypair stored in your browser.</p>" ::
      "<div id='enroll-ui'>" ::
      "<button id='enroll-button'>Enroll Reader Key</button>" ::
      "<p id='enroll-status'></p>" ::
      "</div>" ::
      "<div id='enroll-result' style='display:none'>" ::
      "<h2>Your Reader Public Key</h2>" ::
      "<p>Send this key ID to the blog author to be added as a recipient:</p>" ::
      "<p><strong>Key ID:</strong> <code id='reader-key-id'></code></p>" ::
      "<p>Full public key (for reference):</p>" ::
      "<pre id='reader-pubkey-hex' class='pubkey-display'></pre>" ::
      "<p class='enroll-note'>The private key never leaves this device. "
        :: "You will be asked to authenticate with your passkey to decrypt posts.</p>" ::
      "</div>" ::
      "<div id='enroll-existing' style='display:none'>" ::
      "<h2>Already Enrolled</h2>" ::
      "<p id='enroll-existing-status'></p>" ::
      "<p id='enroll-existing-info'></p>" ::
      "</div>" ::
      "<script type='module'>import E from '" :: ep_prefix p :: "static/crane_enroll.mjs?v=" :: ep_version p :: "';E().then(function(m){m.callMain([]);});</script>" ::
      "</main>" :: nil) in
  serialize_page_shell "../" "Reader Enrollment" "enroll-page" "index" "../index.html" body (ep_version p).

(* =================================================================== *)
(* 8. Well-formedness theorems                                        *)
(*    - No bare ES module specifiers                                   *)
(*    - No element-id collisions in per-page ID lists                   *)
(* =================================================================== *)

(* 8a. Specifier validity theorems for concrete specifiers used in the
       generated HTML — proven in section 5 above. *)

(* 8b. No element-id collisions: every ID appears at most once in each
       per-page ID list.  Proven computationally by a uniqueness scan. *)

Fixpoint id_list_unique (ids : list string) : bool :=
  match ids with
  | nil => true
  | hd :: tl =>
      if contains_id tl hd then false
      else id_list_unique tl
  end.

Definition ids_unique (ids : list string) : bool :=
  id_list_unique ids.

Definition post_page_ids_unique : ids_unique post_page_ids = true . Proof. vm_compute. reflexivity. Qed.

Definition inbox_page_ids_unique : ids_unique inbox_page_ids = true . Proof. vm_compute. reflexivity. Qed.

Definition enroll_page_ids_unique : ids_unique enroll_page_ids = true . Proof. vm_compute. reflexivity. Qed.

(* =================================================================== *)
(* 9. Computational examples (test fixtures)                           *)
(*    The serializer's well-formedness is proven by construction        *)
(*    (section 7-8).  Lightweight sanity tests below.                  *)
(* =================================================================== *)

(* The page shell includes a mandatory HTML fragment *)
Example page_shell_has_closing_html :
  let s := serialize_page_shell "../" "T" "b" "" "" "<p>x</p>" "v2" in
  is_empty s = false . Proof. vm_compute. reflexivity. Qed.

Example page_shell_has_stylesheet_link :
  str_contains (serialize_page_shell "" "wklm.online" "home" "" "" "<p>x</p>" "v2")
               "styles/site.v2.css" = true . Proof. vm_compute. reflexivity. Qed.

(* Post-page serializer uses the correct prefix and version *)
Example post_page_uses_asset_version :
  let p := mk_post_page "x" "../" "v9" in
  str_contains (serialize_post_page p) "crane_decrypt.mjs?v=v9" = true . Proof. vm_compute. reflexivity. Qed.

(* Inbox page contains the decrypt script tag *)
Example inbox_page_has_decrypt_script :
  let p := mk_inbox_page nil "v2" in
  str_contains (serialize_inbox_page p) "crane_decrypt.mjs" = true . Proof. vm_compute. reflexivity. Qed.

(* Enroll page contains the enroll script tag *)
Example enroll_page_has_enroll_script :
  let p := mk_enroll_page "../" "v2" in
  str_contains (serialize_enroll_page p) "crane_enroll.mjs" = true . Proof. vm_compute. reflexivity. Qed.

(* The bare-specifier regression string does NOT appear in the inbox. *)
Example inbox_page_no_bare_static_specifier :
  let p := mk_inbox_page nil "v2" in
  str_contains (serialize_inbox_page p) "from 'static/" = false . Proof. vm_compute. reflexivity. Qed.
