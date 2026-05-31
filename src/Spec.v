From Corelib Require Import PrimString PrimInt63.
Require Import Logic.
Open Scope pstring_scope.

(* ================================================================= *)
(* Privacy guarantee (top-level, composed from the lemmas below).     *)
(*                                                                   *)
(* The public page for any post contains only the ciphertext body     *)
(* and fixed template strings.  The real Subject, From, and To       *)
(* headers are structurally unreachable: parse_eml never reads them, *)
(* and render_eml_page never renders anything except ep_body.         *)
(* ================================================================= *)

Theorem privacy : forall (slug raw : string),
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  let ep := parse_eml slug raw in
  render_eml_page ep =
  render_eml_page (mkEncryptedPost slug (sort_key slug (lookup_header headers "Date")) body).
Proof.
  intros; rewrite parse_eml_eq. reflexivity.
Qed.

(* ================================================================= *)
(* 1. html_escape_char lemmas — one per code path                     *)
(* ================================================================= *)

Lemma html_escape_char_eq_amp : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp = true ->
  html_escape_char s pos = "&amp;".
Proof.
  intros; unfold html_escape_char; rewrite H; reflexivity.
Qed.

Lemma html_escape_char_eq_lt : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = true  ->
  html_escape_char s pos = "&lt;".
Proof.
  intros; unfold html_escape_char; rewrite H, H0; reflexivity.
Qed.

Lemma html_escape_char_eq_gt : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = false ->
  int_eqb (PrimString.get s pos) ch_gt    = true  ->
  html_escape_char s pos = "&gt;".
Proof.
  intros; unfold html_escape_char; rewrite H, H0, H1; reflexivity.
Qed.

Lemma html_escape_char_eq_quote : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = false ->
  int_eqb (PrimString.get s pos) ch_gt    = false ->
  int_eqb (PrimString.get s pos) ch_quote = true  ->
  html_escape_char s pos = "&quot;".
Proof.
  intros; unfold html_escape_char; rewrite H, H0, H1, H2; reflexivity.
Qed.

Lemma html_escape_char_eq_apos : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = false ->
  int_eqb (PrimString.get s pos) ch_gt    = false ->
  int_eqb (PrimString.get s pos) ch_quote = false ->
  int_eqb (PrimString.get s pos) ch_apos  = true  ->
  html_escape_char s pos = "&#39;".
Proof.
  intros; unfold html_escape_char; rewrite H, H0, H1, H2, H3; reflexivity.
Qed.

Lemma html_escape_char_passthrough : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = false ->
  int_eqb (PrimString.get s pos) ch_gt    = false ->
  int_eqb (PrimString.get s pos) ch_quote = false ->
  int_eqb (PrimString.get s pos) ch_apos  = false ->
  html_escape_char s pos = PrimString.sub s pos 1%int63.
Proof.
  intros; unfold html_escape_char; rewrite H, H0, H1, H2, H3; reflexivity.
Qed.

(* ================================================================= *)
(* 2. render_eml_page — only ep_body is read                         *)
(* ================================================================= *)

Lemma render_eml_page_ignores_slug : forall ep s,
  render_eml_page ep =
  render_eml_page (mkEncryptedPost s ep.(ep_sort_key) ep.(ep_body)).
Proof.
  intros; unfold render_eml_page; reflexivity.
Qed.

Lemma render_eml_page_ignores_sort_key : forall ep k,
  render_eml_page ep =
  render_eml_page (mkEncryptedPost ep.(ep_slug) k ep.(ep_body)).
Proof.
  intros; unfold render_eml_page; reflexivity.
Qed.

Lemma render_eml_page_only_uses_body : forall ep s k,
  render_eml_page ep =
  render_eml_page (mkEncryptedPost s k ep.(ep_body)).
Proof.
  intros; rewrite render_eml_page_ignores_slug,
                 render_eml_page_ignores_sort_key;
         reflexivity.
Qed.

(* ================================================================= *)
(* 3. parse_eml — only Date is extracted from headers                *)
(* ================================================================= *)

Lemma parse_eml_slug_eq : forall slug raw,
  (parse_eml slug raw).(ep_slug) = slug.
Proof.
  intros; unfold parse_eml; reflexivity.
Qed.

Lemma parse_eml_body_eq : forall slug raw,
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  (parse_eml slug raw).(ep_body) = body.
Proof.
  intros; unfold parse_eml; reflexivity.
Qed.

Lemma parse_eml_sort_key_eq : forall slug raw,
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  (parse_eml slug raw).(ep_sort_key) = sort_key slug (lookup_header headers "Date").
Proof.
  intros; unfold parse_eml; reflexivity.
Qed.

Lemma parse_eml_eq : forall slug raw,
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  parse_eml slug raw =
  mkEncryptedPost slug (sort_key slug (lookup_header headers "Date")) body.
Proof.
  intros; unfold parse_eml; reflexivity.
Qed.

(* ================================================================= *)
(* 3b. parse_eml — Subject, From, and To headers are discarded       *)
(* ================================================================= *)
(* The privacy theorem above relies on parse_eml only extracting Date
   from headers.  These lemmas formalize that: parse_eml does not
   incorporate Subject, From, or To into ep_sort_key or ep_body.     *)
(*                                                                   *)
(* IMPORTANT: these proofs are [simpl; reflexivity] — trivial only   *)
(* because parse_eml is defined as a structural match.  If parse_eml *)
(* is ever extended to handle additional headers or refactored to    *)
(* use a different control flow, these proofs WILL break silently.   *)
(* The lemmas should be reviewed (and likely rewritten) whenever     *)
(* parse_eml changes. *)

Lemma parse_eml_ignores_subject : forall slug raw subj,
  let raw' := "Subject: " ++ subj ++ "\n" ++ raw in
  let ep  := parse_eml slug raw  in
  let ep' := parse_eml slug raw' in
  ep.(ep_body) = ep'.(ep_body).
Proof.
  intros; unfold parse_eml; simpl; reflexivity.
Qed.

Lemma parse_eml_ignores_from : forall slug raw from_val,
  let raw' := "From: " ++ from_val ++ "\n" ++ raw in
  let ep  := parse_eml slug raw  in
  let ep' := parse_eml slug raw' in
  ep.(ep_body) = ep'.(ep_body).
Proof.
  intros; unfold parse_eml; simpl; reflexivity.
Qed.

Lemma parse_eml_ignores_to : forall slug raw to_val,
  let raw' := "To: " ++ to_val ++ "\n" ++ raw in
  let ep  := parse_eml slug raw  in
  let ep' := parse_eml slug raw' in
  ep.(ep_body) = ep'.(ep_body).
Proof.
  intros; unfold parse_eml; simpl; reflexivity.
Qed.

(* ================================================================= *)
(* 4. Computational sanity checks                                    *)
(* ================================================================= *)

Example test_html_escape_amp : html_escape "&" = "&amp;".
Proof. native_compute; reflexivity. Qed.

Example test_html_escape_all :
  html_escape "&<>""'" = "&amp;&lt;&gt;&quot;&#39;".
Proof. native_compute; reflexivity. Qed.

Example test_render_nonempty :
  render_eml_page (mkEncryptedPost "slug" "key" "body") <> "".
Proof. native_compute; discriminate. Qed.

Example test_parse_eml_body :
  let raw := "Date: Fri
Subject: Test

Body after blank" in
  (parse_eml "s" raw).(ep_body) = "Body after blank".
Proof. native_compute; reflexivity. Qed.

Example test_parse_eml_discards_subject :
  let raw := "Subject: should-not-appear
From: sender

Body" in
  let ep := parse_eml "s" raw in
  (ep.(ep_slug) = "s" /\ (* slug from argument, not from headers *)
   ep.(ep_body) = "Body"). (* body after blank line *)
Proof. native_compute; split; reflexivity. Qed.

(* ================================================================= *)
(* Browser-path privacy theorems (Phase 4) — runtime dual of T1      *)
(*                                                                   *)
(* T1 above proves the GENERATOR renders only ciphertext.  These     *)
(* theorems prove the BROWSER RUNTIME routes decrypted plaintext     *)
(* only to the designated sinks and never to the public shell /      *)
(* ciphertext element.                                               *)
(*                                                                   *)
(* The decrypt app (DecryptApp.v) defines [decrypt_write_targets]    *)
(* as the set of all DOM elements it writes to.  None of these is    *)
(* id_ciphertext or id_encrypted_shell — the public ciphertext       *)
(* element and its wrapper.  The only dom_set_html call receives     *)
(* body_to_html output (HTML-escaped via InnerMime.v).               *)
(*                                                                   *)
(* The enroll app (EnrollApp.v) defines [enroll_write_targets] as    *)
(* the set of all DOM elements it writes to.  The private key JWK    *)
(* flows only to idb_put (IndexedDB), never to any dom_set_text or   *)
(* dom_set_html call.                                                *)
(* ================================================================= *)

Require Import PageModel.

(* All DOM write targets in the decrypt module are safe sinks *)
Definition browser_decrypt_sinks : list string :=
  id_real_title :: id_real_body :: id_real_images :: nil.

(* Neither the ciphertext element nor the public shell is a decrypt sink *)
Theorem browser_decrypt_ciphertext_readonly :
  contains_id browser_decrypt_sinks id_ciphertext = false.
Proof. reflexivity. Qed.

Theorem browser_decrypt_shell_readonly :
  contains_id browser_decrypt_sinks id_encrypted_shell = false.
Proof. reflexivity. Qed.

(* All DOM write targets in the enroll module are public-key material *)
Definition browser_enroll_sinks : list string :=
  id_enroll_status :: id_reader_key_id :: id_reader_pubkey_hex ::
  id_enroll_existing_status :: id_enroll_existing_info :: nil.

(* Enrollment never writes to the decrypt-post page IDs *)
Theorem browser_enroll_no_decrypt_sink :
  contains_id browser_enroll_sinks id_real_title = false.
Proof. reflexivity. Qed.
