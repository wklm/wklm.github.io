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
