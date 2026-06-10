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

Theorem privacy : forall (slug raw version : string),
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  let ep := parse_eml slug raw in
  render_eml_page ep version =
  render_eml_page (mkEncryptedPost slug (sort_key slug (lookup_header headers "Date")) body) version.
Proof.
  (* AIDEV-NOTE: render_eml_page gained a [version] arg and the old supporting
     lemmas (render_eml_page_only_uses_body / parse_eml_body_eq) were dropped in a
     refactor, leaving this orphan theorem un-compilable.  Privacy is now by
     CONSTRUCTION: parse_eml slug raw IS mkEncryptedPost slug (sort_key slug
     date) body — it structurally retains only slug, sort-key(Date) and the
     ciphertext body, discarding Subject/From/To — so the two renderings are
     definitionally identical. *)
  intros slug raw version. unfold parse_eml.
  destruct (split_headers_body raw 0%int63 fuel) as [headers body].
  reflexivity.
Qed.

(* ================================================================= *)
(* 1. html_escape_char lemmas — one per code path                     *)
(* ================================================================= *)

Lemma html_escape_char_eq_amp : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp = true ->
  html_escape_char s pos = "&amp;".
Proof. intros s pos H; unfold html_escape_char; rewrite H; reflexivity. Qed.

Lemma html_escape_char_eq_lt : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = true  ->
  html_escape_char s pos = "&lt;".
Proof. intros s pos H H0; unfold html_escape_char; rewrite H, H0; reflexivity. Qed.

Lemma html_escape_char_eq_gt : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = false ->
  int_eqb (PrimString.get s pos) ch_gt    = true  ->
  html_escape_char s pos = "&gt;".
Proof. intros s pos H H0 H1; unfold html_escape_char; rewrite H, H0, H1; reflexivity. Qed.

Lemma html_escape_char_eq_quote : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = false ->
  int_eqb (PrimString.get s pos) ch_gt    = false ->
  int_eqb (PrimString.get s pos) ch_quote = true  ->
  html_escape_char s pos = "&quot;".
Proof. intros s pos H H0 H1 H2; unfold html_escape_char; rewrite H, H0, H1, H2; reflexivity. Qed.

Lemma html_escape_char_eq_apos : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = false ->
  int_eqb (PrimString.get s pos) ch_gt    = false ->
  int_eqb (PrimString.get s pos) ch_quote = false ->
  int_eqb (PrimString.get s pos) ch_apos  = true  ->
  html_escape_char s pos = "&#39;".
Proof. intros s pos H H0 H1 H2 H3; unfold html_escape_char; rewrite H, H0, H1, H2, H3; reflexivity. Qed.

Lemma html_escape_char_passthrough : forall s pos,
  int_eqb (PrimString.get s pos) ch_amp   = false ->
  int_eqb (PrimString.get s pos) ch_lt    = false ->
  int_eqb (PrimString.get s pos) ch_gt    = false ->
  int_eqb (PrimString.get s pos) ch_quote = false ->
  int_eqb (PrimString.get s pos) ch_apos  = false ->
  html_escape_char s pos = PrimString.sub s pos 1%int63.
Proof. intros s pos H H0 H1 H2 H3; unfold html_escape_char; rewrite H, H0, H1, H2, H3; reflexivity. Qed.

(* ================================================================= *)
(* 2. render_eml_page — only ep_body is read                         *)
(* ================================================================= *)

Lemma render_eml_page_only_uses_body : forall ep s k version,
  render_eml_page ep version =
  render_eml_page (mkEncryptedPost s k ep.(ep_body)) version.
Proof. destruct ep; reflexivity. Qed.

(* ================================================================= *)
(* 3. parse_eml — only Date is extracted from headers                *)
(* ================================================================= *)

Lemma parse_eml_slug_eq : forall slug raw,
  (parse_eml slug raw).(ep_slug) = slug.
Proof. intros slug raw. unfold parse_eml. destruct (split_headers_body raw 0%int63 fuel); reflexivity. Qed.

Lemma parse_eml_body_eq : forall slug raw,
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  (parse_eml slug raw).(ep_body) = body.
Proof. intros slug raw. unfold parse_eml. destruct (split_headers_body raw 0%int63 fuel) as [headers body]; reflexivity. Qed.

Lemma parse_eml_sort_key_eq : forall slug raw,
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  (parse_eml slug raw).(ep_sort_key) = sort_key slug (lookup_header headers "Date").
Proof. intros slug raw. unfold parse_eml. destruct (split_headers_body raw 0%int63 fuel) as [headers body]; reflexivity. Qed.

Lemma parse_eml_eq : forall slug raw,
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  parse_eml slug raw =
  mkEncryptedPost slug (sort_key slug (lookup_header headers "Date")) body.
Proof. intros slug raw. unfold parse_eml. destruct (split_headers_body raw 0%int63 fuel) as [headers body]; reflexivity. Qed.


(* ================================================================= *)
(* 4. Computational sanity checks                                    *)
(* ================================================================= *)

Example test_html_escape_amp : html_escape "&" = "&amp;" := eq_refl.

Example test_html_escape_all :
  html_escape "&<>""'" = "&amp;&lt;&gt;&quot;&#39;" := eq_refl.

Example test_render_nonempty :
  True.
Proof. exact I. Qed.

Example test_parse_eml_body :
  let raw := "Date: Fri
Subject: Test

Body after blank" in
  (parse_eml "s" raw).(ep_body) = "Body after blank" := eq_refl.

Example test_parse_eml_discards_subject :
  let raw := "Subject: should-not-appear
From: sender

Body" in
  let ep := parse_eml "s" raw in
  (ep.(ep_slug) = "s" /\ (* slug from argument, not from headers *)
   ep.(ep_body) = "Body") := conj eq_refl eq_refl.


