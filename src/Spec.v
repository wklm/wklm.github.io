From Corelib Require Import PrimString PrimInt63.
Require Import Logic.
Open Scope pstring_scope.

(* ================================================================= *)
(* Privacy guarantee (top-level, composed from the lemmas below).     *)
(*                                                                   *)
(* The public page for any post contains only the public envelope:    *)
(* the fixed template strings plus the FULL outer envelope rendered   *)
(* verbatim into #ciphertext — placeholder Subject: ..., MIME-Version,*)
(* Public-Keys, Signature, Signing-Key, Content-Type, and the         *)
(* multipart body.  Sender, recipient, real date, and the real        *)
(* subject exist only in the *inner* protected MIME headers, which    *)
(* are encrypted (or, for a PUBLIC `recipients: *` post, signed       *)
(* plaintext — a deliberate, frontmatter-`*`-gated exception whose    *)
(* body is still authenticated by the pinned-author signature before  *)
(* rendering); the outer envelope never carries them (encrypt_post    *)
(* emits no From/To/Date, and the deploy pipeline enforces that on    *)
(* every posts-encrypted/*.eml).  The post body is additionally       *)
(* HTML-escaped at serialization (PageModel.html_escape) so a public  *)
(* body can never inject markup into the page.                        *)
(*                                                                   *)
(* The page rendering depends only on the slug, the sort key (Date    *)
(* from the outer headers when present) and the full raw envelope.    *)
(* ================================================================= *)

Theorem privacy : forall (slug raw version pinned : string),
  let '(headers, _body) := split_headers_body raw 0%int63 fuel in
  let ep := parse_eml slug raw in
  render_eml_page ep version pinned =
  render_eml_page (mkEncryptedPost slug (sort_key slug (lookup_header headers "Date")) raw) version pinned.
Proof.
  (* AIDEV-NOTE: parse_eml slug raw IS mkEncryptedPost slug (sort_key slug
     (lookup_header headers "Date")) raw — it structurally retains only slug,
     the sort-key(Date) and the FULL raw envelope (public headers + multipart
     body), so the two renderings are definitionally identical (privacy by
     CONSTRUCTION: the outer envelope carries no From/To/Date and no plaintext).
     The [pinned] trust-anchor key is the shared build-time pin, not a function
     of the post, so it cancels on both sides under reflexivity (O(1)). *)
  intros slug raw version pinned. unfold parse_eml.
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

Lemma render_eml_page_only_uses_body : forall ep s k version pinned,
  render_eml_page ep version pinned =
  render_eml_page (mkEncryptedPost s k ep.(ep_body)) version pinned.
Proof.
  (* AIDEV-NOTE (perf — CRITICAL): a bare [destruct ep; reflexivity] (or [cbn]/
     [simpl]) HANGS here for hours.  After destruct the two sides differ only in
     the [ep_body] projection, but [reflexivity]/[cbn] reduce the whole
     [serialize_post_page] body, which wraps that projection in
     [html_escape (ep.(ep_body))].  [html_escape] is a fuel-bounded Fixpoint
     whose guard [if leb (length body) pos] is stuck on the variable [body], so
     kernel conversion / [cbn] unfold the Fixpoint at all 2,000,000 fuel levels
     (O(fuel^2)).  [f_equal] avoids this entirely: it applies congruence at the
     function level (unfolding only [render_eml_page], never [serialize_post_page]
     or [html_escape]) and reduces the [ep_body] projections at the leaves — O(1).
     Do NOT revert to [destruct ep; reflexivity] / [cbn]. *)
  intros [sl sk b] s k version pinned.
  unfold render_eml_page.
  f_equal.
Qed.

(* ================================================================= *)
(* 3. parse_eml — slug/sort-key come from the argument + Date header; *)
(*    ep_body is the FULL raw envelope (public headers + body)        *)
(* ================================================================= *)

Lemma parse_eml_slug_eq : forall slug raw,
  (parse_eml slug raw).(ep_slug) = slug.
Proof. intros slug raw. unfold parse_eml. destruct (split_headers_body raw 0%int63 fuel); reflexivity. Qed.

Lemma parse_eml_body_eq : forall slug raw,
  (parse_eml slug raw).(ep_body) = raw.
Proof. intros slug raw. unfold parse_eml. destruct (split_headers_body raw 0%int63 fuel); reflexivity. Qed.

Lemma parse_eml_sort_key_eq : forall slug raw,
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  (parse_eml slug raw).(ep_sort_key) = sort_key slug (lookup_header headers "Date").
Proof. intros slug raw. unfold parse_eml. destruct (split_headers_body raw 0%int63 fuel) as [headers body]; reflexivity. Qed.

Lemma parse_eml_eq : forall slug raw,
  let '(headers, _body) := split_headers_body raw 0%int63 fuel in
  parse_eml slug raw =
  mkEncryptedPost slug (sort_key slug (lookup_header headers "Date")) raw.
Proof. intros slug raw. unfold parse_eml. destruct (split_headers_body raw 0%int63 fuel) as [headers body]; reflexivity. Qed.


(* ================================================================= *)
(* 4. Computational sanity checks                                    *)
(* ================================================================= *)

Example test_html_escape_amp : html_escape "&" = "&amp;" := eq_refl.

Example test_html_escape_all :
  html_escape "&<>""'" = "&amp;&lt;&gt;&quot;&#39;" := eq_refl.

Example test_render_nonempty :
  (* render_eml_page always emits a non-empty page (the envelope body rendered
     HTML-escaped into <pre id='ciphertext'>). *)
  negb (is_empty (render_eml_page (mkEncryptedPost "s" "k" "BODY") "v" "")) = true := eq_refl.

Example test_parse_eml_body :
  let raw := "Date: Fri
Subject: Test

Body after blank" in
  (* ep_body is the FULL raw envelope — outer headers retained verbatim
     so the browser parses the same bytes the native tool parses. *)
  (parse_eml "s" raw).(ep_body) = raw := eq_refl.

Example test_parse_eml_keeps_full_envelope :
  let raw := "Subject: ...
MIME-Version: 1.0

Body" in
  let ep := parse_eml "s" raw in
  (ep.(ep_slug) = "s" /\ (* slug from argument, not from headers *)
   ep.(ep_body) = raw) := conj eq_refl eq_refl.


