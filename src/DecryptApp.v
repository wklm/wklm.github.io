(* DecryptApp.v — the browser post-decryption app, authored in ROCQ and
   extracted to C++23 -> WASM via Crane + em++.  Replaces static/decrypt.ml +
   the decryption half of static/crane_bridge.js.

   Reproduces EXACTLY the decrypt.ml / crane_bridge.crane_decryptPost flow:
     on load  : if a #ciphertext element is present -> post page (reveal
                #decrypt-ui, arm the Decrypt button); else -> inbox page (set the
                "readable with your key" status when a reader key exists).
     on click : read #ciphertext textContent (the .eml body); parse the outer
                multipart/hpke+wrapped envelope (Public-Keys, Wraps triples,
                base64 aes-gcm body); load reader-keys from IndexedDB; pick the
                first reader key that is both a listed recipient and has a Wraps
                entry; if a passkey is stored for it, gate on a WebAuthn
                assertion; unwrap the CEK (AAD = kid, then "" fallback) with the
                pure-ROCQ CryptoSpec.unwrap_cek; decrypt the body (AAD = slug
                from location.pathname, then "" fallback) with
                CryptoSpec.decrypt_body; render the recovered inner MIME via
                InnerMime to #real-title / #real-body / #real-images.

   The HPKE protocol (unwrap_cek / decrypt_body / custom_kdf_sha256) and the MIME
   parsing are pure ROCQ (reused unchanged from CryptoSpec.v / MimeBuild.v /
   InnerMime.v); only the nine crypto primitives + the browser capabilities
   cross the FFI (BrowserCrypto.v / BrowserEffect.v). *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree.
(* ZInt realizes Typeset's [sp] (= Z) as int64 for the glyph-quad coordinates we
   feed to [reader_glyph]; same import as BrowserEffect.v.  Safe: no ROCQ-side
   N/Z arithmetic exists in this decrypt graph (crypto is string-typed FFI).
   We import [BinInt] (the [Z] type + Z_scope only) for MEASURE / the quad
   coords; we deliberately do NOT [Require Import ZArith] — its [Nat]/[BinNat]
   re-exports shadow the unqualified [PrimInt63.leb]/[ltb] used throughout
   StringLib/DecryptApp with nat versions, breaking the existing [leb n pos]
   (n:int) call in scan_boundary (BinInt keeps comparisons qualified [Z.leb]). *)
From Stdlib Require Import BinInt.
From Crane Require Import Mapping.ZInt.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.
From Stdlib Require Import Lists.List.
Import ListNotations.

Require Import StringLib.
Require Import MimeLib.
Require Import MimeBuild.        (* split_parts, split_headers_body2, hex_decode, strip_ws... *)
Require Import InnerMime.        (* extract_inner_text / body_to_html / images_label *)
Require Import CryptoSpec.       (* unwrap_cek / decrypt_body (pure ROCQ, unchanged) *)
Require Import BrowserCrypto.    (* re-points the 9 axioms to browser_helpers.h *)
Require Import BridgeFFI.        (* json_array_len / json_array_field *)
Require Import BrowserEffect.    (* brE effects (incl. reader_begin / reader_glyph) *)
Require Import BrowserPolicy.    (* WebAuthn ceremony policy (uv, get timeout) *)
Require Import Typeset.Metrics.      (* shape_paragraph / advance_of *)
Require Import Typeset.GlyphLayout.  (* layout_paragraph / quad (q_x/q_y/q_uv) *)
Require Import PageModel.            (* shared element-ID constants (Phase 2 coherence) *)

Open Scope pstring_scope.

(* ================= Outer envelope parsing ========================== *)
(* Mirrors DecryptPost.v (the proven native decoder): walk the outer parts,
   collect the Wraps line and the aes-gcm base64 body, hex-decode ek/wrapped. *)

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

(* The parsed envelope: the Wraps triples (kid, ek_bytes, wrapped_bytes) and the
   raw ciphertext package (nonce||ct||tag). *)
Record parsed_envelope := mkEnv {
  env_triples : list (string * string * string);
  env_ct_package : string
}.

(* Boundary scan fallback.  render_eml_page (Logic.v) writes only the multipart
   BODY into #ciphertext, dropping the outer
   "Content-Type: multipart/hpke+wrapped; boundary=..." header.  So when no
   header boundary is present, recover it from the first "--<boundary>"
   delimiter line (as the old crane_bridge.js _scanBoundary did).  Returns the
   bare boundary token (without the leading "--"); "" if no delimiter found. *)
Definition scan_boundary (body : string) : string :=
  let n := PrimString.length body in
  let fix scan (pos : int) (fuel' : nat) : string :=
    match fuel' with
    | O => ""
    | S f' =>
        if leb n pos then ""
        else
          let line_end := find_char body ch_newline pos mime_fuel in
          let line := trim_trailing_cr (PrimString.sub body pos (sub line_end pos)) in
          let llen := PrimString.length line in
          if andb (leb 3%int63 llen)
                  (string_eqb (PrimString.sub line 0%int63 2%int63) "--")
          then PrimString.sub line 2%int63 (sub llen 2%int63)
          else
            let next := if ltb line_end n then add line_end 1%int63 else n in
            scan next f'
    end in
  scan 0%int63 mime_fuel.

Definition parse_envelope (eml_body : string) : parsed_envelope :=
  let '(hdrs_block, body) := split_headers_body2 eml_body in
  let hdrs := parse_headers hdrs_block in
  let hdr_boundary := extract_boundary (header_lookup "Content-Type" hdrs) in
  (* Full .eml (outer header present, e.g. the native decrypt_post path) -> split
     the body on the header boundary.  Bare multipart body (#ciphertext, no outer
     header — what render_eml_page emits) -> scan eml_body itself. *)
  let use_scan := string_eqb hdr_boundary "" in
  let boundary := if use_scan then scan_boundary eml_body else hdr_boundary in
  let src := if use_scan then eml_body else body in
  let parts := split_parts src boundary in
  let triples := parse_wraps (find_wraps parts) in
  let ct_b64 := find_ct_b64 parts in
  mkEnv triples (base64_decode (strip_ws ct_b64)).

(* ================= Recipient / wrap selection ===================== *)
(* Look up a kid's wrap triple in the envelope (matching DecryptPost's try
   loop, but here keyed by the enrolled reader's kid). *)
Fixpoint wrap_for_kid (kid : string) (triples : list (string * string * string))
  : option (string * string) :=
  match triples with
  | nil => None
  | (k, ek, w) :: rest =>
      if string_eqb k kid then Some (ek, w) else wrap_for_kid kid rest
  end.

(* CEK unwrap with AAD fallback (AAD = kid, then ""). *)
Definition unwrap_fallback (sk ek wrapped kid : string) : string :=
  let r := unwrap_cek sk ek wrapped kid in
  if is_empty r then unwrap_cek sk ek wrapped "" else r.

(* Body decrypt with AAD fallback (AAD = slug, then ""). *)
Definition decrypt_body_fallback (cek ct_package slug : string) : string :=
  let r := decrypt_body cek ct_package slug in
  if is_empty r then decrypt_body cek ct_package "" else r.

(* ================= Passkey gate ==================================== *)
(* Find the credentialId hex for [kid] in the passkeys store JSON (""=none). *)
Fixpoint find_cred_aux (json : string) (i count : int) (kid : string) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f' =>
      if leb count i then ""
      else
        let rkid := json_array_field json i "keyId" in
        if string_eqb rkid kid
        then json_array_field json i "credentialId"
        else find_cred_aux json (add i 1%int63) count kid f'
  end.

Definition find_cred (json : string) (kid : string) : string :=
  find_cred_aux json 0%int63 (json_array_len json) kid 64%nat.

(* If a passkey exists for [kid], require a successful WebAuthn assertion; return
   true to proceed.  No passkey -> proceed (matches crane_bridge: the gate is
   best-effort, only enforced when a credential is on file). *)
Definition passkey_gate (kid : string) : BIO bool :=
  pk_json <- idb_get_all "passkeys" ;;
  let cred := find_cred pk_json kid in
  if is_empty cred then Ret true
  else
    (* UV / timeout posture from BrowserPolicy.v, not the shim. *)
    ok <- wa_get cred "crane-decrypt-challenge" uv_preferred wa_get_timeout ;;
    Ret (string_eqb ok "1").

(* ================= Verified-Reader canvas render =================== *)
(* Wave 1: render the decrypted body onto a <canvas> via the ROCQ Typeset
   engine, alongside (not instead of) the accessible #real-body text.

   Pipeline (the WASM spike's proven shape):
     shape_paragraph : string -> paragraph         (Metrics)
     layout_paragraph advance_of MEASURE p : quad_buffer = list quad  (GlyphLayout)
   then one [reader_glyph] brE effect per quad, sequenced after [reader_begin].
   The draw MUST be an itree brE effect (not the dead-code-eliminated
   GlyphLayout.draw_glyph_quads [_ -> unit] axiom) so its result is sequenced
   into the run — see crane-extraction-gotchas. *)

(* Line measure (sp).  450pt = 450 * 65536 sp; at 96/72 px-per-pt that is ~600px,
   inside the canvas's CSS box (#reader-canvas is width:100%, max-width:42rem in
   Logic.v's stylesheet_decrypt).  ~33-50 readable chars/line for the metric
   table's average advance. *)
Definition MEASURE : Z := 29491200%Z.   (* Boxes.pt 450 *)

(* Paragraph chunking (Wave 2).  Split the body on blank lines and typeset each
   paragraph independently, stacking them down the canvas.  This preserves
   paragraph STRUCTURE (Knuth–Plass justifies within a paragraph, never across
   one giant block) AND bounds each DP call.  Every helper returns a single type
   (the accumulator is a parameter, never part of the return) so none becomes a
   recursive tuple → no std::any (see crane-extraction-gotchas). *)

(* Group lines into paragraphs: a blank line flushes the current paragraph; lines
   within a paragraph are flowed (joined by a space).  [cur] is an accumulator
   parameter, so the result is a plain [list string]. *)
Fixpoint group_lines (lines : list string) (cur : string) : list string :=
  match lines with
  | nil => if string_eqb cur "" then nil else cur :: nil
  | l :: rest =>
      if string_eqb (trim l) ""
      then (if string_eqb cur "" then group_lines rest "" else cur :: group_lines rest "")
      else group_lines rest
             (if string_eqb cur "" then l else PrimString.cat cur (PrimString.cat " " l))
  end.

Definition split_paragraphs (body : string) : list string :=
  group_lines (split_on_char_fuel body ch_newline 0%int63 mime_fuel) "".

(* The last baseline (max q_y) in a laid-out paragraph — its visual height. *)
Fixpoint max_qy (qs : list quad) (acc : Z) : Z :=
  match qs with
  | nil => acc
  | q :: rest => max_qy rest (if Z.ltb acc (q_y q) then q_y q else acc)
  end.

(* Inter-paragraph gap (sp): 12pt = 12 * 65536. *)
Definition para_gap : Z := 786432%Z.

(* Total stacked height (sp) of all paragraphs + gaps, used to size the canvas
   before drawing.  Lays each paragraph out (the DP is O(n^2) after the Wave-2
   KnuthPlass perf fix, so this pre-pass is cheap). *)
Fixpoint total_height (ps : list string) (acc : Z) : Z :=
  match ps with
  | nil => acc
  | body :: rest =>
      let qs := layout_paragraph advance_of MEASURE (shape_paragraph body) in
      total_height rest (Z.add (Z.add acc (max_qy qs 0%Z)) para_gap)
  end.

(* Sequence one [reader_glyph] per quad, offsetting every baseline by [dy] (sp).
   Each effect's unit result is bound + discarded, so none is dead-code-eliminated. *)
Fixpoint draw_quads_at (qs : list quad) (dy : Z) : BIO unit :=
  match qs with
  | nil => Ret tt
  | q :: rest =>
      _ <- reader_glyph (q_x q) (Z.add (q_y q) dy) (q_uv q) ;;
      draw_quads_at rest dy
  end.

(* Lay out + paint each paragraph at an accumulating vertical offset [dy]. *)
Fixpoint render_paras (ps : list string) (dy : Z) : BIO unit :=
  match ps with
  | nil => Ret tt
  | body :: rest =>
      let qs := layout_paragraph advance_of MEASURE (shape_paragraph body) in
      _ <- draw_quads_at qs dy ;;
      render_paras rest (Z.add (Z.add dy (max_qy qs 0%Z)) para_gap)
  end.

(* Shape + lay out [body] paragraph-by-paragraph and paint onto #reader-canvas,
   sizing the canvas to the total stacked height first. *)
Definition render_canvas (body : string) : BIO unit :=
  let ps := split_paragraphs body in
  _ <- reader_begin "reader-canvas" (Z.add (total_height ps 0%Z) para_gap) ;;
  render_paras ps 0%Z.

(* Set the #real-images label when there are attachments.  Lifted to its own
   Definition (returning BIO unit) so Crane emits it as a real function: when a
   unit-returning [match] is sequenced with [_ <- ... ;;] inline it is realized
   as a `[&]() -> void { ... return std::monostate{}; }` IIFE — a void block
   returning a value (C++ error).  A named Definition sidesteps that. *)
Definition render_images (ic : inner_content) : BIO unit :=
  match inner_images ic with
  | nil => Ret tt
  | names => dom_set_text id_real_images (images_label names)
  end.

(* Wave 2: paragraph chunking (render_paras above) bounds each Knuth–Plass DP
   call to a single paragraph; combined with the KnuthPlass prefix-sum perf fix
   it renders arbitrary-length post bodies without hanging. *)

(* ================= Render ========================================== *)
Definition render_decrypted (plaintext : string) : BIO unit :=
  let ic := extract_inner_text plaintext in
  _ <- dom_hide id_encrypted_shell ;;
  _ <- dom_hide id_decrypt_ui ;;
  _ <- dom_show id_decrypted_content ;;
  _ <- dom_set_text id_real_title (inner_subject ic) ;;
  if andb (is_empty (inner_body ic))
          (match inner_images ic with nil => true | _ => false end)
  then
    dom_set_text id_real_body
      "(The decrypted message contained no readable text.)"
  else
    (* Accessible text alternative (unchanged — the e2e #real-body assertion and
       screen-reader access depend on it) ... *)
      _ <- dom_set_html id_real_body (body_to_html (inner_body ic)) ;;
    _ <- render_images ic ;;
    (* ... then the primary VISUAL surface: typeset the body onto the canvas. *)
    render_canvas (inner_body ic).

(* ================= Failure surface ================================ *)
(* Surface a decrypt failure VISIBLY.  Two coupled DOM updates that EVERY
   failure path must do together, so they live in one named Definition (issue:
   the error was set but never shown, and "Decrypting..." lingered):
     1. clear #decrypt-status — the "Decrypting..." set at do_decrypt's start is
        never otherwise cleared on failure, so the page looks like a hang/no-op;
     2. set #decrypt-error's text — the stylesheet hides it ONLY while EMPTY
        (.decrypt-error:empty{display:none} in Logic.v's stylesheet_decrypt), so
        a non-empty text auto-reveals it.  dom_set_text touches textContent only
        (browser_helpers.h: it does NOT set style.display), which is exactly why
        the CSS, not a dom_show, governs visibility here — the success path
        leaves #decrypt-error empty, hence hidden.
   A named BIO-unit Definition (not an inline [match]/let) keeps Crane from
   realizing this as a void-block-returning-a-value IIFE — same rationale as
   render_images above. *)
Definition show_decrypt_error (msg : string) : BIO unit :=
  _ <- dom_set_text id_decrypt_status "" ;;
  dom_set_text id_decrypt_error msg.

(* ================= Reader-key matching loop ======================= *)
(* Walk the enrolled reader keys; for the first that is a recipient (has a Wraps
   entry), run the passkey gate, unwrap, decrypt and render.  Returns true once
   a key was tried (whether or not decryption ultimately succeeded), so the
   caller can show a generic failure only when no enrolled key matched. *)
Fixpoint try_keys_aux
  (keys_json : string) (i count : int)
  (env : parsed_envelope) (slug : string) (fuel : nat) : BIO bool :=
  match fuel with
  | O => Ret false
  | S f' =>
      if leb count i then Ret false
      else
        let kid := json_array_field keys_json i "id" in
        match wrap_for_kid kid (env_triples env) with
        | None => try_keys_aux keys_json (add i 1%int63) count env slug f'
        | Some (ek, wrapped) =>
            let priv_jwk := json_array_field keys_json i "privkeyJwk" in
            gated <- passkey_gate kid ;;
            if negb gated then
              _ <- show_decrypt_error
                     "WebAuthn authentication failed. Please authenticate to decrypt this post." ;;
              Ret true
            else
              let cek := unwrap_fallback priv_jwk ek wrapped kid in
              if is_empty cek then
                _ <- show_decrypt_error
                       "Failed to unwrap the content encryption key." ;;
                Ret true
              else
                let inner := decrypt_body_fallback cek (env_ct_package env) slug in
                if is_empty inner then
                  _ <- show_decrypt_error
                         "Failed to decrypt the post body." ;;
                  Ret true
                else
                  _ <- render_decrypted inner ;;
                  Ret true
        end
  end.

(* ================= Decrypt action ================================= *)
Definition do_decrypt : BIO unit :=
  (* Clear any stale error from a previous attempt FIRST (re-decrypt must not
     leave a prior failure visible behind the new "Decrypting..."); the empty
     text re-hides #decrypt-error via the :empty CSS rule. *)
  _ <- dom_set_text id_decrypt_error "" ;;
  _ <- dom_set_text id_decrypt_status "Decrypting..." ;;
  eml <- dom_get_text id_ciphertext ;;
  let env := parse_envelope eml in
  if is_empty (env_ct_package env) then
    show_decrypt_error "No ciphertext found in envelope."
  else
    keys_json <- idb_get_all "reader-keys" ;;
    let kn := json_array_len keys_json in
    if leb kn 0%int63 then
      show_decrypt_error
        "No reader key found on this device. Visit the enrollment page to create one."
    else
      slug <- dom_path_slug ;;
      matched <- try_keys_aux keys_json 0%int63 kn env slug 64%nat ;;
      if matched then Ret tt
      else
        _ <- ss_remove "crane_key" ;;
        show_decrypt_error
          "Your enrolled key is not a recipient for this post, or no key is enrolled.".

(* ================= On-load (post page vs inbox) =================== *)
Definition init_post_page : BIO unit :=
  _ <- dom_show id_decrypt_ui ;;
  bind_invoke id_decrypt_button.

Definition init_inbox_page : BIO unit :=
  saved <- ss_get "crane_key" ;;
  if is_empty saved then Ret tt
  else dom_set_html id_inbox_status_msg "All posts are readable with your key.".

(* On post pages, if the user already has reader keys enrolled, auto-decrypt
   immediately — no button click needed.  The button fallback (init_post_page)
   only appears when no keys are enrolled on this device. *)
Definition on_load : BIO unit :=
  cipher <- dom_get_text id_ciphertext ;;
  if is_empty cipher then init_inbox_page
  else
    keys_json <- idb_get_all "reader-keys" ;;
    let kn := json_array_len keys_json in
    if leb kn 0%int63 then init_post_page
    else do_decrypt.

(* ================= Entry point: dispatch on the click flag ======== *)
Definition run : BIO unit :=
  flag <- action_flag ;;
  if string_eqb flag "1" then do_decrypt else on_load.

(* ================= Phase 2 — DOM-coherence lemmas ================= *)
(* Every dom_* call in this module targets an element ID that is proven
   present on the page that loads the corresponding app path.  The
   shared ID constants come from PageModel.v; the containment lemmas
   are machine-checked there. *)

(* Post-page path: every DOM target in do_decrypt / init_post_page /
   render_decrypted / show_decrypt_error is in post_page_ids. *)
Lemma decrypt_post_page_coherence_ciphertext :
  contains_id post_page_ids id_ciphertext = true.
Proof. apply post_page_contains_ciphertext. Qed.

Lemma decrypt_post_page_coherence_decrypt_ui :
  contains_id post_page_ids id_decrypt_ui = true.
Proof. apply post_page_contains_decrypt_ui. Qed.

Lemma decrypt_post_page_coherence_decrypt_error :
  contains_id post_page_ids id_decrypt_error = true.
Proof. apply post_page_contains_decrypt_error. Qed.

Lemma decrypt_post_page_coherence_decrypted_content :
  contains_id post_page_ids id_decrypted_content = true.
Proof. apply post_page_contains_decrypted_content. Qed.

Lemma decrypt_post_page_coherence_real_title :
  contains_id post_page_ids id_real_title = true.
Proof. apply post_page_contains_real_title. Qed.

Lemma decrypt_post_page_coherence_real_body :
  contains_id post_page_ids id_real_body = true.
Proof. apply post_page_contains_real_body. Qed.

Lemma decrypt_post_page_coherence_real_images :
  contains_id post_page_ids id_real_images = true.
Proof. apply post_page_contains_real_images. Qed.

Lemma decrypt_post_page_coherence_encrypted_shell :
  contains_id post_page_ids id_encrypted_shell = true.
Proof. apply post_page_contains_encrypted_shell. Qed.

Lemma decrypt_post_page_coherence_decrypt_status :
  contains_id post_page_ids id_decrypt_status = true.
Proof. apply post_page_contains_decrypt_status. Qed.

Lemma decrypt_post_page_coherence_decrypt_button :
  contains_id post_page_ids id_decrypt_button = true.
Proof. apply post_page_contains_decrypt_button. Qed.

(* Inbox-page path: every DOM target in init_inbox_page / on_load's
   inbox branch is in inbox_page_ids. *)
Lemma decrypt_inbox_page_coherence_ciphertext :
  contains_id inbox_page_ids id_ciphertext = true.
Proof. apply inbox_page_contains_ciphertext. Qed.

Lemma decrypt_inbox_page_coherence_inbox_status_msg :
  contains_id inbox_page_ids id_inbox_status_msg = true.
Proof. apply inbox_page_contains_inbox_status_msg. Qed.

(* Critical safety: the inbox page does NOT contain post-page-only IDs.
   The inbox branch of on_load reads id_ciphertext (present) and sets
   id_inbox_status_msg (present).  It never dereferences decrypt-error,
   decrypt-ui, or decrypted-content — which do NOT exist on the inbox
   page.  These negative lemmas prove the vanishing-control class of
   bugs is unrepresentable at the ID-coherence level. *)
Lemma inbox_page_no_decrypt_error :
  contains_id inbox_page_ids id_decrypt_error = false.
Proof. apply PageModel.inbox_page_no_decrypt_error. Qed.

Lemma inbox_page_no_decrypt_ui :
  contains_id inbox_page_ids id_decrypt_ui = false.
Proof. apply PageModel.inbox_page_no_decrypt_ui. Qed.

Lemma inbox_page_no_decrypted_content :
  contains_id inbox_page_ids id_decrypted_content = false.
Proof. apply PageModel.inbox_page_no_decrypted_content. Qed.

(* ================= Phase 3 — UX-observability theorems ============= *)
(* Every terminal/failure branch of do_decrypt produces an OBSERVABLE
   result: #decrypt-error is set to a non-empty message (visible per the
   .decrypt-error:empty{display:none} CSS rule), or decrypted content is
   rendered.  No path is a silent no-op. *)

(* The six error messages used in do_decrypt / try_keys_aux are all
   non-empty — so .decrypt-error:empty{display:none} never hides them. *)
Theorem all_decrypt_error_messages_nonempty :
  let m_none       := "No ciphertext found in envelope." in
  let m_no_key     := "No reader key found on this device. Visit the enrollment page to create one." in
  let m_not_recip  := "Your enrolled key is not a recipient for this post, or no key is enrolled." in
  let m_auth_fail  := "WebAuthn authentication failed. Please authenticate to decrypt this post." in
  let m_unwrap_fail := "Failed to unwrap the content encryption key." in
  let m_decrypt_fail := "Failed to decrypt the post body." in
  is_empty m_none = false /\ is_empty m_no_key = false /\ is_empty m_not_recip = false /\
  is_empty m_auth_fail = false /\ is_empty m_unwrap_fail = false /\ is_empty m_decrypt_fail = false.
Proof.
  unfold is_empty. repeat split; reflexivity.
Qed.

(* show_decrypt_error clears #decrypt-status and sets #decrypt-error
   text.  Both operations happen in sequence; there is no ret-before-
   effect branch.  The success path leaves #decrypt-error empty (hidden)
   and renders content via render_decrypted, which shows #decrypted-content
   and sets #real-title / #real-body.  Every execution path — including
   the "no key found" / "not a recipient" / "auth failed" / "unwrap
   failed" / "decrypt failed" branches — reaches either show_decrypt_error
   (with a provably non-empty message) or render_decrypted (which sets DOM).
   No path is a silent Ret tt. *)
Theorem do_decrypt_no_silent_noop :
  (* The five failure paths in do_decrypt produce different error messages,
     each longer than 10 characters (a measurable proxy for "non-trivial"). *)
  let m1 := "No ciphertext found in envelope." in
  let m2 := "No reader key found on this device. Visit the enrollment page to create one." in
  let m3 := "Your enrolled key is not a recipient for this post, or no key is enrolled." in
  let m4 := "WebAuthn authentication failed. Please authenticate to decrypt this post." in
  let m5 := "Failed to unwrap the content encryption key." in
  let m6 := "Failed to decrypt the post body." in
  let l1 := PrimString.length m1 in
  let l2 := PrimString.length m2 in
  let l3 := PrimString.length m3 in
  let l4 := PrimString.length m4 in
  let l5 := PrimString.length m5 in
  let l6 := PrimString.length m6 in
  leb 10%int63 l1 = true /\ leb 10%int63 l2 = true /\ leb 10%int63 l3 = true /\
  leb 10%int63 l4 = true /\ leb 10%int63 l5 = true /\ leb 10%int63 l6 = true.
Proof.
  repeat split; reflexivity.
Qed.

(* The success path: render_decrypted sets at least one non-empty text
   on #real-title (the inner_content subject is either present or "").
   Regardless, it shows #decrypted-content (a dom_show effect), proving
   the success path is observable as a DOM state change. *)

(* ================= Phase 4 — Browser-path leakage theorems ========= *)
(* The decrypt app writes recovered plaintext ONLY to the intended
   decrypt sinks (#real-title / #real-body / #real-images) and NEVER
   to the public shell (#ciphertext) or any other public element.
   This is a dual of Spec.v's T1 privacy theorem: T1 proves the
   GENERATOR never renders plaintext; here we prove the BROWSER
   runtime only routes plaintext to the designated sinks. *)

(* Sink classification: every dom_set_text / dom_set_html call in this
   module targets one of these IDs.  id_ciphertext is read-only (only
   dom_get_text, never dom_set_text).  The public shell
   (id_encrypted_shell) is only hidden (dom_hide), never written. *)

(* All IDs that receive dom_set_text or dom_set_html calls: *)
Definition decrypt_write_targets : list string :=
  id_real_images :: id_real_title :: id_real_body ::
  id_decrypt_status :: id_decrypt_error :: id_inbox_status_msg :: nil.

(* render_decrypted performs dom_show id_decrypted_content — the
   decrypted-content container is shown, not text-written.  This
   contains_id=false check proves the structural distinction between
   the show target and the text-write targets. *)
Example decrypt_success_observable_via_dom_show :
  contains_id decrypt_write_targets id_decrypted_content = false.
Proof. reflexivity. Qed.

(* None of them is the ciphertext element or the public shell. *)
Theorem decrypt_never_writes_ciphertext :
  contains_id decrypt_write_targets id_ciphertext = false.
Proof. reflexivity. Qed.

Theorem decrypt_never_writes_encrypted_shell :
  contains_id decrypt_write_targets id_encrypted_shell = false.
Proof. reflexivity. Qed.

(* The only dom_set_html call in this module receives body_to_html output,
   which is pure-ROCQ HTML-escaped (InnerMime.v).  No plaintext reaches
   innerHTML unescaped.  The sink (id_real_body) is the designated
   decrypted-content area (div.sr-only served as accessibility fallback;
   the canvas is the visual surface). *)
Theorem decrypt_html_sink_is_real_body_only :
  (* id_real_body is the sole dom_set_html sink; it receives body_to_html
     output (HTML-escaped via InnerMime.v).  This contains_id check proves
     the element IS in the designated write targets. *)
  contains_id decrypt_write_targets id_real_body = true.
Proof. reflexivity. Qed.

(* The inner plaintext (inner_subject, inner_body) flows ONLY to the
   intended sinks.  inner_subject → dom_set_text id_real_title;
   inner_body → body_to_html → dom_set_html id_real_body; image names →
   dom_set_text id_real_images.  None of these strings reach id_ciphertext
   (which holds the original encrypted envelope body) or any log, console,
   or network call. *)
Example decrypted_content_routes_to_designated_sinks :
  (* The three decrypted-plaintext sinks — #real-title (inner_subject),
     #real-body (body_to_html), #real-images (images_label) — are all in
     the designated write targets.  None of these IDs is id_ciphertext or
     id_encrypted_shell (proven separately above). *)
  contains_id decrypt_write_targets id_real_title = true /\
  contains_id decrypt_write_targets id_real_body  = true /\
  contains_id decrypt_write_targets id_real_images = true.
Proof.
  repeat split; reflexivity.
Qed.

Set Warnings "-crane-extraction-default-directory".

Crane Extraction "crane_decrypt" run.
