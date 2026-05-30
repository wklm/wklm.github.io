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
Require Import Typeset.Metrics.      (* shape_paragraph / advance_of *)
Require Import Typeset.GlyphLayout.  (* layout_paragraph / quad (q_x/q_y/q_uv) *)

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
    ok <- wa_get cred "crane-decrypt-challenge" ;;
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
  | names => dom_set_text "real-images" (images_label names)
  end.

(* Wave 2: paragraph chunking (render_paras above) bounds each Knuth–Plass DP
   call to a single paragraph; combined with the KnuthPlass prefix-sum perf fix
   it renders arbitrary-length post bodies without hanging. *)

(* ================= Render ========================================== *)
Definition render_decrypted (plaintext : string) : BIO unit :=
  let ic := extract_inner_text plaintext in
  _ <- dom_hide "encrypted-shell" ;;
  _ <- dom_hide "decrypt-ui" ;;
  _ <- dom_show "decrypted-content" ;;
  _ <- dom_set_text "real-title" (inner_subject ic) ;;
  if andb (is_empty (inner_body ic))
          (match inner_images ic with nil => true | _ => false end)
  then
    dom_set_text "real-body"
      "(The decrypted message contained no readable text.)"
  else
    (* Accessible text alternative (unchanged — the e2e #real-body assertion and
       screen-reader access depend on it) ... *)
    _ <- dom_set_html "real-body" (body_to_html (inner_body ic)) ;;
    _ <- render_images ic ;;
    (* ... then the primary VISUAL surface: typeset the body onto the canvas. *)
    render_canvas (inner_body ic).

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
              _ <- dom_set_text "decrypt-error"
                     "WebAuthn authentication failed. Please authenticate to decrypt this post." ;;
              Ret true
            else
              let cek := unwrap_fallback priv_jwk ek wrapped kid in
              if is_empty cek then
                _ <- dom_set_text "decrypt-error"
                       "Failed to unwrap the content encryption key." ;;
                Ret true
              else
                let inner := decrypt_body_fallback cek (env_ct_package env) slug in
                if is_empty inner then
                  _ <- dom_set_text "decrypt-error"
                         "Failed to decrypt the post body." ;;
                  Ret true
                else
                  _ <- render_decrypted inner ;;
                  Ret true
        end
  end.

(* ================= Decrypt action ================================= *)
Definition do_decrypt : BIO unit :=
  _ <- dom_set_text "decrypt-status" "Decrypting..." ;;
  eml <- dom_get_text "ciphertext" ;;
  let env := parse_envelope eml in
  if is_empty (env_ct_package env) then
    dom_set_text "decrypt-error" "No ciphertext found in envelope."
  else
    keys_json <- idb_get_all "reader-keys" ;;
    let kn := json_array_len keys_json in
    if leb kn 0%int63 then
      dom_set_text "decrypt-error"
        "No reader key found on this device. Visit the enrollment page to create one."
    else
      slug <- dom_path_slug ;;
      matched <- try_keys_aux keys_json 0%int63 kn env slug 64%nat ;;
      if matched then Ret tt
      else
        _ <- ss_remove "crane_key" ;;
        dom_set_text "decrypt-error"
          "Your enrolled key is not a recipient for this post, or no key is enrolled.".

(* ================= On-load (post page vs inbox) =================== *)
Definition init_post_page : BIO unit :=
  _ <- dom_show "decrypt-ui" ;;
  bind_invoke "decrypt-button".

Definition init_inbox_page : BIO unit :=
  saved <- ss_get "crane_key" ;;
  if is_empty saved then Ret tt
  else dom_set_html "inbox-status-msg" "All posts are readable with your key.".

Definition on_load : BIO unit :=
  cipher <- dom_get_text "ciphertext" ;;
  if is_empty cipher then init_inbox_page else init_post_page.

(* ================= Entry point: dispatch on the click flag ======== *)
Definition run : BIO unit :=
  flag <- action_flag ;;
  if string_eqb flag "1" then do_decrypt else on_load.

Set Warnings "-crane-extraction-default-directory".

Crane Extraction "crane_decrypt" run.
