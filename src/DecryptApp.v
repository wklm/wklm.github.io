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

(* The parsed envelope: the Wraps triples (kid, ek_bytes, wrapped_bytes), the
   raw ciphertext package (nonce||ct||tag), and the authorship signature. *)
Record parsed_envelope := mkEnv {
  env_triples : list (string * string * string);
  env_ct_package : string;
  env_signature : string;
  env_signing_key : string
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
  let sig_hex := header_lookup "Signature" hdrs in
  let sign_key_hex := header_lookup "Signing-Key" hdrs in
  mkEnv triples (base64_decode (strip_ws ct_b64))
        (hex_decode (trim sig_hex)) (hex_decode (trim sign_key_hex)).

(* ================= Recipient / wrap selection ===================== *)
Fixpoint wrap_for_kid (kid : string) (triples : list (string * string * string))
  : option (string * string) :=
  match triples with
  | nil => None
  | (k, ek, w) :: rest =>
      if string_eqb k kid then Some (ek, w) else wrap_for_kid kid rest
  end.

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
   true to proceed.  No passkey -> REJECT (mandatory passkey requirement). *)
Definition passkey_gate (kid : string) : BIO bool :=
  pk_json <- idb_get_all "passkeys" ;;
  let cred := find_cred pk_json kid in
  if is_empty cred then Ret false
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
Fixpoint group_lines_tr (lines : list string) (cur : string) (acc : list string) : list string :=
  match lines with
  | nil => if string_eqb cur "" then rev acc else rev (cur :: acc)
  | l :: rest =>
      if string_eqb (trim l) ""
      then (if string_eqb cur "" then group_lines_tr rest "" acc else group_lines_tr rest "" (cur :: acc))
      else group_lines_tr rest
             (if string_eqb cur "" then l else PrimString.cat cur (PrimString.cat " " l))
             acc
  end.

Definition split_paragraphs (body : string) : list string :=
  group_lines_tr (split_on_char_fuel body ch_newline 0%int63 mime_fuel) "" nil.

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
   KnuthPlass perf fix, so this pre-pass is cheap).

   Tail-recursive via accumulator + [rev] so Crane-extracted C++ can be
   tail-call-optimized by em++ -O2, keeping the WASM call stack shallow
   under Emscripten Asyncify instrumentation. *)
Inductive ParaLayout : Type :=
| PLText : list quad -> ParaLayout
| PLLatex : string -> ParaLayout.

Definition is_latex_para (p : string) : bool :=
  let n := PrimString.length p in
  if ltb n 2%int63 then false else
  andb (int_eqb (PrimString.get p 0%int63) 36%int63)
       (int_eqb (PrimString.get p 1%int63) 36%int63).

Fixpoint layout_all_tr (ps : list string) (acc : list ParaLayout) : list ParaLayout :=
  match ps with
  | nil => rev acc
  | body :: rest =>
      if is_latex_para body then
        layout_all_tr rest (PLLatex body :: acc)
      else
        layout_all_tr rest (PLText (layout_paragraph advance_of MEASURE (shape_paragraph body)) :: acc)
  end.

Fixpoint total_height (qss : list ParaLayout) (acc : Z) : Z :=
  match qss with
  | nil => acc
  | PLText qs :: rest =>
      total_height rest (Z.add (Z.add acc (max_qy qs 0%Z)) para_gap)
  | PLLatex _ :: rest =>
      total_height rest (Z.add (Z.add acc 3276800%Z) para_gap)
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
Fixpoint render_paras (qss : list ParaLayout) (dy : Z) : BIO unit :=
  match qss with
  | nil => Ret tt
  | PLText qs :: rest =>
      _ <- draw_quads_at qs dy ;;
      render_paras rest (Z.add (Z.add dy (max_qy qs 0%Z)) para_gap)
  | PLLatex latex :: rest =>
      used_h <- render_latex_canvas latex 0%Z dy ;;
      render_paras rest (Z.add (Z.add dy used_h) para_gap)
  end.

(* Shape + lay out [body] paragraph-by-paragraph and paint onto #reader-canvas,
   sizing the canvas to the total stacked height first. *)
Definition render_canvas (body : string) : BIO unit :=
  let ps := split_paragraphs body in
  let qss := layout_all_tr ps nil in
  _ <- reader_begin "reader-canvas" (Z.add (total_height qss 0%Z) para_gap) ;;
  render_paras qss 0%Z.

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
   it renders arbitrary-length post bodies without hanging.

   Stack-safety guard: the Verified-Reader typesetter's extracted C++ recurses
   over paragraph glyph lists (now tail-recursive in KnuthPlass.v / GlyphLayout.v
   — Phase-0a stack-safety fix).  For very long bodies (>4000 chars) the WASM
   linear-memory stack is adequate with tail calls, but as a defense-in-depth
   measure we bypass the canvas render and serve the accessible #real-body HTML
   directly.  This guarantees no stack overflow regardless of body length. *)
Definition max_canvas_body : int := 4000%int63.

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
    _ <- dom_set_html id_real_body (body_to_html (inner_body ic)) ;;
    _ <- render_images ic ;;
    if leb (PrimString.length (inner_body ic)) max_canvas_body
    then render_canvas (inner_body ic)
    else Ret tt.

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
                     "WebAuthn passkey required. Re-enroll with a passkey to decrypt." ;;
              Ret true
            else
              let cek := unwrap_cek priv_jwk ek wrapped kid in
              if is_empty cek then
                _ <- show_decrypt_error
                       "Failed to unwrap the content encryption key." ;;
                Ret true
              else
                let inner := decrypt_body cek (env_ct_package env) slug in
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
  else if is_empty (env_signature env) then
    show_decrypt_error "No author signature found in envelope."
  else if negb (verify_post (env_signing_key env) (env_ct_package env) (env_signature env)) then
    show_decrypt_error "Author signature verification failed."
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




Set Warnings "-crane-extraction-default-directory".

Set Crane Extraction Output Directory ".".
Crane Extraction "crane_decrypt" run.
