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
Require Import BrowserEffect.    (* brE effects *)

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

Definition parse_envelope (eml_body : string) : parsed_envelope :=
  let '(hdrs_block, body) := split_headers_body2 eml_body in
  let hdrs := parse_headers hdrs_block in
  let ct_hdr := header_lookup "Content-Type" hdrs in
  let boundary := extract_boundary ct_hdr in
  let parts := split_parts body boundary in
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
    _ <- dom_set_html "real-body" (body_to_html (inner_body ic)) ;;
    match inner_images ic with
    | nil => Ret tt
    | names => dom_set_text "real-images" (images_label names)
    end.

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
