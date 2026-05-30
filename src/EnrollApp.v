(* EnrollApp.v — the browser reader-enrollment app, authored in ROCQ and
   extracted to C++23 -> WASM via Crane + em++.  Replaces static/enroll.ml +
   the enrollment half of static/crane_bridge.js.

   Reproduces EXACTLY the enroll.ml / crane_bridge.crane_enrollCreateReader flow:
     on load  : count reader-keys in IndexedDB; if any, reveal #enroll-existing
                and list the enrolled key ids; else reveal #enroll-ui and arm
                the button.
     on click : generate an ECDH P-256 keypair (WebCrypto), compress the public
                key, derive key_id = SHA-256(compressed)[:12], create a WebAuthn
                passkey (challenge "crane-enroll-"<keyId>), store the passkey
                {credentialId, keyId} and the reader key
                {id, pubkey:hex(compressed), privkeyJwk, created:""}, then show
                the key id + compressed-pubkey hex in #enroll-result.

   The click handler is modeled with a keepalive re-entry: [run] binds the
   button to a thunk that sets a JS action flag and re-invokes the module's main
   ([bind_invoke]); on re-entry [run] sees the flag ([action_flag]) and runs the
   create action instead of the on-load check.  All branching is ROCQ; the
   EM_ASM does binding only. *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.
From Stdlib Require Import Lists.List.
Import ListNotations.

Require Import StringLib.
Require Import MimeBuild.       (* concat_all, join_comma, basename helpers *)
Require Import CryptoSpec.      (* the 9 axioms + pure-ROCQ protocol (unchanged) *)
Require Import BrowserCrypto.   (* re-points the 9 axioms to browser_helpers.h *)
Require Import BridgeFFI.       (* json_array_len / json_array_field / json_object4 *)
Require Import BrowserEffect.   (* brE effects incl. bind_invoke / action_flag *)

Open Scope pstring_scope.

(* ---- enrolled-key id listing --------------------------------------- *)
(* Read the reader-keys store and join the [id] field of each record into a
   comma-separated string for display.  json_array_len / json_array_field are
   marshalling helpers (BridgeFFI -> browser_helpers.h); the iteration and all
   branching are ROCQ. *)

Fixpoint collect_ids_aux (json : string) (i count : int) (fuel : nat) : list string :=
  match fuel with
  | O => []
  | S f' =>
      if leb count i then []
      else
        let id := json_array_field json i "id" in
        id :: collect_ids_aux json (add i 1%int63) count f'
  end.

Definition enrolled_ids (json : string) : string :=
  let n := json_array_len json in
  join_comma (collect_ids_aux json 0%int63 n 64%nat).

(* ---- the create action --------------------------------------------- *)
(* WebAuthn challenge / user display, matching crane_bridge.js. *)
Definition enroll_challenge (kid : string) : string := cat "crane-enroll-" kid.
Definition rp_name : string := "wklm.online".
Definition user_display : string := "Crane Blog Reader".

(* Build the JSON record for a store via the json_object4 marshalling helper
   (BridgeFFI). *)
Definition passkey_record (cred_id kid : string) : string :=
  json_object4 "credentialId" cred_id "keyId" kid "" "" "" "".

Definition readerkey_record (kid pub_hex priv_jwk : string) : string :=
  json_object4 "id" kid "pubkey" pub_hex "privkeyJwk" priv_jwk "created" "".

Definition do_enroll : BIO unit :=
  _ <- dom_set_text "enroll-status" "Creating credentials..." ;;
  (* 1. ECDH keypair: (uncompressed_pub, priv_jwk). *)
  let '(uncompressed, priv_jwk) := ecdh_p256_generate tt in
  let compressed := compress_pubkey uncompressed in
  let kid := browser_key_id compressed in
  let pub_hex := hex_encode compressed in
  (* 2. WebAuthn passkey. *)
  cred_id <- wa_create (enroll_challenge kid) rp_name user_display ;;
  if is_empty cred_id then
    dom_set_text "enroll-status"
      "Enrollment failed. Make sure your browser supports WebAuthn."
  else
    (* 3. Persist passkey + reader key. *)
    _ <- idb_put "passkeys" (passkey_record cred_id kid) ;;
    _ <- idb_put "reader-keys" (readerkey_record kid pub_hex priv_jwk) ;;
    (* 4. Reveal the result. *)
    _ <- dom_hide "enroll-ui" ;;
    _ <- dom_show "enroll-result" ;;
    _ <- dom_set_text "reader-key-id" kid ;;
    dom_set_text "reader-pubkey-hex" pub_hex.

(* ---- the on-load check --------------------------------------------- *)
Definition on_load : BIO unit :=
  keys <- idb_get_all "reader-keys" ;;
  let n := json_array_len keys in
  if ltb 0%int63 n then
    _ <- dom_hide "enroll-ui" ;;
    _ <- dom_set_text "enroll-existing-status"
           "You already have a reader key enrolled on this device." ;;
    _ <- dom_show "enroll-existing" ;;
    dom_set_text "enroll-existing-info" (cat "Enrolled keys: " (enrolled_ids keys))
  else
    _ <- dom_show "enroll-ui" ;;
    bind_invoke "enroll-button".

(* ---- entry point: dispatch on the action flag ---------------------- *)
Definition run : BIO unit :=
  flag <- action_flag ;;
  if string_eqb flag "1" then do_enroll else on_load.

Set Warnings "-crane-extraction-default-directory".

Crane Extraction "crane_enroll" run.
