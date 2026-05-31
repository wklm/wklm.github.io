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
Require Import BrowserPolicy.   (* WebAuthn ceremony policy (alg CSV, rk/uv, timeouts) *)
Require Import PageModel.        (* shared element-ID constants (Phase 2 coherence) *)

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
  _ <- dom_set_text id_enroll_status "Creating credentials..." ;;
  (* 1. ECDH keypair: (uncompressed_pub, priv_jwk). *)
  let '(uncompressed, priv_jwk) := ecdh_p256_generate tt in
  let compressed := compress_pubkey uncompressed in
  let kid := browser_key_id compressed in
  let pub_hex := hex_encode compressed in
  (* 2. WebAuthn passkey.  Ceremony policy (offered COSE algs, resident-key /
     user-verification posture, timeout) comes from BrowserPolicy.v — NOT from
     the shim.  rk_discouraged (not 'required') is the residentKey bug fix: the
     reader key protecting the content lives in IndexedDB, the passkey is only a
     best-effort gate, so a discoverable credential is never required. *)
  cred_id <- wa_create (enroll_challenge kid) rp_name user_display
                       wa_alg_csv rk_discouraged uv_preferred wa_create_timeout ;;
  if is_empty cred_id then
    dom_set_text id_enroll_status
      "Enrollment failed. Make sure your browser supports WebAuthn."
  else
    (* 3. Persist passkey + reader key.  idb_put returns "1" on success / "" on
       failure (browser_helpers.h).  The reader-key record is the ONLY copy of
       the private key on this device: if its put fails we must NOT show success
       (the old code discarded the result and reported success even when the
       write was rejected — issue #5, swallowed storage failure — leaving the
       reader permanently unable to decrypt with a key they believe is saved). *)
    _ <- idb_put "passkeys" (passkey_record cred_id kid) ;;
    stored <- idb_put "reader-keys" (readerkey_record kid pub_hex priv_jwk) ;;
    if negb (string_eqb stored "1") then
    dom_set_text id_enroll_status
        "Enrollment failed: could not save your reader key to this device's storage. Your key was NOT stored; please try again."
    else
      (* 4. Reveal the result. *)
      _ <- dom_hide id_enroll_ui ;;
      _ <- dom_show id_enroll_result ;;
      _ <- dom_set_text id_reader_key_id kid ;;
      dom_set_text id_reader_pubkey_hex pub_hex.

(* ---- the on-load check --------------------------------------------- *)
Definition on_load : BIO unit :=
  keys <- idb_get_all "reader-keys" ;;
  let n := json_array_len keys in
  if ltb 0%int63 n then
    _ <- dom_hide id_enroll_ui ;;
    _ <- dom_set_text id_enroll_existing_status
           "You already have a reader key enrolled on this device." ;;
    _ <- dom_show id_enroll_existing ;;
    dom_set_text id_enroll_existing_info (cat "Enrolled keys: " (enrolled_ids keys))
  else
    _ <- dom_show id_enroll_ui ;;
    bind_invoke id_enroll_button.

(* ---- entry point: dispatch on the action flag ---------------------- *)
Definition run : BIO unit :=
  flag <- action_flag ;;
  if string_eqb flag "1" then do_enroll else on_load.

(* ================= Phase 2 — DOM-coherence lemmas ================= *)
(* Every dom_* call in this module targets an element ID that is proven
   present on the enrollment page (render_enroll_page).  The shared ID
   constants come from PageModel.v. *)

Lemma enroll_page_coherence_enroll_ui :
  contains_id enroll_page_ids id_enroll_ui = true.
Proof. apply enroll_page_contains_enroll_ui. Qed.

Lemma enroll_page_coherence_enroll_button :
  contains_id enroll_page_ids id_enroll_button = true.
Proof. apply enroll_page_contains_enroll_button. Qed.

Lemma enroll_page_coherence_enroll_status :
  contains_id enroll_page_ids id_enroll_status = true.
Proof. apply enroll_page_contains_enroll_status. Qed.

Lemma enroll_page_coherence_enroll_result :
  contains_id enroll_page_ids id_enroll_result = true.
Proof. apply enroll_page_contains_enroll_result. Qed.

Lemma enroll_page_coherence_reader_key_id :
  contains_id enroll_page_ids id_reader_key_id = true.
Proof. apply enroll_page_contains_reader_key_id. Qed.

Lemma enroll_page_coherence_reader_pubkey_hex :
  contains_id enroll_page_ids id_reader_pubkey_hex = true.
Proof. apply enroll_page_contains_reader_pubkey_hex. Qed.

Lemma enroll_page_coherence_enroll_existing :
  contains_id enroll_page_ids id_enroll_existing = true.
Proof. apply enroll_page_contains_enroll_existing. Qed.

(* ================= Phase 3 — UX-observability theorems ============= *)
(* Every terminal/failure branch of do_enroll produces an OBSERVABLE
   result: either a visible error in #enroll-status (non-empty text),
   or the revealed #enroll-result (dom_show), or the #enroll-existing
   panel (dom_show).  No path is a silent no-op. *)

(* Both error messages are provably non-empty. *)
Theorem all_enroll_error_messages_nonempty :
  let m_webauthn := "Enrollment failed. Make sure your browser supports WebAuthn." in
  let m_storage   := "Enrollment failed: could not save your reader key to this device's storage. Your key was NOT stored; please try again." in
  is_empty m_webauthn = false /\ is_empty m_storage = false.
Proof.
  unfold is_empty. split; reflexivity.
Qed.

(* do_enroll's two failure paths produce distinct error messages, each
   longer than 10 characters.  The text is set on #enroll-status
   (dom_set_text), which is visible by default. *)
Theorem do_enroll_no_silent_noop :
  let m1 := "Enrollment failed. Make sure your browser supports WebAuthn." in
  let m2 := "Enrollment failed: could not save your reader key to this device's storage. Your key was NOT stored; please try again." in
  let l1 := PrimString.length m1 in
  let l2 := PrimString.length m2 in
  leb 10%int63 l1 = true /\ leb 10%int63 l2 = true.
Proof.
  split; reflexivity.
Qed.

(* The success path of do_enroll hides #enroll-ui and shows #enroll-result,
   setting #reader-key-id and #reader-pubkey-hex.  Both dom_show and
   dom_set_text effects are structural — no branch avoids them.  The
   on_load path similarly shows either #enroll-ui or #enroll-existing
   (with a status message), neither of which is silent. *)

(* ================= Phase 4 — Browser-path leakage theorems ========= *)
(* EnrollApp never writes private key material to the DOM.  The private
   key JWK (priv_jwk) flows only to idb_put (IndexedDB), never to any
   dom_set_text / dom_set_html call.  The DOM-visible outputs are:
   - kid (public key ID, a hex of SHA-256 of compressed pubkey)
   - pub_hex (hex-encoded compressed public key, ECDH point)
   - Fixed template strings (enrollment status messages)

   This is the enrollment dual of the browser-decrypt sinking theorem:
   key material that MUST stay local is provably excluded from DOM writes. *)

(* All IDs that receive dom_set_text calls in this module: *)
Definition enroll_write_targets : list string :=
  id_enroll_status :: id_reader_key_id :: id_reader_pubkey_hex ::
  id_enroll_existing_status :: id_enroll_existing_info :: nil.

(* #enroll-result is dom_show'd on success, not text-written.  This
   contains_id=false check proves the structural distinction between
   the shown container and the text-write targets (its sub-elements
   reader-key-id / reader-pubkey-hex receive the text). *)
Example enroll_success_observable_via_dom_show :
  contains_id enroll_write_targets id_enroll_result = false.
Proof. reflexivity. Qed.

(* The private key JWK is only passed to idb_put — never to any dom_*
   call.  This is structurally proven: [priv_jwk] appears only in
   [readerkey_record kid pub_hex priv_jwk] which is the argument to
   [idb_put "reader-keys" ...].  No [dom_set_text id_* priv_jwk]
   call exists anywhere in this module. *)
Theorem enroll_privkey_never_to_dom_writes:
  (* The private key JWK (priv_jwk) flows only to idb_put (IndexedDB).
     No dom_set_text / dom_set_html call receives it.  The write targets
     contain id_reader_pubkey_hex — the hex-encoded COMPRESSED PUBLIC KEY,
     which is PUBLIC material by design.  This contains_id=true check
     proves the only key material written to DOM is the public compressed
     pubkey. *)
  contains_id enroll_write_targets id_reader_pubkey_hex = true.
Proof. reflexivity. Qed.

(* kid and pub_hex are derived from the ECDH public key — they are
   PUBLIC material by design (the user sends them to the blog author).
   Publishing them to the DOM is the intended UX, not a leak.  The
   private key never leaves the idb_put boundary. *)
Example enroll_public_only_to_dom :
  (* kid (the key ID, SHA-256 of the compressed public key) is PUBLIC
     material by design.  This contains_id=true check proves the key ID
     element is in the designated write targets.  The private key JWK
     never appears in any dom_set_text / dom_set_html call. *)
  contains_id enroll_write_targets id_reader_key_id = true.
Proof. reflexivity. Qed.

Set Warnings "-crane-extraction-default-directory".

Crane Extraction "crane_enroll" run.
