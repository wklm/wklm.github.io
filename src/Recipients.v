(* Recipients.v — shared multi-recipient resolution for [encrypt_post] and
   [smtp_server].  A post may be addressed to the author plus up to
   [max_extra_recipients] readers, each identified by the 12-hex key ID the
   reader's browser derived at enrollment (first 12 hex chars of
   SHA-256(compressed public key)).

   The recipient's public key is resolved from keys/<kid>.pub (65-byte
   uncompressed SEC1 hex, exactly as crypto_helpers.h / ec_point_from_uncompressed
   expect).  Resolution is CWD-relative, mirroring the previous single-recipient
   behavior — the automatic key directory only has to make keys/<kid>.pub
   visible on the encrypting host for a reader's ID to work.

   All of the envelope construction that was previously duplicated in
   EncryptPost.v and SmtpServer.v lives here as the single source of truth. *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree Monads.IO Monads.Dir.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.
From Stdlib Require Import Lists.List.
Import ListNotations.

Require Import StringLib.
Require Import MimeLib.
Require Import MimeBuild.     (* build_outer_envelope, join_comma, wrap_base64 *)
Require Import CryptoSpec.    (* key_material, pubkey, wrap_cek, encrypt_body, sign_post, base64_encode *)

Open Scope pstring_scope.

(* ---- small list helpers -------------------------------------------- *)

Fixpoint mem_str (s : string) (xs : list string) : bool :=
  match xs with
  | [] => false
  | x :: rest => orb (string_eqb s x) (mem_str s rest)
  end.

(* Dedupe, keeping the FIRST occurrence. *)
Fixpoint dedup_str (xs : list string) : list string :=
  match xs with
  | [] => []
  | x :: rest =>
      if mem_str x rest then dedup_str rest else x :: dedup_str rest
  end.

(* ---- parsing the recipients field ---------------------------------- *)

(* Collect the non-empty, trimmed segments of a comma-separated kid list. *)
Fixpoint collect_kids (xs : list string) (fuel : nat) : list string :=
  match fuel with
  | O => nil
  | S f' =>
      match xs with
      | [] => nil
      | x :: rest =>
          let k := trim x in
          if is_empty k then collect_kids rest f'
          else k :: collect_kids rest f'
      end
  end.

Fixpoint take_kids (n : nat) (xs : list string) : list string :=
  match n with
  | O => nil
  | S n' =>
      match xs with
      | [] => nil
      | x :: rest => x :: take_kids n' rest
      end
  end.

(* Maximum number of *additional* recipients (the author is always prepended). *)
Notation max_extra_recipients := 3%nat.

(* clean_kids: split, trim, drop empties, dedupe, cap at max_extra_recipients. *)
Definition clean_kids (s : string) : list string :=
  take_kids max_extra_recipients
    (dedup_str (collect_kids (split_on_char_fuel s ch_comma 0%int63 mime_fuel)
                             mime_fuel)).

(* The full recipient kid list: author first, then the parsed extras.  The
   author is deduped against the extras (dedup_str keeps the first occurrence,
   i.e. the author). *)
Definition build_recipients (author_kid extra : string) : list string :=
  dedup_str (author_kid :: clean_kids extra).

(* ---- reading recipient public keys (per-tool, concrete monad) ------- *)

(* NOTE: read_pubkeys is intentionally defined concretely in EncryptPost.v /
   SmtpServer.v (each at its own effect sum), NOT here: a polymorphic
   itree-Fixpoint ({E} `{fileE -< E}) type-checks but Crane's C++ extraction
   emits a broken template (default-arg redefinition) for it.  Pure helpers
   shared here; the one monadic helper is 6 lines per tool. *)

(* True iff every (kid, pubkey) pair has a non-empty public key. *)
Fixpoint recips_ok (rs : list (string * string)) : bool :=
  match rs with
  | [] => true
  | (_, pk) :: rest => andb (negb (is_empty pk)) (recips_ok rest)
  end.

(* The kid list from (kid, pubkey) pairs. *)
Fixpoint kid_list (rs : list (string * string)) : list string :=
  match rs with
  | [] => []
  | (k, _) :: rest => k :: kid_list rest
  end.

(* ---- wrapping and envelope construction ----------------------------- *)

(* HPKE-wrap the CEK for every recipient.  Each wrap_cek call generates its
   own fresh ephemeral keypair and nonce — exactly one wrap per recipient,
   bound to that recipient's kid as AAD. *)
Fixpoint wrap_all (cek : key_material) (rs : list (string * string))
                  : list (string * string * string) :=
  match rs with
  | [] => []
  | (kid, pk) :: rest =>
      let '(ek, wrapped) := wrap_cek cek pk kid in
      (kid, hex_encode ek, hex_encode wrapped) :: wrap_all cek rest
  end.

(* Inner "To" value: "reader: kid1, reader: kid2". *)
Fixpoint readers_to (kids : list string) : list string :=
  match kids with
  | [] => []
  | k :: rest => cat "reader:" k :: readers_to rest
  end.

Definition recipients_to (kids : list string) : string :=
  join_comma (readers_to kids).

(* Build the full outer envelope from a *single* materialized CEK.  [cek] is a
   function parameter so Crane evaluates [random_bytes 32] exactly once at the
   call site — a nullary Definition (like generate_cek) would be inlined and
   re-evaluated, encrypting the body under a different CEK than the wraps.
   [sign_sk] is the raw 32-byte ECDSA signing key and [sign_pk_hex] the hex
   65-byte uncompressed signing public key: the RAW ciphertext package
   (nonce||ct||tag) is signed, exactly as DecryptPost/DecryptApp verify it.
   The envelope carries one Public-Keys / Wraps entry per recipient. *)
Definition build_envelope
  (cek : key_material) (recipients : list (string * string))
  (slug inner_mime sign_sk sign_pk_hex : string) : string :=
  let ct_package := encrypt_body cek inner_mime slug in
  let sig_raw := sign_post sign_sk ct_package in
  build_outer_envelope
    (kid_list recipients)
    (wrap_all cek recipients)
    (wrap_base64 (base64_encode ct_package))
    (hex_encode sig_raw)
    sign_pk_hex.
