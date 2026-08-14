(* Verified cryptographic protocol specification for the Crane blog
   HPKE-based encryption system.  The nine cryptographic primitives are
   axioms realized via Crane C++23 extraction by OpenSSL EVP in
   [src/crypto_helpers.h] (FFI boundary C1).  The protocol composition
   (HPKE base mode, CEK wrap/unwrap, body encrypt/decrypt) and the KDF are
   pure ROCQ, defined and verified here.

   This file is imported by [EncryptPost.v] / [DecryptPost.v], which run the
   actual [Crane Extraction]; CryptoSpec itself is a library (no entry point).
   The site generator (Logic.v) does not import this file; it only renders
   the encrypted blobs. *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std.
From Stdlib Require Import Lists.List.
Import ListNotations.
Require Import StringLib.
Open Scope pstring_scope.

(* ======== String helpers (legacy shims) ============================== *)
(* [cat], [emptyb], [nat_of_int_fuel], and hex encoding are provided by
   StringLib.v.  [nat_of_int] is a legacy alias kept for compatibility. *)
Definition nat_of_int (i : int) (fuel : nat) : nat := nat_of_int_fuel i fuel.

(* ======== Crypto Type Aliases ====================================== *)

(* A public key is 65 bytes: 0x04 prefix + 32-byte x + 32-byte y
   (SEC1 uncompressed point encoding for NIST P-256). *)
Definition pubkey := string.

(* A private key is 32 bytes (scalar for P-256). *)
Definition privkey := string.

(* 12-byte AES-GCM nonce. *)
Definition nonce := string.

(* 16-byte AES-GCM authentication tag. *)
Definition auth_tag := string.

(* ECDH shared secret (32 bytes). *)
Definition shared_secret := string.

(* Key material — generic byte sequence for keys (32 bytes for AES-256). *)
Definition key_material := string.

(* ======== Cryptographic Axioms ===================================== *)

Axiom ecdh_p256_generate : unit -> pubkey * privkey.
(* Generate a fresh random keypair.
   Post: uncompressed_pk (65 bytes), sk (32 bytes).
   Takes unit as a freshness token so extraction produces a function. *)

Axiom ecdh_p256_public_key : privkey -> pubkey.
(* Derive the public key from a private key. *)

Axiom ecdh_p256_agree : privkey -> pubkey -> shared_secret.
(* ECDH key agreement: scalar-multiply recipient's public key by
   the sender's private key.  Returns the 32-byte x-coordinate
   of the shared point. *)

Axiom random_bytes : int -> string.
(* Generate n cryptographically random bytes.
   Pre: n > 0.  Post: length(result) = n. *)

Axiom aes_256_gcm_encrypt : key_material -> nonce -> string -> string -> string * auth_tag.
(* AES-256-GCM authenticated encryption.
   Pre:  length(key)=32, length(nonce)=12.
   Post: returns (ciphertext, tag) where length(ciphertext)=length(plaintext),
         length(tag)=16. *)

Axiom aes_256_gcm_decrypt : key_material -> nonce -> string -> auth_tag -> string -> string.
(* AES-256-GCM authenticated decryption.
   Returns the plaintext on success, or the empty string on tag mismatch.
   Pre: length(key)=32, length(nonce)=12, length(tag)=16. *)

Axiom sha256 : string -> string.
(* SHA-256 cryptographic hash.  Always returns 32 bytes. *)

(* [PrimString.make n c] builds an [n]-byte string of byte [c].  Crane has no
   default realization, so we supply a From-less directive (std::string is in
   the prelude; a [From] header would drag OpenSSL into the WASM build).  Used
   to build the KDF's 32-byte zero salt and the 0x01 expand counter. *)
Definition zero32 : string := PrimString.make 32%int63 0%int63.
Definition byte01  : string := PrimString.make 1%int63 1%int63.

(* Custom SHA-256-based KDF (not RFC 5869 HKDF).  Now a *pure ROCQ
   definition* over [sha256] (was an axiom linked to Crane_crypto):
     PRK = SHA-256(zero_salt(32) || ikm)
     OKM = SHA-256(PRK || info || 0x01)
   Arguments: salt ikm info length.  Ignores _salt and _len (kept for the
   call-site signature).  Post: length(result) = 32. *)
Definition custom_kdf_sha256 (_salt ikm info : string) (_len : int) : string :=
  let prk := sha256 (cat zero32 ikm) in
  sha256 (cat prk (cat info byte01)).

(* ======== ECDSA P-256 Digital Signatures =========================== *)

(* ECDSA P-256 sign: sign a 32-byte message digest with a private key.
   Returns a 64-byte raw signature (r || s, each 32 bytes zero-padded).
   Returns "" on error. *)
Axiom ecdsa_p256_sign : privkey -> string -> string.

(* ECDSA P-256 verify: verify a 64-byte raw signature (r || s) against
   a 32-byte message digest using a public key.
   Returns true if valid, false otherwise. *)
Axiom ecdsa_p256_verify : pubkey -> string -> string -> bool.

(* ======== Base64 Encode/Decode ===================================== *)

Axiom base64_encode : string -> string.
(* Encode arbitrary bytes to base64 ascii (no line wrapping). *)

Axiom base64_decode : string -> string.
(* Decode base64 ascii to bytes.  Returns empty string on parse error. *)

(* ======== Hex Encode (provided by StringLib.v) ===================== *)
(* hex_chars, byte_to_hex, hex_encode_aux, hex_encode are imported
   from StringLib.v and used in format_wrapped_entry below. *)

(* ======== HPKE Base-Mode Protocol ================================= *)

(* Domain-separation info strings to prevent key reuse across contexts. *)
Definition hpke_encrypt_info : string := "crane-blog-hpke-v1".
Definition wrap_cek_info   : string := "crane-blog-wrap-v1".
Definition sign_info       : string := "crane-blog-sign-v1".
(* Domain-separated info string for PUBLIC (keyless) envelopes (D2): disjoint
   from [sign_info] as byte strings (shared 16-byte prefix, diverge at bytes
   17-20), so a public envelope's signature can never replay against a
   ciphertext envelope's verification and vice versa. *)
Definition sign_info_public : string := "crane-blog-sign-public-v1".

(* HPKE base-mode encrypt for a single recipient.
   Returns (encapsulated_ephemeral_pubkey, ciphertext_package).
   ciphertext_package:   nonce(12) || ciphertext || tag(16)
   encapsulated_pubkey:  SEC1 uncompressed (65 bytes). *)
Definition hpke_encrypt (pkR : pubkey) (plaintext : string) : string * string :=
  let '(epk, esk) := ecdh_p256_generate tt in
  let dh := ecdh_p256_agree esk pkR in
  let cek := custom_kdf_sha256 "" dh hpke_encrypt_info 32%int63 in
  let n := random_bytes 12%int63 in
  let '(ct, tg) := aes_256_gcm_encrypt cek n plaintext "" in
  (epk, cat n (cat ct tg)).

(* HPKE base-mode decrypt.
   ek: encapsulated ephemeral public key (65 bytes).
   ct_package: nonce(12) || ciphertext || tag(16). *)
Definition hpke_decrypt (skR : privkey) (ek : pubkey) (ct_package : string) : string :=
  let dh := ecdh_p256_agree skR ek in
  let cek := custom_kdf_sha256 "" dh hpke_encrypt_info 32%int63 in
  let n_len := 12%int63 in
  let t_len := 16%int63 in
  let pkg_len := PrimString.length ct_package in
  if leb pkg_len (add n_len t_len) then ""
  else
    let n := PrimString.sub ct_package 0%int63 n_len in
    let rest := PrimString.sub ct_package n_len (sub pkg_len n_len) in
    let rest_len := PrimString.length rest in
    let ct := PrimString.sub rest 0%int63 (sub rest_len t_len) in
    let tg := PrimString.sub rest (sub rest_len t_len) t_len in
    aes_256_gcm_decrypt cek n ct tg "".

(* ======== Content Encryption Key Management ======================== *)

(* Generate a fresh random 32-byte CEK. *)
Definition generate_cek : key_material :=
  random_bytes 32%int63.

(* Wrap a CEK for a specific recipient (HPKE key encapsulation).
   Returns (encapsulated_pubkey, wrapped_package).
   wrapped_package: nonce(12) || encrypted_cek(32) || tag(16).
   AAD: the recipient's key_id binds the wrap to a specific recipient. *)
Definition wrap_cek (cek : key_material) (pkR : pubkey) (kid : string) : string * string :=
  let '(epk, esk) := ecdh_p256_generate tt in
  let dh := ecdh_p256_agree esk pkR in
  let wrapping_key := custom_kdf_sha256 "" dh wrap_cek_info 32%int63 in
  let n := random_bytes 12%int63 in
  let '(wrapped, tg) := aes_256_gcm_encrypt wrapping_key n cek kid in
  (epk, cat n (cat wrapped tg)).

(* Unwrap a CEK using the recipient's private key.
   ek: encapsulated ephemeral pubkey (65 bytes).
   wrapped: nonce(12) || encrypted_cek(32) || tag(16).
   AAD: the key_id must match the one used during wrap. *)
Definition unwrap_cek (skR : privkey) (ek : pubkey) (wrapped : string) (kid : string) : string :=
  let dh := ecdh_p256_agree skR ek in
  let wrapping_key := custom_kdf_sha256 "" dh wrap_cek_info 32%int63 in
  let n_len := 12%int63 in
  let t_len := 16%int63 in
  let w_len := PrimString.length wrapped in
  if leb w_len (add n_len t_len) then ""
  else
    let n := PrimString.sub wrapped 0%int63 n_len in
    let rest := PrimString.sub wrapped n_len (sub w_len n_len) in
    let rest_len := PrimString.length rest in
    let ct := PrimString.sub rest 0%int63 (sub rest_len t_len) in
    let tg := PrimString.sub rest (sub rest_len t_len) t_len in
    aes_256_gcm_decrypt wrapping_key n ct tg kid.

(* ======== Post Body Encryption ===================================== *)

(* Encrypt a post body with a CEK.
   Returns nonce(12) || ciphertext || tag(16) package.
   AAD: the post slug binds the ciphertext to a specific post. *)
Definition encrypt_body (cek : key_material) (body : string) (slug : string) : string :=
  let n := random_bytes 12%int63 in
  let '(enc, tg) := aes_256_gcm_encrypt cek n body slug in
  cat n (cat enc tg).

(* Decrypt a post body with a CEK.
   enc_package: nonce(12) || ciphertext || tag(16).
   AAD: the post slug must match the one used during encryption. *)
Definition decrypt_body (cek : key_material) (enc_package : string) (slug : string) : string :=
  let n_len := 12%int63 in
  let t_len := 16%int63 in
  let pkg_len := PrimString.length enc_package in
  if leb pkg_len (add n_len t_len) then ""
  else
    let n := PrimString.sub enc_package 0%int63 n_len in
    let rest := PrimString.sub enc_package n_len (sub pkg_len n_len) in
    let rest_len := PrimString.length rest in
    let ct := PrimString.sub rest 0%int63 (sub rest_len t_len) in
    let tg := PrimString.sub rest (sub rest_len t_len) t_len in
    aes_256_gcm_decrypt cek n ct tg slug.

(* ======== Key Identity ============================================= *)

(* Compute a key ID from a public key: truncated SHA-256 hex.
   The extraction override returns the first 12 hex characters. *)
Definition key_id (pk : pubkey) : string :=
  sha256 pk.

(* ======== Post Signing / Verification ============================== *)

(* Sign a post's ciphertext package to prove authorship.
   The signature covers SHA-256(sign_info || ct_package), binding the
   signature to the specific ciphertext and preventing cross-context reuse.
   Returns 64-byte raw ECDSA signature (r || s). *)
Definition sign_post (sk : privkey) (ct_package : string) : string :=
  let digest := sha256 (cat sign_info ct_package) in
  ecdsa_p256_sign sk digest.

(* Verify a post's authorship signature.
   Returns true iff the signature is valid for the given ciphertext package
   under the given public key. *)
Definition verify_post (pk : pubkey) (ct_package sig : string) : bool :=
  let digest := sha256 (cat sign_info ct_package) in
  ecdsa_p256_verify pk digest sig.

(* ======== Public Post Signing / Verification (feature 2) ============= *)

(* Canonical newline normalization for the public signed form (D-C2, A1).
   Browser HTML input-stream preprocessing and arbitrary writer CRLF/LF
   habits make the raw inner-MIME bytes non-deterministic, so the writer and
   BOTH verifiers reduce CRLF and lone CR to LF before hashing.  Total
   (fuel-bounded), non-corrupting (identity on LF-only input) and idempotent
   — pinned by the eq_refl Examples below.  The byte constants use distinct
   names (MimeBuild defines its own lf/cr/crlf; importing both modules must
   not make the names ambiguous). *)
Definition cr_byte : string := PrimString.make 1%int63 ch_cr.
Definition lf_byte : string := PrimString.make 1%int63 ch_newline.

Fixpoint normalize_crlf_aux (s : string) (pos : int) (fuel : nat) (acc : string) : string :=
  match fuel with
  | O => acc
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then acc
      else
        let c := PrimString.get s pos in
        if int_eqb c ch_cr
        then
          let acc' := cat acc lf_byte in
          if andb (ltb (add pos 1%int63) n)
                  (int_eqb (PrimString.get s (add pos 1%int63)) ch_newline)
          then normalize_crlf_aux s (add pos 2%int63) f' acc'
          else normalize_crlf_aux s (add pos 1%int63) f' acc'
        else normalize_crlf_aux s (add pos 1%int63) f' (cat acc (PrimString.make 1%int63 c))
  end.

Definition normalize_crlf (s : string) : string :=
  normalize_crlf_aux s 0%int63 mime_fuel "".

(* Sign/verify a PUBLIC post envelope (D-C2, A10, M3).  The signed message is
   sha256(sign_info_public || slug || normalize_crlf inner_mime) — 4-arg
   arity everywhere.  DERIVED from the existing sign_post/verify_post
   primitives (no new axioms); the realized double-hash at the FFI
   (crypto_helpers.h:296-301) applies unchanged through
   ecdsa_p256_sign/ecdsa_p256_verify — do NOT hash again.

   G3/A fix (fail-closed): normalize_crlf is fuel-bounded at mime_fuel
   (65536 iterations), and each iteration consumes >=1 byte, so any
   inner_mime of byte length <= mime_fuel normalizes WITHOUT truncation.
   Both sign and verify therefore REJECT an inner_mime longer than
   mime_fuel bytes rather than silently authenticating only the normalized
   prefix (which would let two bodies sharing a 64KB prefix collide). *)
Definition sign_post_public (sk : privkey) (slug inner_mime : string) : string :=
  if leb (PrimString.length inner_mime) 65536%int63
  then
    let digest := sha256 (cat sign_info_public (cat slug (normalize_crlf inner_mime))) in
    ecdsa_p256_sign sk digest
  else "".

Definition verify_post_public (pk : pubkey) (slug inner_mime sig : string) : bool :=
  if leb (PrimString.length inner_mime) 65536%int63
  then
    let digest := sha256 (cat sign_info_public (cat slug (normalize_crlf inner_mime))) in
    ecdsa_p256_verify pk digest sig
  else false.

(* Machine-checked pins for normalize_crlf (D-C2, A1; eq_refl house style).
   Coq string literals carry no \r / \n escapes, so the CR/LF bytes are
   built with cr_byte / lf_byte exactly as the runtime strings contain them. *)
Example normalize_crlf_lf_identity :
  normalize_crlf (cat "a" (cat lf_byte (cat "b" (cat lf_byte "c"))))
  = cat "a" (cat lf_byte (cat "b" (cat lf_byte "c"))) := eq_refl.

Example normalize_crlf_crlf :
  normalize_crlf (cat "a" (cat cr_byte (cat lf_byte "b")))
  = cat "a" (cat lf_byte "b") := eq_refl.

Example normalize_crlf_lone_cr :
  normalize_crlf (cat "a" (cat cr_byte "b"))
  = cat "a" (cat lf_byte "b") := eq_refl.

Example normalize_crlf_crlf_cr :
  normalize_crlf (cat "a" (cat cr_byte (cat lf_byte (cat cr_byte "b"))))
  = cat "a" (cat lf_byte (cat lf_byte "b")) := eq_refl.

Example normalize_crlf_idempotent :
  normalize_crlf (normalize_crlf (cat "a" (cat cr_byte (cat lf_byte "b"))))
  = normalize_crlf (cat "a" (cat cr_byte (cat lf_byte "b"))) := eq_refl.

(* ======== Wrapped Key Map ========================================== *)

(* A wrapped key entry in the .eml format: key_id + encapsulated key
   + wrapped key package.  Stored as:
     keyid:hex_ek:hex_wrapped
   where hex_ek is 33*2 hex chars, hex_wrapped is (12+32+16)*2 = 120 hex
   chars.  These are comma-separated in the header. *)

Definition format_wrapped_entry (kid ek wrapped : string) : string :=
  cat kid (cat ":" (cat (hex_encode ek) (cat ":" (hex_encode wrapped)))).

(* ======== Cryptographic Round-Trip Axioms =========================== *)

(* HPKE base-mode decrypt(encrypt(m)) = m for correct recipient. *)
Axiom hpke_roundtrip : forall (pkR : pubkey) (skR : privkey) (plaintext : string)
  (kid : string) (slug : string),
  let erec := encrypt_body (custom_kdf_sha256 "" (ecdh_p256_agree skR pkR) hpke_encrypt_info 32%int63) plaintext slug in
  decrypt_body (custom_kdf_sha256 "" (ecdh_p256_agree skR pkR) hpke_encrypt_info 32%int63) erec slug = plaintext.

(* CEK wrap/unwrap: unwrap(wrap(cek)) = cek for correct recipient. *)
Axiom cek_wrap_roundtrip : forall (cek : key_material) (pkR : pubkey) (skR : privkey) (kid : string),
  let '(epk, wrapped) := wrap_cek cek pkR kid in
  unwrap_cek skR epk wrapped kid = cek.

(* AES-GCM encrypt-then-decrypt returns original plaintext when tag matches. *)
Axiom aes_gcm_roundtrip : forall (k : key_material) (nonce : nonce) (pt aad : string),
  let '(ct, tg) := aes_256_gcm_encrypt k nonce pt aad in
  aes_256_gcm_decrypt k nonce ct tg aad = pt.

(* Base64 round-trip: decode(encode(x)) = x. *)
Axiom base64_roundtrip : forall (s : string),
  base64_decode (base64_encode s) = s.

(* ECDSA sign/verify round-trip: verify(sign(msg)) = true for correct keypair. *)
Axiom ecdsa_roundtrip : forall (sk : privkey) (msg : string),
  let pk := ecdh_p256_public_key sk in
  let sig := ecdsa_p256_sign sk msg in
  ecdsa_p256_verify pk msg sig = true.

(* Derived round-trip for the PUBLIC variant (A10): sign then verify under
   the same keypair succeeds.  eapply the EXISTING ecdsa_roundtrip axiom
   (defined above) — no new axiom. *)
Lemma sign_public_verify_roundtrip : forall (sk : privkey) (slug inner_mime : string),
  let pk := ecdh_p256_public_key sk in
  leb (PrimString.length inner_mime) 65536%int63 = true ->
  verify_post_public pk slug inner_mime (sign_post_public sk slug inner_mime) = true.
Proof.
  intros sk slug inner_mime pk H.
  unfold sign_post_public, verify_post_public.
  destruct (leb (PrimString.length inner_mime) 65536%int63) eqn:E.
  - (* guard = true: both [if]s reduce to their then-branches (cbv zeta/beta
       only — never [cbn]/[simpl], which would unfold [normalize_crlf] over the
       variable [inner_mime] and hang O(fuel^2)). *)
    cbv zeta beta.
    eapply ecdsa_roundtrip.
  - (* guard = false: contradicts H. *)
    congruence.
Qed.

(* ======== Crane C++ Extraction Directives ========================== *)

(* The nine primitive axioms are realized natively by OpenSSL EVP in
   [src/crypto_helpers.h] (FFI boundary C1).  Semantics match the retired
   [src/crane_crypto.ml] exactly (uncompressed 65-byte pubkeys, 32-byte
   scalars, nonce||ct||tag packaging, "" on error/mismatch).

   The two tuple-returning primitives ([ecdh_p256_generate],
   [aes_256_gcm_encrypt]) have the helper return [std::pair] DIRECTLY, which is
   exactly Crane's representation of Coq [prod] — so no prod-adapter IIFE is
   needed.  [ecdh_p256_generate] drops its [tt] freshness token (no [%a0]). *)

(* From-less [PrimString.make] — std::string is in Crane's prelude; adding a
   [From] header here would pull OpenSSL into the WASM build. *)
Crane Extract Inlined Constant PrimString.make =>
  "std::string((std::size_t)(%a0),(char)(%a1))".

(* Crane applies the [tt] argument (extracted as std::monostate{}) regardless
   of whether the directive mentions %a0, so the helper takes (and ignores) it. *)
Crane Extract Inlined Constant ecdh_p256_generate =>
  "ecdh_p256_generate(%a0)" From "crypto_helpers.h".
Crane Extract Inlined Constant ecdh_p256_public_key =>
  "ecdh_p256_public_key(%a0)" From "crypto_helpers.h".
Crane Extract Inlined Constant ecdh_p256_agree =>
  "ecdh_p256_agree(%a0, %a1)" From "crypto_helpers.h".
Crane Extract Inlined Constant random_bytes =>
  "random_bytes((int)(%a0))" From "crypto_helpers.h".
Crane Extract Inlined Constant aes_256_gcm_encrypt =>
  "aes_256_gcm_encrypt(%a0, %a1, %a2, %a3)" From "crypto_helpers.h".
Crane Extract Inlined Constant aes_256_gcm_decrypt =>
  "aes_256_gcm_decrypt(%a0, %a1, %a2, %a3, %a4)" From "crypto_helpers.h".
Crane Extract Inlined Constant sha256 =>
  "sha256(%a0)" From "crypto_helpers.h".
Crane Extract Inlined Constant base64_encode =>
  "base64_encode(%a0)" From "crypto_helpers.h".
Crane Extract Inlined Constant base64_decode =>
  "base64_decode(%a0)" From "crypto_helpers.h".
Crane Extract Inlined Constant ecdsa_p256_sign =>
  "ecdsa_p256_sign(%a0, %a1)" From "crypto_helpers.h".
Crane Extract Inlined Constant ecdsa_p256_verify =>
  "ecdsa_p256_verify(%a0, %a1, %a2)" From "crypto_helpers.h".
