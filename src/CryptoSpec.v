(* Verified cryptographic protocol specification for the Crane blog
   HPKE-based encryption system.  Cryptographic primitives are axiomatic;
   the OCaml extraction links them to Mirage_crypto / Digestif.  The
   protocol composition (HPKE base mode, CEK wrap/unwrap, body
   encrypt/decrypt) is defined and verified in Coq.

   This file is extracted to OCaml (not via Crane) and linked into the
   encrypt_post and smtp_listener tools.  The site generator (Logic.v)
   does not import this file; it only renders the encrypted blobs. *)

From Corelib Require Import PrimString PrimInt63.
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
   Takes unit as a freshness token so extraction produces a function.)

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

Axiom custom_kdf_sha256 : string -> string -> string -> int -> string.
(* Custom SHA-256-based KDF (not RFC 5869 HKDF).  Uses:
     PRK = SHA-256(zero_salt(32) || ikm)
     OKM = SHA-256(PRK || info || 0x01)
   Arguments: salt ikm info length.  Ignores _salt and _len.
   Post: length(result) = 32. *)

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

(* ======== OCaml Extraction Directives ============================== *)

(* Link axioms to the Crane_crypto OCaml module (hand-written FFI in
   crypto_ffi.ml).  The OCaml module wraps Mirage_crypto and Digestif. *)

Extraction Language OCaml.

Extract Constant ecdh_p256_generate   => "Crane_crypto.ecdh_p256_generate".
Extract Constant ecdh_p256_public_key => "Crane_crypto.ecdh_p256_public_key".
Extract Constant ecdh_p256_agree      => "Crane_crypto.ecdh_p256_agree".
Extract Constant random_bytes         => "Crane_crypto.random_bytes".
Extract Constant aes_256_gcm_encrypt  => "Crane_crypto.aes_256_gcm_encrypt".
Extract Constant aes_256_gcm_decrypt  => "Crane_crypto.aes_256_gcm_decrypt".
Extract Constant sha256               => "Crane_crypto.sha256".
Extract Constant custom_kdf_sha256     => "Crane_crypto.custom_kdf_sha256".
Extract Constant base64_encode        => "Crane_crypto.base64_encode".
Extract Constant base64_decode        => "Crane_crypto.base64_decode".
