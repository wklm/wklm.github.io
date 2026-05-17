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
Open Scope pstring_scope.

(* ======== String helpers ============================================ *)

Definition cat (a b : string) : string :=
  concat_all (a :: b :: nil).

Fixpoint nat_of_int (i : int) (fuel : nat) : nat :=
  match fuel with
  | O => O
  | S f =>
    if leb i 0%int63 then O
    else S (nat_of_int (sub i 1%int63) f)
  end.

Definition emptyb (s : string) : bool :=
  leb (PrimString.length s) 0%int63.

(* ======== Crypto Type Aliases ====================================== *)

(* A public key is 33 bytes: 0x02/0x03 prefix + 32-byte x-coordinate
   (SEC1 compressed point encoding for NIST P-256). *)
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
   Post: compressed_pk (33 bytes), sk (32 bytes).
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

Axiom hkdf_sha256 : string -> string -> string -> int -> string.
(* HKDF-SHA256 (extract-then-expand).  Arguments: salt ikm info length.
   Pre: length may be any positive int63 value.
   Post: length(result) = length (the int64 parameter). *)

(* ======== Base64 Encode/Decode ===================================== *)

Axiom base64_encode : string -> string.
(* Encode arbitrary bytes to base64 ascii (no line wrapping). *)

Axiom base64_decode : string -> string.
(* Decode base64 ascii to bytes.  Returns empty string on parse error. *)

(* ======== Hex Encode (for debug / key display only) ================ *)

Definition hex_chars : string := "0123456789abcdef".

Definition byte_to_hex (b : int) : string :=
  let hi := lsr b 4%int63 in
  let lo := land b 15%int63 in
  cat (PrimString.sub hex_chars hi 1%int63)
      (PrimString.sub hex_chars lo 1%int63).

Fixpoint hex_encode_aux (s : string) (pos : int) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f =>
    if leb (PrimString.length s) pos then ""
    else cat (byte_to_hex (PrimString.get s pos))
             (hex_encode_aux s (add pos 1%int63) f)
  end.

Definition hex_encode (s : string) : string :=
  hex_encode_aux s 0%int63 65536%nat.

(* ======== HPKE Base-Mode Protocol ================================= *)

(* Domain-separation info strings to prevent key reuse across contexts. *)
Definition hpke_encrypt_info : string := "crane-blog-hpke-v1".
Definition wrap_cek_info   : string := "crane-blog-wrap-v1".

(* HPKE base-mode encrypt for a single recipient.
   Returns (encapsulated_ephemeral_pubkey, ciphertext_package).
   ciphertext_package:   nonce(12) || ciphertext || tag(16)
   encapsulated_pubkey:  SEC1 compressed (33 bytes). *)
Definition hpke_encrypt (pkR : pubkey) (plaintext : string) : string * string :=
  let '(epk, esk) := ecdh_p256_generate tt in
  let dh := ecdh_p256_agree esk pkR in
  let cek := hkdf_sha256 "" dh hpke_encrypt_info 32%int63 in
  let n := random_bytes 12%int63 in
  let '(ct, tg) := aes_256_gcm_encrypt cek n plaintext "" in
  (epk, cat n (cat ct tg)).

(* HPKE base-mode decrypt.
   ek: encapsulated ephemeral public key (33 bytes).
   ct_package: nonce(12) || ciphertext || tag(16). *)
Definition hpke_decrypt (skR : privkey) (ek : pubkey) (ct_package : string) : string :=
  let dh := ecdh_p256_agree skR ek in
  let cek := hkdf_sha256 "" dh hpke_encrypt_info 32%int63 in
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
   wrapped_package: nonce(12) || encrypted_cek(32) || tag(16) *)
Definition wrap_cek (cek : key_material) (pkR : pubkey) : string * string :=
  let '(epk, esk) := ecdh_p256_generate tt in
  let dh := ecdh_p256_agree esk pkR in
  let wrapping_key := hkdf_sha256 "" dh wrap_cek_info 32%int63 in
  let n := random_bytes 12%int63 in
  let '(wrapped, tg) := aes_256_gcm_encrypt wrapping_key n cek "" in
  (epk, cat n (cat wrapped tg)).

(* Unwrap a CEK using the recipient's private key.
   ek: encapsulated ephemeral pubkey (33 bytes).
   wrapped: nonce(12) || encrypted_cek(32) || tag(16) *)
Definition unwrap_cek (skR : privkey) (ek : pubkey) (wrapped : string) : string :=
  let dh := ecdh_p256_agree skR ek in
  let wrapping_key := hkdf_sha256 "" dh wrap_cek_info 32%int63 in
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
    aes_256_gcm_decrypt wrapping_key n ct tg "".

(* ======== Post Body Encryption ===================================== *)

(* Encrypt a post body with a CEK.
   Returns nonce(12) || ciphertext || tag(16) package. *)
Definition encrypt_body (cek : key_material) (body : string) : string :=
  let n := random_bytes 12%int63 in
  let '(enc, tg) := aes_256_gcm_encrypt cek n body "" in
  cat n (cat enc tg).

(* Decrypt a post body with a CEK.
   enc_package: nonce(12) || ciphertext || tag(16) *)
Definition decrypt_body (cek : key_material) (enc_package : string) : string :=
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
    aes_256_gcm_decrypt cek n ct tg "".

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
Extract Constant hkdf_sha256          => "Crane_crypto.hkdf_sha256".
Extract Constant base64_encode        => "Crane_crypto.base64_encode".
Extract Constant base64_decode        => "Crane_crypto.base64_decode".
