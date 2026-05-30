(* BrowserCrypto.v — browser realization of the nine CryptoSpec.v cryptographic
   primitives (FFI boundary C2), backed by crypto.subtle / crypto.getRandomValues
   in src/browser_helpers.h.

   The native build (EncryptPost.v / DecryptPost.v) realizes the same nine
   axioms with OpenSSL via crypto_helpers.h.  This module is the *browser* leg:
   it re-issues every Crane extraction directive that CryptoSpec.v registered
   against crypto_helpers.h, re-pointing it at browser_helpers.h.  Crane applies
   the LAST directive registered for a constant, so importing CryptoSpec (for
   its pure-ROCQ protocol: custom_kdf_sha256 / wrap_cek / unwrap_cek /
   encrypt_body / decrypt_body / hpke base mode) and then this module yields an
   extracted .cpp that includes ONLY browser_helpers.h — crypto_helpers.h
   (OpenSSL, absent under Emscripten) is referenced by no used directive and so
   is never emitted.  This is why DecryptApp.v / EnrollApp.v must
   [Require Import CryptoSpec] BEFORE [Require Import BrowserCrypto].

   CryptoSpec.v itself is reused UNCHANGED (Facet C / shared boundary).

   Semantics match crypto_helpers.h exactly: uncompressed 65-byte public keys,
   nonce(12)||ct||tag(16) packaging, "" on tag mismatch / error.  The one
   representational difference is internal and invisible to the protocol: in the
   browser a [privkey] value carries a WebCrypto JWK JSON string (WebCrypto
   cannot import a bare 32-byte EC scalar), not raw scalar bytes — it is only
   ever produced by ecdh_p256_generate and consumed by ecdh_p256_agree, both
   realized here. *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std.
Require Import StringLib.
Require Import CryptoSpec.

Open Scope pstring_scope.

(* ---- Compressed-pubkey derivation (pure ROCQ) ----------------------- *)
(* Enrollment needs the *compressed* (33-byte) form of the freshly generated
   uncompressed (65-byte) public key, both to derive the key_id and to display.
   Per crane-extraction-gotchas, point compression is pure arithmetic and lives
   in ROCQ (not an FFI helper): 0x04||x(32)||y(32) -> (0x02|0x03)||x, where the
   prefix is 0x03 iff y is odd (its last byte's low bit). *)
(* Parity prefix as a top-level [: int] Definition: a bare [let prefix := if ..]
   inside compress_pubkey extracts to [std::any prefix] (crane-extraction-gotchas:
   chained/conditional-in-let leaks std::any — cf. upk_parity_prefix). *)
Definition compressed_prefix (y_last : int) : int :=
  if int_eqb (land (land y_last 255%int63) 1%int63) 1%int63
  then 3%int63 else 2%int63.

Definition compress_pubkey (uncompressed : string) : string :=
  if int_eqb (PrimString.length uncompressed) 65%int63 then
    let x := PrimString.sub uncompressed 1%int63 32%int63 in
    let prefix := compressed_prefix (PrimString.get uncompressed 64%int63) in
    cat (PrimString.make 1%int63 prefix) x
  else uncompressed.

(* key_id = first 12 hex chars of SHA-256(compressed_pubkey).  CryptoSpec.key_id
   returns the raw 32-byte digest; the browser id is its 12-char hex prefix
   (matching the shipped enroll: _bufToHex(sha256(compressed)).substring(0,12)). *)
Definition browser_key_id (compressed : string) : string :=
  let digest := sha256 compressed in
  PrimString.sub (hex_encode digest) 0%int63 12%int63.

(* ======== Crane C++ extraction (re-point to browser_helpers.h) ======= *)

(* From-less PrimString.make (std::string is in the prelude).  CryptoSpec.v
   already issues this From-less; re-issuing keeps BrowserCrypto self-contained
   if loaded without CryptoSpec's directive having "stuck". *)
Crane Extract Inlined Constant PrimString.make =>
  "std::string((std::size_t)(%a0),(char)(%a1))".

(* The nine primitives, now via browser_helpers.h (EM_ASM / crypto.subtle).
   ecdh_p256_generate / aes_256_gcm_encrypt return std::pair directly (Crane's
   prod), so no adapter IIFE is needed; ecdh_p256_generate takes (and ignores)
   the std::monostate freshness token Crane always applies. *)
Crane Extract Inlined Constant ecdh_p256_generate =>
  "ecdh_p256_generate(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant ecdh_p256_public_key =>
  "ecdh_p256_public_key(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant ecdh_p256_agree =>
  "ecdh_p256_agree(%a0, %a1)" From "browser_helpers.h".
Crane Extract Inlined Constant random_bytes =>
  "random_bytes((int)(%a0))" From "browser_helpers.h".
Crane Extract Inlined Constant aes_256_gcm_encrypt =>
  "aes_256_gcm_encrypt(%a0, %a1, %a2, %a3)" From "browser_helpers.h".
Crane Extract Inlined Constant aes_256_gcm_decrypt =>
  "aes_256_gcm_decrypt(%a0, %a1, %a2, %a3, %a4)" From "browser_helpers.h".
Crane Extract Inlined Constant sha256 =>
  "sha256(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant base64_encode =>
  "base64_encode(%a0)" From "browser_helpers.h".
Crane Extract Inlined Constant base64_decode =>
  "base64_decode(%a0)" From "browser_helpers.h".
