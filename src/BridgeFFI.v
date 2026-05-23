(* BridgeFFI.v — Axiomatized crane_bridge.js external calls.
   These axioms model the browser-side Web Crypto + WebAuthn bridge
   used by decrypt.ml and enroll.ml.  Extracted to OCaml, compiled
   to JavaScript by js_of_ocaml, and linked against crane_bridge.js.

   The bridge handles:
   - WebAuthn passkey creation and authentication
   - ECDH P-256 keypair generation (Web Crypto API)
   - HPKE decryption (ECDH deriveBits + AES-GCM decrypt)
   - IndexedDB storage of reader keypairs
   - SessionStorage for decryption state *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.

Open Scope pstring_scope.

(* ---- Enrollment axioms -------------------------------------------- *)

Axiom crane_enroll_is_enrolled : unit -> bool.
(* Check if any reader key is enrolled in IndexedDB. *)

Axiom crane_enroll_create_reader : unit -> string.
(* Create a WebAuthn passkey + ECDH P-256 keypair.  Returns the
   hex-encoded public key for display.  Extraction: async JS call. *)

Axiom crane_enroll_get_pubkeys : unit -> string.
(* Get list of enrolled key IDs (comma-separated). *)

(* ---- Decryption axioms -------------------------------------------- *)

Axiom crane_decrypt_post : (string -> unit) -> unit.
(* Decrypt the current post.  Takes a callback that receives the
   decrypted plaintext string.  Extraction: crane_bridge.js
   crane_decryptPost function. *)

Axiom crane_decrypt_body : string -> string -> (string -> unit) -> unit.
(* Decrypt a body with a given CEK (hex) and ciphertext package
   (base64).  Takes a callback for the plaintext result. *)

(* ---- SessionStorage axioms ---------------------------------------- *)

Axiom crane_session_storage_get : string -> string.
(* Get a value from sessionStorage by key. *)

Axiom crane_session_storage_set : string -> string -> unit.
(* Set a value in sessionStorage. *)

Axiom crane_session_storage_remove : string -> unit.
(* Remove a key from sessionStorage. *)

(* ---- Extraction to OCaml ------------------------------------------ *)

Extraction Language OCaml.

Extract Constant crane_enroll_is_enrolled    => "Bridge_ffi.enroll_is_enrolled".
Extract Constant crane_enroll_create_reader  => "Bridge_ffi.enroll_create_reader".
Extract Constant crane_enroll_get_pubkeys    => "Bridge_ffi.enroll_get_pubkeys".
Extract Constant crane_decrypt_post          => "Bridge_ffi.decrypt_post".
Extract Constant crane_decrypt_body          => "Bridge_ffi.decrypt_body".
Extract Constant crane_session_storage_get   => "Bridge_ffi.session_storage_get".
Extract Constant crane_session_storage_set   => "Bridge_ffi.session_storage_set".
Extract Constant crane_session_storage_remove => "Bridge_ffi.session_storage_remove".
