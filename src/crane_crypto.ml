(* crane_crypto.ml — OCaml FFI bridge for Coq crypto axioms.
   Wraps mirage_crypto_ec (ECDH P-256), mirage_crypto (AES-GCM),
   and digestif (SHA-256). *)

(* Initialize the RNG — required by mirage-crypto-ec for key generation *)
let () =
  Mirage_crypto_rng_unix.use_default ()

(* ---- P-256 ECDH ---- *)

let ecdh_p256_generate () =
  let sk, pk = Mirage_crypto_ec.P256.Dh.gen_key ~compress:false () in
  (pk, Mirage_crypto_ec.P256.Dh.secret_to_octets sk)

let ecdh_p256_public_key sk_bytes =
  match
    Mirage_crypto_ec.P256.Dh.secret_of_octets ~compress:false sk_bytes
  with
  | Ok (_sk, pk) -> pk
  | Error _ -> ""

let ecdh_p256_agree sk_bytes pk_bytes =
  match
    Mirage_crypto_ec.P256.Dh.secret_of_octets sk_bytes
  with
  | Ok (sk, _) ->
    (match Mirage_crypto_ec.P256.Dh.key_exchange sk pk_bytes with
     | Ok shared -> shared
     | Error _ -> "")
  | Error _ -> ""

(* ---- Random bytes ---- *)

let random_bytes n =
  if n <= 0 then "" else
  Mirage_crypto_rng.generate n

(* ---- AES-256-GCM ---- *)

let aes_256_gcm_encrypt key nonce plaintext aad =
  let key = Mirage_crypto.AES.GCM.of_secret key in
  let ct, tag = Mirage_crypto.AES.GCM.authenticate_encrypt_tag
      ~key ~nonce ?adata:(if aad = "" then None else Some aad) plaintext in
  (ct, tag)

let aes_256_gcm_decrypt key nonce ciphertext tag aad =
  let key = Mirage_crypto.AES.GCM.of_secret key in
  Mirage_crypto.AES.GCM.authenticate_decrypt_tag
    ~key ~nonce ~tag ?adata:(if aad = "" then None else Some aad) ciphertext
  |> Option.value ~default:""

(* ---- SHA-256 ---- *)

let sha256 data =
  Digestif.SHA256.digest_string data |> Digestif.SHA256.to_raw_string

(* ---- KDF: SHA-256 based (simple, sufficient for blog encryption) ---- *)

let custom_kdf_sha256 _salt ikm info _len =
  (* HKDF extract — use SHA-256(zero_salt || ikm) *)
  let prk = sha256 (String.make 32 '\x00' ^ ikm) in
  (* HKDF expand — single step: SHA-256(prk || info || 0x01) *)
  sha256 (prk ^ info ^ "\x01")

(* ---- Base64 ---- *)

let base64_encode s =
  Base64.encode_string s

let base64_decode s =
  match Base64.decode s with
  | Ok s -> s
  | Error (`Msg _) -> ""
