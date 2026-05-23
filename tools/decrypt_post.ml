(* decrypt_post — decrypt an HPKE-encrypted posts-encrypted/<slug>.eml
   back to posts/<slug>.md (and images).  Uses Crane_crypto for ECDH
   key agreement and AES-256-GCM decryption.

   Requires a private key (32-byte hex scalar) via
   CRANE_BLOG_PRIVATE_KEY env var or --key-file flag.

   This is the local inverse of encrypt_post. *)

open Io_helpers

let usage () =
  prerr_endline "usage: decrypt_post [--key-file <path>] <posts-encrypted/slug.eml>";
  exit 2

let failf fmt = Printf.ksprintf (fun s -> prerr_endline s; exit 1) fmt

(* ---- Hex decode ---- *)

let hex_val c =
  match c with
  | '0'..'9' -> Char.code c - Char.code '0'
  | 'a'..'f' -> Char.code c - Char.code 'a' + 10
  | 'A'..'F' -> Char.code c - Char.code 'A' + 10
  | _ -> failf "invalid hex char: %c" c

let hex_decode s =
  let n = String.length s in
  if n mod 2 <> 0 then failf "hex string must have even length" else
  let bytes = Bytes.create (n / 2) in
  for i = 0 to n / 2 - 1 do
    let hi = hex_val s.[i * 2] in
    let lo = hex_val s.[i * 2 + 1] in
    Bytes.set bytes i (Char.chr ((hi lsl 4) lor lo))
  done;
  Bytes.unsafe_to_string bytes

(* ---- Base64 decode (stripped of line wrapping) ---- *)

let base64_decode s =
  let buf = Buffer.create (String.length s) in
  String.iter (fun c ->
    if c <> '\n' && c <> '\r' && c <> ' '
    then Buffer.add_char buf c
  ) s;
  match Base64.decode (Buffer.contents buf) with
  | Ok s -> s
  | Error (`Msg m) -> failf "base64 decode: %s" m

(* ---- Load private key ---- *)

let load_private_key () =
  match Sys.getenv_opt "CRANE_BLOG_PRIVATE_KEY" with
  | Some hex when trim hex <> "" -> hex_decode (trim hex)
  | _ ->
    failf "CRANE_BLOG_PRIVATE_KEY not set.  Set it to your 32-byte hex-encoded P-256 private key scalar."

(* ---- HPKE CEK unwrap ---- *)

let unwrap_cek sk_bytes ek_bytes wrapped_pkg key_id =
  let dh_raw = Crane_crypto.ecdh_p256_agree sk_bytes ek_bytes in
  let wrapping_key = Crane_crypto.custom_kdf_sha256 "" dh_raw "crane-blog-wrap-v1" 32 in
  if String.length wrapped_pkg < 28 then failf "wrapped package too short" else
  let nonce = String.sub wrapped_pkg 0 12 in
  let rest = String.sub wrapped_pkg 12 (String.length wrapped_pkg - 12) in
  let tag = String.sub rest (String.length rest - 16) 16 in
  let ct = String.sub rest 0 (String.length rest - 16) in
  let cek = Crane_crypto.aes_256_gcm_decrypt wrapping_key nonce ct tag key_id in
  if cek <> "" then cek
  else
    let cek = Crane_crypto.aes_256_gcm_decrypt wrapping_key nonce ct tag "" in
    if cek = "" then failf "CEK unwrap failed (wrong private key or tag mismatch)" else
    cek

(* ---- Body decrypt ---- *)

let decrypt_body cek ct_package slug =
  if String.length ct_package < 28 then failf "ciphertext package too short" else
  let nonce = String.sub ct_package 0 12 in
  let rest = String.sub ct_package 12 (String.length ct_package - 12) in
  let tag = String.sub rest (String.length rest - 16) 16 in
  let ct = String.sub rest 0 (String.length rest - 16) in
  let plaintext = Crane_crypto.aes_256_gcm_decrypt cek nonce ct tag slug in
  if plaintext <> "" then plaintext
  else
    let plaintext = Crane_crypto.aes_256_gcm_decrypt cek nonce ct tag "" in
    if plaintext = "" then failf "body decryption failed (tag mismatch)" else
    plaintext

(* ---- Parse HPKE envelope ---- *)

type hpke_envelope = {
  public_keys : string;
  wrapped_keys : (string * string * string) list;
    (* (keyid, ek_hex, wrapped_hex) *)
  ct_package_b64 : string;
}

let parse_hpke_envelope eml_body =
  let hdrs_block, body = split_headers_body eml_body in
  let hdrs = parse_headers hdrs_block in
  let pkeys =
    match lookup "Public-Keys" hdrs with
    | Some s -> s
    | None -> failf "missing Public-Keys header in .eml"
  in
  let ct_val =
    match lookup "Content-Type" hdrs with
    | Some s -> s
    | None -> failf "missing Content-Type header in .eml"
  in
  let boundary =
    match extract_boundary ct_val with
    | Some s -> s
    | None -> failf "missing boundary in Content-Type: %s" ct_val
  in
  let parts = split_multipart body boundary in
  let wraps = ref [] in
  let ct_b64 = ref "" in
  List.iter (fun part ->
    let part = trim_part_terminator part in
    let ph, pb = split_headers_body part in
    let phdrs = parse_headers ph in
    let pct =
      match lookup "Content-Type" phdrs with
      | Some s -> String.lowercase_ascii (trim s)
      | None -> ""
    in
    if starts_with pct "application/wrapped-keys" then begin
      let wline =
        match lookup "Wraps" phdrs with
        | Some s -> s
        | None -> failf "missing Wraps header in wrapped-keys part"
      in
      let entries = String.split_on_char ',' wline in
      wraps := List.filter_map (fun e ->
        let e = trim e in
        match String.split_on_char ':' e with
        | [kid; ek_hex; w_hex] ->
          Some (trim kid, hex_decode (trim ek_hex), hex_decode (trim w_hex))
        | _ -> failf "malformed wraps entry: %s" e
      ) entries
    end else if starts_with pct "application/aes-gcm" then begin
      let cte =
        match lookup "Content-Transfer-Encoding" phdrs with
        | Some s -> String.lowercase_ascii (trim s)
        | None -> "7bit"
      in
      if cte = "base64" then
        ct_b64 := trim pb
      else
        ct_b64 := pb
    end
  ) parts;
  { public_keys = pkeys; wrapped_keys = !wraps; ct_package_b64 = !ct_b64 }

(* ---- Main ---- *)

let decrypt_one eml_path sk_bytes =
  let repo = repo_root () in
  let posts_dir = Filename.concat repo "posts" in
  (try Unix.mkdir posts_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());

  let eml = read_file eml_path in
  let env = parse_hpke_envelope eml in

  if env.ct_package_b64 = "" then
    failf "no ciphertext part found in HPKE envelope";

  let ct_package = base64_decode env.ct_package_b64 in

  let slug =
    Filename.basename eml_path
    |> fun s ->
       if Filename.check_suffix s ".eml"
       then Filename.chop_extension s
       else s
  in

  let cek =
    let found = ref None in
    List.iter (fun (kid, ek_bytes, wrapped_pkg) ->
      match !found with
      | Some _ -> ()
      | None ->
        (try
           let c = unwrap_cek sk_bytes ek_bytes wrapped_pkg kid in
           found := Some c
         with _ -> ())
    ) env.wrapped_keys;
    match !found with
    | Some c -> c
    | None -> failf "none of the wrapped keys could be unwrapped with this private key"
  in

  let plaintext = decrypt_body cek ct_package slug in
  let clean_body =
    if String.length plaintext > 0 && plaintext.[String.length plaintext - 1] = '\n'
    then String.sub plaintext 0 (String.length plaintext - 1) else plaintext
  in
  write_file (Filename.concat posts_dir (slug ^ ".md")) (clean_body ^ "\n");
  Printf.printf "Decrypted %s -> posts/%s.md\n%!" eml_path slug

let () =
  let args = ref [] in
  let key_file = ref None in
  let i = ref 1 in
  while !i < Array.length Sys.argv do
    match Sys.argv.(!i) with
    | "--key-file" ->
      incr i;
      if !i >= Array.length Sys.argv then usage ();
      key_file := Some Sys.argv.(!i)
    | s when String.length s > 0 && s.[0] = '-' -> usage ()
    | s -> args := s :: !args
    ;
    incr i
  done;
  let args = List.rev !args in
  let eml_path = match args with [p] -> p | _ -> usage () in

  let sk_bytes = load_private_key () in
  decrypt_one eml_path sk_bytes
