(* encrypt_post — turn a plaintext posts/<slug>.md into a
   posts-encrypted/<slug>.eml with HPKE per-reader wrapped keys.
   Crypto is delegated to Crane_crypto (mirage_crypto + digestif).
   Replaces the old gpg-based RFC 3156 PGP/MIME pipeline. *)

open Io_helpers

let usage () =
  prerr_endline "usage: encrypt_post [--stage] <posts/slug.md> [...]";
  exit 2

let failf fmt = Printf.ksprintf (fun s -> prerr_endline s; exit 1) fmt

let validate_slug slug =
  let ok = ref (String.length slug > 0) in
  String.iter (fun c ->
    if not (c = '-' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
    then ok := false
  ) slug;
  if not !ok then failf "slug %S must match [a-z0-9-]+" slug

(* ---- Hex decode ----------------------------------------------------- *)

let hex_val c =
  match c with
  | '0'..'9' -> Char.code c - Char.code '0'
  | 'a'..'f' -> Char.code c - Char.code 'a' + 10
  | 'A'..'F' -> Char.code c - Char.code 'A' + 10
  | _ -> failf "invalid hex char: %c" c

let hex_decode hex =
  let n = String.length hex in
  if n mod 2 <> 0 then failf "hex string has odd length";
  let buf = Buffer.create (n / 2) in
  let i = ref 0 in
  while !i < n do
    let hi = hex_val hex.[!i] in
    let lo = hex_val hex.[!i + 1] in
    Buffer.add_char buf (Char.chr ((hi lsl 4) lor lo));
    i := !i + 2
  done;
  Buffer.contents buf

(* ---- Key store ------------------------------------------------------ *)

(* Keys are stored as hex-encoded raw public key (SEC1 compressed, 33 bytes)
   in files named keys/<keyid>.pub *)
let keys_dir () =
  let repo = repo_root () in
  Filename.concat repo "keys"

let read_pubkey keyid =
  let path = Filename.concat (keys_dir ()) (keyid ^ ".pub") in
  if not (file_exists path) then
    failf "public key not found: %s (expected at %s)" keyid path;
  let hex = trim (read_file path) in
  let raw = hex_decode hex in
  if String.length raw <> 33 then
    failf "public key %s has wrong length (%d, expected 33)" keyid (String.length raw);
  (hex, raw)

(* Hex encode a byte string *)
let hex_encode s =
  let buf = Buffer.create (String.length s * 2) in
  String.iter (fun c ->
    let b = Char.code c in
    Buffer.add_char buf "0123456789abcdef".[b lsr 4];
    Buffer.add_char buf "0123456789abcdef".[b land 0xf]
  ) s;
  Buffer.contents buf

(* ---- Author key resolution ------------------------------------------ *)

let resolve_author_key () =
  match Sys.getenv_opt "CRANE_BLOG_AUTHOR_KEY_ID" with
  | Some s when trim s <> "" ->
    let keyid = trim s in
    let hex, raw = read_pubkey keyid in
    (keyid, hex, raw)
  | _ ->
    let email = git ["config"; "user.email"] in
    if email = "" then failf "git config user.email is unset; set CRANE_BLOG_AUTHOR_KEY_ID or configure git";
    (* Derive key ID from email (for lookup in keys/ dir).
       Use SHA256 of the email, truncated to 12 hex chars. *)
    let hash = Crane_crypto.sha256 email in
    let keyid = String.sub (hex_encode (String.sub hash 0 6)) 0 12 in
    (try
      let hex, raw = read_pubkey keyid in
      (keyid, hex, raw)
    with _ ->
      failf "cannot resolve author key: set CRANE_BLOG_AUTHOR_KEY_ID or place key at keys/<keyid>.pub")

(* ---- Recipients ----------------------------------------------------- *)

(* Returns the author info and sorted recipient list.
   Each entry: (keyid, hex_pubkey, raw_pubkey) *)
let resolve_recipients meta =
  let author_keyid, author_hex, author_raw = resolve_author_key () in
  let extra_ids =
    match lookup "public-keys" meta with
    | None -> []
    | Some raw ->
      List.filter_map (fun s ->
        let s = trim s in if s = "" then None else Some s
      ) (split_on_char ',' raw)
  in
  if List.length extra_ids > 10 then
    failf "post declares %d extra recipients; max 10 (the author is added automatically)"
      (List.length extra_ids);
  let seen = Hashtbl.create 11 in
  let ordered = ref [] in
  let add_one (keyid, hex, raw) =
    if not (Hashtbl.mem seen keyid) then begin
      Hashtbl.add seen keyid ();
      ordered := (keyid, hex, raw) :: !ordered
    end
  in
  add_one (author_keyid, author_hex, author_raw);
  List.iter (fun keyid ->
    try
      let hex, raw = read_pubkey keyid in
      add_one (keyid, hex, raw)
    with _ -> failf "public key not found for recipient: %s" keyid
  ) extra_ids;
  let recipients = List.rev !ordered in
  (author_keyid, recipients)

(* ---- HPKE encrypt + wrap -------------------------------------------- *)

(* HPKE base-mode encrypt for a single recipient.
   Returns (encapsulated_key_raw, ciphertext_package) *)
let hpke_encrypt pkR_raw plaintext =
  let epk_raw, esk_raw = Crane_crypto.ecdh_p256_generate () in
  let dh_raw = Crane_crypto.ecdh_p256_agree esk_raw pkR_raw in
  let cek = Crane_crypto.custom_kdf_sha256 "" dh_raw "crane-blog-hpke-v1" 32 in
  let nonce = Crane_crypto.random_bytes 12 in
  let ct, tag = Crane_crypto.aes_256_gcm_encrypt cek nonce plaintext "" in
  (epk_raw, nonce ^ ct ^ tag)

(* HPKE wrap CEK for a recipient.
   Returns (encapsulated_key_raw, wrapped_package) *)
let hpke_wrap_cek cek pkR_raw key_id =
  let epk_raw, esk_raw = Crane_crypto.ecdh_p256_generate () in
  let dh_raw = Crane_crypto.ecdh_p256_agree esk_raw pkR_raw in
  let wrapping_key = Crane_crypto.custom_kdf_sha256 "" dh_raw "crane-blog-wrap-v1" 32 in
  let nonce = Crane_crypto.random_bytes 12 in
  let wrapped, tag = Crane_crypto.aes_256_gcm_encrypt wrapping_key nonce cek key_id in
  (epk_raw, nonce ^ wrapped ^ tag)

(* AES-256-GCM encrypt the post body with the CEK.
   Returns nonce(12) || ciphertext || tag(16).
   AAD binds the ciphertext to a specific post slug. *)
let encrypt_body cek body slug =
  let nonce = Crane_crypto.random_bytes 12 in
  let ct, tag = Crane_crypto.aes_256_gcm_encrypt cek nonce body slug in
  nonce ^ ct ^ tag

(* ---- RFC 5322 Date -------------------------------------------------- *)

let rfc5322_date () =
  let tm = Unix.gmtime (Unix.time ()) in
  let dow =
    [| "Sun"; "Mon"; "Tue"; "Wed"; "Thu"; "Fri"; "Sat" |].(tm.Unix.tm_wday) in
  let mon =
    [| "Jan"; "Feb"; "Mar"; "Apr"; "May"; "Jun";
       "Jul"; "Aug"; "Sep"; "Oct"; "Nov"; "Dec" |].(tm.Unix.tm_mon) in
  Printf.sprintf "%s, %02d %s %04d %02d:%02d:%02d +0000"
    dow tm.Unix.tm_mday mon (tm.Unix.tm_year + 1900)
    tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec

(* ---- HPKE MIME Envelope --------------------------------------------- *)

(* Build the outer HPKE MIME envelope:
     Subject: ...
     MIME-Version: 1.0
     Public-Keys: kid1, kid2, kid3
     Content-Type: multipart/hpke+wrapped; boundary="B"

     --B
     Content-Type: application/wrapped-keys
     Wraps: kid1:ekhex1:wrappedhex1, kid2:ekhex2:wrappedhex2

     --B
     Content-Type: application/aes-gcm
     Content-Transfer-Encoding: base64

     <b64(nonce || ct || tag)>
     --B-- *)

let build_hpke_envelope ~public_keys ~wrapped_entries ~ct_package () =
  let boundary = make_boundary () in
  let out = Buffer.create 4096 in
  Buffer.add_string out "Subject: ...\r\n";
  Buffer.add_string out "MIME-Version: 1.0\r\n";
  Buffer.add_string out
    (Printf.sprintf "Public-Keys: %s\r\n"
       (String.concat ", " (List.map (fun (kid, _, _) -> kid) public_keys)));
  Buffer.add_string out
    (Printf.sprintf
       "Content-Type: multipart/hpke+wrapped; boundary=\"%s\"\r\n" boundary);
  Buffer.add_string out "\r\n";
  Buffer.add_string out
    "This is an HPKE encrypted message for Crane Blog readers.\r\n";

  (* Wrapped keys part *)
  let wraps_line =
    String.concat ", "
      (List.map (fun (kid, ek_hex, w_hex) ->
         Printf.sprintf "%s:%s:%s" kid ek_hex w_hex
       ) wrapped_entries)
  in
  Buffer.add_string out (Printf.sprintf "--%s\r\n" boundary);
  Buffer.add_string out "Content-Type: application/wrapped-keys\r\n";
  Buffer.add_string out (Printf.sprintf "Wraps: %s\r\n" wraps_line);
  Buffer.add_string out "\r\n";

  (* Ciphertext part *)
  let ct_b64 = wrap_base64 (base64_encode ct_package) in
  Buffer.add_string out (Printf.sprintf "--%s\r\n" boundary);
  Buffer.add_string out "Content-Type: application/aes-gcm\r\n";
  Buffer.add_string out "Content-Transfer-Encoding: base64\r\n";
  Buffer.add_string out "\r\n";
  Buffer.add_string out ct_b64;
  if not (String.ends_with ~suffix:"\n" ct_b64) then
    Buffer.add_string out "\r\n";

  Buffer.add_string out (Printf.sprintf "--%s--\r\n" boundary);
  Buffer.contents out

(* ---- Main encrypt logic --------------------------------------------- *)

let encrypt_one ~stage md_path =
  let repo = repo_root () in
  let posts_dir = Filename.concat repo "posts" in
  let out_dir = Filename.concat repo "posts-encrypted" in
  (try Unix.mkdir out_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());

  let raw = read_file md_path in
  let meta, body = parse_frontmatter raw in
  let md_basename = Filename.basename md_path in
  let fallback = Filename.remove_extension md_basename in
  let slug =
    match lookup "slug" meta with
    | Some s when s <> "" -> s
    | _ -> fallback
  in
  validate_slug slug;

  let author_keyid, public_keys = resolve_recipients meta in
  let date = rfc5322_date () in

  let title =
    match lookup "title" meta with
    | Some t when t <> "" -> t
    | _ -> "Untitled"
  in
  let title = require_header_value "title" title in

  (* Protected headers: go inside the encrypted inner MIME *)
  let from_key =
    match Sys.getenv_opt "CRANE_BLOG_AUTHOR_EMAIL" with
    | Some s when trim s <> "" -> trim s
    | _ -> git ["config"; "user.email"]
  in
  let recipients_str =
    String.concat ", " (List.map (fun (kid, _, _) -> "reader:" ^ kid) public_keys)
  in
  let protected_headers =
    [ "From", from_key;
      "To", recipients_str;
      "Date", date;
      "Subject", title ]
  in

  let image_refs = collect_image_refs body in
  let images =
    List.map (fun rel ->
      let segs = split_on_char '/' rel in
      if List.exists (fun s -> s = ".." || s = "" || s = ".") segs then
        failf "image path %s is not a simple relative name" rel;
      let p = Filename.concat posts_dir rel in
      if not (file_exists p) then
        failf "referenced image not found: %s" rel;
      let name = require_safe_filename "image filename" (Filename.basename rel) in
      (name, read_file p)
    ) image_refs
  in

  let inner_mime =
    build_inner_mime
      ~protected:protected_headers
      ~md_filename:md_basename
      ~md_body:raw
      ~images
      ()
  in

  (* Generate CEK and encrypt body *)
  let cek = Crane_crypto.random_bytes 32 in
  let ct_package = encrypt_body cek inner_mime slug in

  (* Wrap CEK for each recipient *)
  let wrapped_entries =
    List.map (fun (keyid, _hex, raw_pk) ->
      let ek_raw, wrapped_pkg = hpke_wrap_cek cek raw_pk keyid in
      (keyid, hex_encode ek_raw, hex_encode wrapped_pkg)
    ) public_keys
  in

  let envelope = build_hpke_envelope
    ~public_keys
    ~wrapped_entries
    ~ct_package
    ()
  in

  let out_path = Filename.concat out_dir (slug ^ ".eml") in
  write_file out_path envelope;

  if stage then begin
    let rel_out =
      let n = String.length repo + 1 in
      if starts_with out_path (repo ^ "/") then
        String.sub out_path n (String.length out_path - n)
      else out_path
    in
    ignore (git ["add"; "--"; rel_out]);
    let rel_md =
      let n = String.length repo + 1 in
      if starts_with md_path (repo ^ "/") then
        String.sub md_path n (String.length md_path - n)
      else md_path
    in
    let _ = run_capture [|"git"; "reset"; "HEAD"; "--"; rel_md|] "" in
    ()
  end;
  prerr_endline (Printf.sprintf "encrypted %s -> %s (recipients: %d)"
    md_path out_path (List.length public_keys))

(* ---- CLI ------------------------------------------------------------ *)

let () =
  let stage = ref false in
  let paths = ref [] in
  let rec parse = function
    | [] -> ()
    | "--stage" :: rest -> stage := true; parse rest
    | ("-h" | "--help") :: _ -> usage ()
    | p :: rest -> paths := p :: !paths; parse rest
  in
  parse (List.tl (Array.to_list Sys.argv));
  if !paths = [] then usage ();
  List.iter (fun p ->
    if not (file_exists p) then failf "not a file: %s" p;
    if Filename.extension p <> ".md" then
      failf "expected a .md file, got: %s" p;
    encrypt_one ~stage:!stage p
  ) (List.rev !paths)
