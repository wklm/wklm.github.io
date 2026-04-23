(* decrypt_post -- reverse of encrypt_post for local editing.
   Reads posts-encrypted/<slug>.eml, asks [gpg --decrypt] to unwrap
   the RFC 3156 envelope, and writes the original .md + any
   attachments back to posts/.  Crypto is delegated entirely to gpg. *)

open Pgp_mime

let fail msg = prerr_endline msg; exit 1

let gpg_decrypt armored =
  let code, out, err =
    run_capture [|"gpg"; "--batch"; "--yes"; "--decrypt"|] armored
  in
  if code <> 0 then begin
    prerr_string err;
    fail (Printf.sprintf "gpg --decrypt failed with exit code %d" code)
  end;
  out

let () =
  let argv = Sys.argv in
  if Array.length argv <> 2 then begin
    prerr_endline "usage: decrypt_post <posts-encrypted/slug.eml>";
    exit 2
  end;
  let eml_path = argv.(1) in
  let repo = repo_root () in
  let posts_dir = Filename.concat repo "posts" in
  (try Unix.mkdir posts_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());

  let raw = read_file eml_path in
  let outer_headers_raw, outer_body = split_headers_body raw in
  let outer_headers = parse_headers outer_headers_raw in
  let ct =
    match lookup "Content-Type" outer_headers with
    | Some v -> v
    | None -> fail "outer message has no Content-Type"
  in
  let boundary =
    match extract_boundary ct with
    | Some b -> b
    | None -> fail "outer Content-Type has no boundary"
  in
  let parts = split_multipart outer_body boundary in
  (* RFC 3156: the second part is the application/octet-stream
     carrying the ASCII-armored ciphertext. *)
  let armored =
    List.find_map (fun part ->
      let part = trim_part_terminator part in
      let ph_raw, pb = split_headers_body part in
      let ph = parse_headers ph_raw in
      match content_type ph with
      | "application/octet-stream" -> Some pb
      | _ -> None
    ) parts
  in
  let armored = match armored with
    | Some s -> s
    | None -> fail "no application/octet-stream part in the envelope"
  in
  let plaintext = gpg_decrypt armored in

  (* Walk the inner MIME tree and write out every part that has a
     filename.  The inner root is multipart/mixed. *)
  let inner_headers_raw, inner_body = split_headers_body plaintext in
  let inner_headers = parse_headers inner_headers_raw in
  let inner_ct =
    match lookup "Content-Type" inner_headers with
    | Some v -> v
    | None -> fail "inner message has no Content-Type"
  in
  let inner_boundary =
    match extract_boundary inner_ct with
    | Some b -> b
    | None -> fail "inner Content-Type has no boundary"
  in
  let inner_parts = split_multipart inner_body inner_boundary in
  List.iter (fun part ->
    let part = trim_part_terminator part in
    let ph_raw, pb = split_headers_body part in
    let ph = parse_headers ph_raw in
    match extract_filename ph with
    | None -> ()
    | Some name ->
      let data = decode_transfer ph pb in
      let target = Filename.concat posts_dir name in
      write_file target data;
      let rel =
        let n = String.length repo + 1 in
        if starts_with target (repo ^ "/") then
          String.sub target n (String.length target - n)
        else target
      in
      print_endline (Printf.sprintf "decrypted -> %s" rel)
  ) inner_parts
