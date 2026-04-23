(* encrypt_post -- turn a plaintext posts/<slug>.md into a
   posts-encrypted/<slug>.eml whose body is one RFC 3156 PGP/MIME
   multipart/encrypted message.  Crypto is delegated entirely to
   [gpg].  We only assemble MIME framing. *)

open Pgp_mime

let usage () =
  prerr_endline "usage: encrypt_post [--stage] <posts/slug.md> [...]";
  exit 2

let fail msg = prerr_endline msg; exit 1

let validate_slug slug =
  let ok = ref (String.length slug > 0) in
  String.iter (fun c ->
    if not (c = '-'
            || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9'))
    then ok := false
  ) slug;
  if not !ok then fail (Printf.sprintf "slug %S must match [a-z0-9-]+" slug)

let resolve_recipients (meta : (string * string) list) =
  let author = git ["config"; "user.email"] in
  if author = "" then fail "git config user.email is unset; refusing to encrypt";
  let extras =
    match lookup "recipients" meta with
    | None -> []
    | Some raw ->
      List.filter_map (fun s ->
        let s = trim s in if s = "" then None else Some s
      ) (split_on_char ',' raw)
  in
  if List.length extras > 3 then
    fail (Printf.sprintf
            "post declares %d extra recipients; max 3 (the author is added automatically)"
            (List.length extras));
  (* Deduplicate while preserving order; author goes first. *)
  let seen = Hashtbl.create 4 in
  let ordered = ref [] in
  List.iter (fun r ->
    let rl = String.lowercase_ascii r in
    if not (Hashtbl.mem seen rl) then begin
      Hashtbl.add seen rl ();
      ordered := r :: !ordered
    end
  ) (author :: extras);
  (author, List.rev !ordered)

(* RFC 5322 date: "Thu, 23 Apr 2026 13:45:00 +0000".  Always UTC. *)
let rfc5322_date () =
  let tm = Unix.gmtime (Unix.time ()) in
  let dow =
    [| "Sun"; "Mon"; "Tue"; "Wed"; "Thu"; "Fri"; "Sat" |].(tm.Unix.tm_wday)
  in
  let mon =
    [| "Jan"; "Feb"; "Mar"; "Apr"; "May"; "Jun";
       "Jul"; "Aug"; "Sep"; "Oct"; "Nov"; "Dec" |].(tm.Unix.tm_mon)
  in
  Printf.sprintf "%s, %02d %s %04d %02d:%02d:%02d +0000"
    dow tm.Unix.tm_mday mon (tm.Unix.tm_year + 1900)
    tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec

let gpg_sign_encrypt ~author ~recipients plaintext =
  let args =
    ["gpg"; "--batch"; "--yes"; "--armor"; "--sign"; "--encrypt";
     "--trust-model"; "always";
     "--local-user"; author]
    @ List.concat_map (fun r -> ["--recipient"; r]) recipients
  in
  let argv = Array.of_list args in
  let code, out, err = run_capture argv plaintext in
  if code <> 0 then begin
    prerr_string err;
    fail (Printf.sprintf "gpg failed with exit code %d" code)
  end;
  out

let encrypt_one ~stage md_path =
  let repo = repo_root () in
  let posts_dir = Filename.concat repo "posts" in
  let out_dir = Filename.concat repo "posts-encrypted" in
  (try Unix.mkdir out_dir 0o755 with Unix.Unix_error (Unix.EEXIST, _, _) -> ());

  let raw = read_file md_path in
  let meta, body = parse_frontmatter raw in
  let md_basename = Filename.basename md_path in
  let fallback =
    let stem = Filename.remove_extension md_basename in
    stem
  in
  let slug =
    match lookup "slug" meta with
    | Some s when s <> "" -> s
    | _ -> fallback
  in
  validate_slug slug;

  let author, recipients = resolve_recipients meta in
  let date = rfc5322_date () in
  (* Subject is always the literal placeholder: no metadata leaks
     through the outer envelope.  (Matches the cautious reading of
     the Protected Headers draft.) *)
  let subject_placeholder = "..." in
  let visible =
    [ "From", author;
      "To", String.concat ", " recipients;
      "Date", date;
      "Subject", subject_placeholder ]
  in

  let image_refs = collect_image_refs body in
  let images =
    List.map (fun rel ->
      (* Reject any rel path that contains traversal or is absolute.
         [collect_image_refs] has already dropped http(s) and leading-/
         paths; this is a belt-and-braces check for [..] segments. *)
      let segs = split_on_char '/' rel in
      if List.exists (fun s -> s = ".." || s = "" || s = ".") segs then
        fail (Printf.sprintf "image path %s is not a simple relative name" rel);
      let p = Filename.concat posts_dir rel in
      if not (file_exists p) then
        fail (Printf.sprintf "referenced image not found: %s" rel);
      (Filename.basename rel, read_file p)
    ) image_refs
  in

  let inner =
    build_inner_mime
      ~protected:visible
      ~md_filename:md_basename
      ~md_body:raw
      ~images
      ()
  in
  let armored = gpg_sign_encrypt ~author ~recipients inner in
  let envelope = build_outer_envelope ~visible ~armored () in

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
    (* Ignore errors: plaintext may not have been staged to begin with. *)
    let _ = run_capture [|"git"; "reset"; "HEAD"; "--"; rel_md|] "" in
    ()
  end;
  prerr_endline (Printf.sprintf "encrypted %s -> %s" md_path out_path)

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
    if not (file_exists p) then fail (Printf.sprintf "not a file: %s" p);
    if Filename.extension p <> ".md" then
      fail (Printf.sprintf "expected a .md file, got: %s" p);
    encrypt_one ~stage:!stage p
  ) (List.rev !paths)
