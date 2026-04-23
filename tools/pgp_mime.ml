(* Shared MIME / subprocess / git / filesystem helpers for the
   encrypt and decrypt CLIs.  Pure OCaml stdlib + Unix.  No crypto. *)

(* ---- File I/O ---------------------------------------------------- *)

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let b = Bytes.create n in
  really_input ic b 0 n;
  close_in ic;
  Bytes.unsafe_to_string b

let write_file path data =
  let oc = open_out_bin path in
  output_string oc data;
  close_out oc

let file_exists p = Sys.file_exists p && not (Sys.is_directory p)

(* ---- String helpers --------------------------------------------- *)

let starts_with s p =
  let ls = String.length s and lp = String.length p in
  lp <= ls && String.sub s 0 lp = p

let trim = String.trim

let split_on_char c s =
  let r = ref [] in
  let j = ref (String.length s) in
  for i = String.length s - 1 downto 0 do
    if String.unsafe_get s i = c then begin
      r := String.sub s (i + 1) (!j - i - 1) :: !r;
      j := i
    end
  done;
  String.sub s 0 !j :: !r

(* ---- Base64 ------------------------------------------------------ *)

let b64_chars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

let base64_encode s =
  let len = String.length s in
  let buf = Buffer.create ((len / 3 + 1) * 4) in
  let i = ref 0 in
  while !i + 3 <= len do
    let b0 = Char.code s.[!i] in
    let b1 = Char.code s.[!i + 1] in
    let b2 = Char.code s.[!i + 2] in
    Buffer.add_char buf b64_chars.[b0 lsr 2];
    Buffer.add_char buf b64_chars.[((b0 land 0x3) lsl 4) lor (b1 lsr 4)];
    Buffer.add_char buf b64_chars.[((b1 land 0xf) lsl 2) lor (b2 lsr 6)];
    Buffer.add_char buf b64_chars.[b2 land 0x3f];
    i := !i + 3
  done;
  let rem = len - !i in
  if rem = 1 then begin
    let b0 = Char.code s.[!i] in
    Buffer.add_char buf b64_chars.[b0 lsr 2];
    Buffer.add_char buf b64_chars.[(b0 land 0x3) lsl 4];
    Buffer.add_string buf "=="
  end else if rem = 2 then begin
    let b0 = Char.code s.[!i] in
    let b1 = Char.code s.[!i + 1] in
    Buffer.add_char buf b64_chars.[b0 lsr 2];
    Buffer.add_char buf b64_chars.[((b0 land 0x3) lsl 4) lor (b1 lsr 4)];
    Buffer.add_char buf b64_chars.[(b1 land 0xf) lsl 2];
    Buffer.add_char buf '='
  end;
  Buffer.contents buf

let b64_decode_table =
  let t = Array.make 256 (-1) in
  String.iteri (fun i c -> t.(Char.code c) <- i) b64_chars;
  t

let base64_decode s =
  let buf = Buffer.create (String.length s) in
  let bits = ref 0 and nbits = ref 0 in
  String.iter (fun c ->
    if c = '=' then ()
    else
      let v = b64_decode_table.(Char.code c) in
      if v >= 0 then begin
        bits := (!bits lsl 6) lor v;
        nbits := !nbits + 6;
        if !nbits >= 8 then begin
          nbits := !nbits - 8;
          Buffer.add_char buf (Char.chr ((!bits lsr !nbits) land 0xff))
        end
      end
  ) s;
  Buffer.contents buf

(* Wrap a long base64 blob at 76 columns per RFC 2045. *)
let wrap_base64 s =
  let buf = Buffer.create (String.length s + String.length s / 76) in
  let n = String.length s in
  let i = ref 0 in
  while !i < n do
    let take = min 76 (n - !i) in
    Buffer.add_substring buf s !i take;
    Buffer.add_string buf "\r\n";
    i := !i + take
  done;
  Buffer.contents buf

(* ---- Subprocess -------------------------------------------------- *)

(* Run [argv], pipe [stdin_data] to its stdin, capture stdout/stderr.
   Returns (exit_code, stdout, stderr). *)
let run_capture ?(env = Unix.environment ()) argv stdin_data =
  let in_r, in_w = Unix.pipe ~cloexec:true () in
  let out_r, out_w = Unix.pipe ~cloexec:true () in
  let err_r, err_w = Unix.pipe ~cloexec:true () in
  let pid =
    Unix.create_process_env argv.(0) argv env in_r out_w err_w
  in
  Unix.close in_r;
  Unix.close out_w;
  Unix.close err_w;
  (* Write stdin on a helper thread equivalent: use non-blocking write loop.
     For our sizes (<= a few MB) a single writev after selecting stdout
     drain is fine; simplest is to write then close, reading after. *)
  let write_all fd s =
    let len = String.length s in
    let pos = ref 0 in
    while !pos < len do
      let n = Unix.write_substring fd s !pos (len - !pos) in
      if n = 0 then failwith "short write";
      pos := !pos + n
    done
  in
  (* To avoid deadlocks when the child fills its stdout buffer before
     we finish writing, use a fork: drain stdout/stderr in a child-like
     loop using select. *)
  let obuf = Buffer.create 4096 and ebuf = Buffer.create 1024 in
  let chunk = Bytes.create 4096 in
  let in_closed = ref false in
  let stdin_pos = ref 0 in
  let stdin_len = String.length stdin_data in
  let out_open = ref true and err_open = ref true in
  while (!out_open || !err_open) do
    let rfds =
      (if !out_open then [out_r] else [])
      @ (if !err_open then [err_r] else [])
    in
    let wfds =
      if !in_closed then [] else [in_w]
    in
    let r, w, _ = Unix.select rfds wfds [] (-1.0) in
    List.iter (fun fd ->
      let n = Unix.read fd chunk 0 (Bytes.length chunk) in
      if n = 0 then begin
        Unix.close fd;
        if fd = out_r then out_open := false
        else if fd = err_r then err_open := false
      end else if fd = out_r then
        Buffer.add_subbytes obuf chunk 0 n
      else
        Buffer.add_subbytes ebuf chunk 0 n
    ) r;
    List.iter (fun fd ->
      if fd = in_w && not !in_closed then begin
        let remaining = stdin_len - !stdin_pos in
        if remaining = 0 then begin
          Unix.close in_w;
          in_closed := true
        end else begin
          let n = Unix.write_substring in_w stdin_data !stdin_pos remaining in
          stdin_pos := !stdin_pos + n;
          if !stdin_pos = stdin_len then begin
            Unix.close in_w;
            in_closed := true
          end
        end
      end
    ) w
  done;
  if not !in_closed then (Unix.close in_w; in_closed := true);
  let _, status = Unix.waitpid [] pid in
  let code = match status with
    | Unix.WEXITED c -> c
    | Unix.WSIGNALED s -> 128 + s
    | Unix.WSTOPPED s -> 128 + s
  in
  ignore (write_all);
  (code, Buffer.contents obuf, Buffer.contents ebuf)

let must_run argv stdin_data =
  let code, out, err = run_capture argv stdin_data in
  if code <> 0 then begin
    prerr_string err;
    failwith (Printf.sprintf "%s exited with %d" argv.(0) code)
  end;
  out

(* ---- Git --------------------------------------------------------- *)

let git args =
  let argv = Array.of_list ("git" :: args) in
  let s = must_run argv "" in
  trim s

let repo_root () = git ["rev-parse"; "--show-toplevel"]

(* ---- Frontmatter + image scan ----------------------------------- *)

let parse_frontmatter raw =
  (* Accept "---\n" at position 0 followed by lines up to the next "---\n". *)
  if not (starts_with raw "---\n" || starts_with raw "---\r\n") then
    ([], raw)
  else
    let after_open =
      if starts_with raw "---\r\n" then 5 else 4
    in
    (* Find "\n---\n" or "\n---\r\n" starting from after_open. *)
    let len = String.length raw in
    let rec find i =
      if i + 4 > len then None
      else if raw.[i] = '\n'
           && i + 4 <= len
           && raw.[i+1] = '-' && raw.[i+2] = '-' && raw.[i+3] = '-'
      then
        (* Match the rest of the close marker. *)
        if i + 4 < len && raw.[i+4] = '\n' then Some (i, i + 5)
        else if i + 5 < len && raw.[i+4] = '\r' && raw.[i+5] = '\n' then Some (i, i + 6)
        else find (i + 1)
      else find (i + 1)
    in
    match find after_open with
    | None -> ([], raw)
    | Some (block_end, body_start) ->
      let block = String.sub raw after_open (block_end - after_open) in
      let body = String.sub raw body_start (len - body_start) in
      let kv =
        List.filter_map (fun line ->
          let line = trim line in
          if line = "" then None
          else match String.index_opt line ':' with
            | None -> None
            | Some i ->
              let k = trim (String.sub line 0 i) in
              let v = trim (String.sub line (i+1) (String.length line - i - 1)) in
              Some (k, v)
        ) (split_on_char '\n' block)
      in
      (kv, body)

let lookup k kv = try Some (List.assoc k kv) with Not_found -> None

(* Collect every [![alt](path)] path in [body], deduplicated, in
   first-occurrence order, skipping http:// https:// and leading /. *)
let collect_image_refs body =
  let n = String.length body in
  let out = ref [] in
  let seen = Hashtbl.create 8 in
  let i = ref 0 in
  while !i < n - 3 do
    if body.[!i] = '!' && body.[!i + 1] = '[' then begin
      match String.index_from_opt body (!i + 2) ']' with
      | Some close ->
        if close + 1 < n && body.[close + 1] = '(' then begin
          match String.index_from_opt body (close + 2) ')' with
          | Some paren_close ->
            let url = String.sub body (close + 2) (paren_close - close - 2) in
            let url = trim url in
            let bad =
              starts_with url "http://"
              || starts_with url "https://"
              || (String.length url > 0 && url.[0] = '/')
              || url = ""
            in
            if not bad && not (Hashtbl.mem seen url) then begin
              Hashtbl.add seen url ();
              out := url :: !out
            end;
            i := paren_close + 1
          | None -> incr i
        end else incr i
      | None -> incr i
    end else incr i
  done;
  List.rev !out

(* ---- MIME assembly ---------------------------------------------- *)

(* Deterministic boundary: a fixed prefix plus a hash of the content.
   Using a constant prefix matches the "no crypto in OCaml" rule --
   we pick uniqueness via the current pid + a counter.  Boundaries
   only need to be unlikely to appear verbatim inside a part; they
   are public framing, not a secret. *)

let boundary_counter = ref 0

let make_boundary () =
  incr boundary_counter;
  Printf.sprintf "=_cb_%d_%d_%d_="
    (Unix.getpid ())
    (int_of_float (Unix.gettimeofday () *. 1000.))
    !boundary_counter

(* Encode a header value folded at ~76 columns per RFC 5322 3.2.2.
   We do not emit RFC 2047 encoded-words; the author's email and the
   To/From/Subject on the outer envelope are ASCII by policy (the
   literal "..." Subject has no non-ASCII bytes). *)
let header_line k v =
  Printf.sprintf "%s: %s\r\n" k v

(* Build inner MIME:
     multipart/mixed; boundary="X"
       [protected headers copied]
     --X
     Content-Type: text/markdown; charset=utf-8
     Content-Disposition: inline; filename="<md>"
     Content-Transfer-Encoding: 8bit

     <raw markdown>
     --X
     Content-Type: application/octet-stream; name="<img>"
     Content-Disposition: attachment; filename="<img>"
     Content-Transfer-Encoding: base64

     <wrapped base64>
     --X--
*)
let build_inner_mime
    ~protected
    ~md_filename
    ~md_body
    ~images
    () =
  let b = make_boundary () in
  let out = Buffer.create 4096 in
  List.iter (fun (k, v) -> Buffer.add_string out (header_line k v)) protected;
  Buffer.add_string out "MIME-Version: 1.0\r\n";
  Buffer.add_string out
    (Printf.sprintf "Content-Type: multipart/mixed; boundary=\"%s\"\r\n" b);
  Buffer.add_string out "\r\n";
  Buffer.add_string out
    "This is a multi-part message in MIME format.\r\n";
  (* Markdown part. *)
  Buffer.add_string out (Printf.sprintf "--%s\r\n" b);
  Buffer.add_string out "Content-Type: text/markdown; charset=utf-8\r\n";
  Buffer.add_string out
    (Printf.sprintf "Content-Disposition: inline; filename=\"%s\"\r\n"
       md_filename);
  Buffer.add_string out "Content-Transfer-Encoding: 8bit\r\n";
  Buffer.add_string out "\r\n";
  Buffer.add_string out md_body;
  if String.length md_body = 0
     || md_body.[String.length md_body - 1] <> '\n'
  then Buffer.add_string out "\r\n";
  (* Image parts. *)
  List.iter (fun (name, bytes) ->
    Buffer.add_string out (Printf.sprintf "--%s\r\n" b);
    Buffer.add_string out
      (Printf.sprintf "Content-Type: application/octet-stream; name=\"%s\"\r\n"
         name);
    Buffer.add_string out
      (Printf.sprintf "Content-Disposition: attachment; filename=\"%s\"\r\n"
         name);
    Buffer.add_string out "Content-Transfer-Encoding: base64\r\n";
    Buffer.add_string out "\r\n";
    Buffer.add_string out (wrap_base64 (base64_encode bytes))
  ) images;
  Buffer.add_string out (Printf.sprintf "--%s--\r\n" b);
  Buffer.contents out

(* Build the outer RFC 3156 envelope:
     multipart/encrypted; protocol="application/pgp-encrypted"; boundary="Y"
     --Y
     Content-Type: application/pgp-encrypted
     Content-Description: PGP/MIME version identification

     Version: 1
     --Y
     Content-Type: application/octet-stream; name="encrypted.asc"
     Content-Description: OpenPGP encrypted message
     Content-Disposition: inline; filename="encrypted.asc"

     <armored PGP MESSAGE, verbatim>
     --Y--
*)
let build_outer_envelope
    ~visible
    ~armored
    () =
  let b = make_boundary () in
  let out = Buffer.create 4096 in
  List.iter (fun (k, v) -> Buffer.add_string out (header_line k v)) visible;
  Buffer.add_string out "MIME-Version: 1.0\r\n";
  Buffer.add_string out
    (Printf.sprintf
       "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"%s\"\r\n"
       b);
  Buffer.add_string out "\r\n";
  Buffer.add_string out
    "This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156).\r\n";
  Buffer.add_string out (Printf.sprintf "--%s\r\n" b);
  Buffer.add_string out "Content-Type: application/pgp-encrypted\r\n";
  Buffer.add_string out "Content-Description: PGP/MIME version identification\r\n";
  Buffer.add_string out "\r\n";
  Buffer.add_string out "Version: 1\r\n";
  Buffer.add_string out (Printf.sprintf "--%s\r\n" b);
  Buffer.add_string out
    "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n";
  Buffer.add_string out "Content-Description: OpenPGP encrypted message\r\n";
  Buffer.add_string out
    "Content-Disposition: inline; filename=\"encrypted.asc\"\r\n";
  Buffer.add_string out "\r\n";
  Buffer.add_string out armored;
  if String.length armored = 0
     || armored.[String.length armored - 1] <> '\n'
  then Buffer.add_string out "\r\n";
  Buffer.add_string out (Printf.sprintf "--%s--\r\n" b);
  Buffer.contents out

(* ---- Minimal MIME parser for decrypt ---------------------------- *)

(* Split a message into (headers, body).  Looks for CRLF CRLF or LF LF. *)
let split_headers_body raw =
  let n = String.length raw in
  let rec find i =
    if i + 1 >= n then None
    else if i + 3 < n
         && raw.[i] = '\r' && raw.[i+1] = '\n'
         && raw.[i+2] = '\r' && raw.[i+3] = '\n'
    then Some (i, i + 4)
    else if raw.[i] = '\n' && raw.[i+1] = '\n'
    then Some (i, i + 2)
    else find (i + 1)
  in
  match find 0 with
  | None -> (raw, "")
  | Some (hi, bi) ->
    (String.sub raw 0 hi, String.sub raw bi (n - bi))

let parse_headers block =
  (* Supports RFC 5322 line folding: a header line whose continuation
     line starts with SP or HTAB. *)
  let lines = split_on_char '\n' block in
  let lines =
    List.map (fun l ->
      if String.length l > 0 && l.[String.length l - 1] = '\r'
      then String.sub l 0 (String.length l - 1)
      else l
    ) lines
  in
  let rec fold acc cur = function
    | [] ->
      (match cur with None -> List.rev acc | Some c -> List.rev (c :: acc))
    | line :: rest ->
      if String.length line > 0 && (line.[0] = ' ' || line.[0] = '\t') then
        match cur with
        | None -> fold acc (Some line) rest
        | Some c -> fold acc (Some (c ^ " " ^ trim line)) rest
      else begin
        let acc = match cur with None -> acc | Some c -> c :: acc in
        fold acc (Some line) rest
      end
  in
  let flat = fold [] None lines in
  List.filter_map (fun line ->
    match String.index_opt line ':' with
    | None -> None
    | Some i ->
      let k = trim (String.sub line 0 i) in
      let v = trim (String.sub line (i+1) (String.length line - i - 1)) in
      Some (k, v)
  ) flat

(* Extract the Content-Type boundary parameter, if any. *)
let extract_boundary ct =
  (* Look for boundary=VAL where VAL is "..." or a bare token. *)
  let marker = "boundary=" in
  match
    let n = String.length ct and m = String.length marker in
    let rec find i =
      if i + m > n then None
      else if String.sub ct i m = marker then Some (i + m)
      else find (i + 1)
    in find 0
  with
  | None -> None
  | Some start ->
    let n = String.length ct in
    if start < n && ct.[start] = '"' then
      match String.index_from_opt ct (start + 1) '"' with
      | None -> None
      | Some e -> Some (String.sub ct (start + 1) (e - start - 1))
    else
      let rec take i =
        if i >= n then i
        else
          let c = ct.[i] in
          if c = ';' || c = ' ' || c = '\r' || c = '\n' || c = '\t'
          then i else take (i + 1)
      in
      let e = take start in
      Some (String.sub ct start (e - start))

(* Split body at "--<boundary>" lines; return the list of parts
   (between opening and closing boundary, excluding the final
   "--<boundary>--"). *)
let split_multipart body boundary =
  let opening = "--" ^ boundary in
  let closing = "--" ^ boundary ^ "--" in
  let n = String.length body in
  let parts = ref [] in
  let cur_start = ref (-1) in
  let i = ref 0 in
  while !i < n do
    (* Find next line start. *)
    let line_start = !i in
    let line_end =
      match String.index_from_opt body line_start '\n' with
      | Some e -> e
      | None -> n
    in
    let raw_line = String.sub body line_start (line_end - line_start) in
    let line =
      if String.length raw_line > 0
         && raw_line.[String.length raw_line - 1] = '\r'
      then String.sub raw_line 0 (String.length raw_line - 1)
      else raw_line
    in
    if line = closing then begin
      if !cur_start >= 0 then
        parts := (String.sub body !cur_start (line_start - !cur_start)) :: !parts;
      i := n (* stop *)
    end else if line = opening then begin
      if !cur_start >= 0 then
        parts := (String.sub body !cur_start (line_start - !cur_start)) :: !parts;
      cur_start := (if line_end < n then line_end + 1 else n);
      i := !cur_start
    end else
      i := (if line_end < n then line_end + 1 else n)
  done;
  List.rev !parts

(* Strip a trailing CRLF that belongs to the boundary line, not the
   part content. *)
let trim_part_terminator p =
  let n = String.length p in
  if n >= 2 && p.[n-2] = '\r' && p.[n-1] = '\n' then String.sub p 0 (n - 2)
  else if n >= 1 && p.[n-1] = '\n' then String.sub p 0 (n - 1)
  else p

let decode_transfer headers body =
  let cte =
    match lookup "Content-Transfer-Encoding" headers with
    | Some s -> String.lowercase_ascii (trim s)
    | None -> "7bit"
  in
  match cte with
  | "base64" -> base64_decode body
  | "quoted-printable" ->
    (* Minimal QP decoder. *)
    let n = String.length body in
    let buf = Buffer.create n in
    let i = ref 0 in
    while !i < n do
      let c = body.[!i] in
      if c = '=' && !i + 2 < n then begin
        let a = body.[!i + 1] and b = body.[!i + 2] in
        if a = '\r' && b = '\n' then i := !i + 3
        else if a = '\n' then i := !i + 2
        else begin
          let hex = Printf.sprintf "%c%c" a b in
          (try
             Buffer.add_char buf (Char.chr (int_of_string ("0x" ^ hex)));
             i := !i + 3
           with _ -> Buffer.add_char buf c; incr i)
        end
      end else begin
        Buffer.add_char buf c;
        incr i
      end
    done;
    Buffer.contents buf
  | _ -> body

(* Extract filename parameter from Content-Disposition or Content-Type. *)
let extract_filename headers =
  let scan s =
    let marker_list = ["filename="; "name="] in
    List.find_map (fun marker ->
      let m = String.length marker and n = String.length s in
      let rec find i =
        if i + m > n then None
        else if String.sub s i m = marker then Some (i + m)
        else find (i + 1)
      in
      match find 0 with
      | None -> None
      | Some start ->
        if start < n && s.[start] = '"' then
          match String.index_from_opt s (start + 1) '"' with
          | None -> None
          | Some e -> Some (String.sub s (start + 1) (e - start - 1))
        else
          let rec take i =
            if i >= n then i
            else let c = s.[i] in
              if c = ';' || c = ' ' || c = '\t' then i else take (i + 1)
          in
          let e = take start in
          Some (String.sub s start (e - start))
    ) marker_list
  in
  let candidates =
    List.filter_map (fun k -> lookup k headers) ["Content-Disposition"; "Content-Type"]
  in
  List.find_map scan candidates

(* Return the Content-Type major/minor, lowercased. *)
let content_type headers =
  match lookup "Content-Type" headers with
  | None -> "text/plain"
  | Some v ->
    let v =
      match String.index_opt v ';' with
      | None -> v
      | Some i -> String.sub v 0 i
    in
    String.lowercase_ascii (trim v)
