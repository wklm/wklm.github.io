(* Browser-side decryption module — compiled to JavaScript by js_of_ocaml.
   Replaces the PGP/OpenPGP.js pipeline.  Uses the Web Crypto API and
   WebAuthn via the crane_bridge.js JavaScript bridge.

   The page embeds decryption metadata as attributes on the ciphertext
   element and JSON data islands.  The bridge reads these and performs
   the actual HPKE unwrap + AES-GCM decrypt.

   Pure MIME parsing mirrors src/Decrypt.v extraction. *)

open Js_of_ocaml

(* ======== Pure MIME parser (extracted from Decrypt.v) ================= *)

let split_on_char c s =
  let len = String.length s in
  let rec go pos acc fuel =
    if fuel = 0 || pos >= len then
      List.rev (String.sub s pos (len - pos) :: acc)
    else match String.index_from_opt s pos c with
      | None -> List.rev (String.sub s pos (len - pos) :: acc)
      | Some next ->
          let piece = String.sub s pos (next - pos) in
          go (next + 1) (piece :: acc) (fuel - 1)
  in go 0 [] 65536

let starts_with s pref =
  let ls = String.length s and lp = String.length pref in
  lp <= ls && String.sub s 0 lp = pref

let trim s = String.trim s

let trim_trailing_cr s =
  let n = String.length s in
  if n > 0 && s.[n - 1] = '\r' then String.sub s 0 (n - 1) else s

let parse_headers_raw block =
  let lines = split_on_char '\n' (trim_trailing_cr block) in
  let rec fold acc = function
    | [] -> List.rev acc
    | line :: rest ->
        let line' = trim line in
        if line' = "" then fold acc rest
        else if String.length line' > 0 && (line'.[0] = ' ' || line'.[0] = '\t') then
          match acc with
          | (k, v) :: others -> fold ((k, v ^ " " ^ trim line') :: others) rest
          | [] -> fold ((line', "") :: acc) rest
        else
          match String.index_opt line' ':' with
          | None -> fold acc rest
          | Some i ->
              let k = String.lowercase_ascii (trim (String.sub line' 0 i)) in
              let v = trim (String.sub line' (i + 1) (String.length line' - i - 1)) in
              fold ((k, v) :: acc) rest
  in fold [] lines

let hdr_lookup k hdrs =
  try List.assoc (String.lowercase_ascii k) hdrs with Not_found -> ""

let extract_boundary ct =
  let marker = "boundary=" in
  let mlen = String.length marker in
  let n = String.length ct in
  let rec find i =
    if i + mlen > n then None
    else if String.sub ct i mlen = marker then Some (i + mlen)
    else find (i + 1)
  in match find 0 with
  | None -> ""
  | Some start ->
    if start >= n then ""
    else if ct.[start] = '"' then
      match String.index_from_opt ct (start + 1) '"' with
      | None -> ""
      | Some e -> String.sub ct (start + 1) (e - start - 1)
    else
      let rec take i =
        if i >= n then i
        else let c = ct.[i] in
          if c = ';' || c = ' ' || c = '\r' || c = '\n' || c = '\t' then i
          else take (i + 1)
      in String.sub ct start (take start - start)

let split_multipart body boundary =
  let opening = "--" ^ boundary in
  let closing = "--" ^ boundary ^ "--" in
  let n = String.length body in
  let parts = ref [] in
  let cur_start = ref (-1) in
  let i = ref 0 in
  while !i < n do
    let line_start = !i in
    let line_end = match String.index_from_opt body line_start '\n' with
      | Some e -> e | None -> n
    in
    let raw_line = String.sub body line_start (line_end - line_start) in
    let line =
      if String.length raw_line > 0 && raw_line.[String.length raw_line - 1] = '\r'
      then String.sub raw_line 0 (String.length raw_line - 1)
      else raw_line
    in
    if line = closing then begin
      if !cur_start >= 0 then
        parts := String.sub body !cur_start (line_start - !cur_start) :: !parts;
      i := n
    end else if line = opening then begin
      if !cur_start >= 0 then
        parts := String.sub body !cur_start (line_start - !cur_start) :: !parts;
      cur_start := (if line_end < n then line_end + 1 else n);
      i := !cur_start
    end else
      i := (if line_end < n then line_end + 1 else n)
  done;
  List.rev !parts

let trim_part_terminator p =
  let n = String.length p in
  if n >= 2 && p.[n - 2] = '\r' && p.[n - 1] = '\n' then String.sub p 0 (n - 2)
  else if n >= 1 && p.[n - 1] = '\n' then String.sub p 0 (n - 1)
  else p

let split_headers_body raw =
  let n = String.length raw in
  let rec find i =
    if i + 1 >= n then None
    else if i + 3 < n && raw.[i] = '\r' && raw.[i+1] = '\n'
         && raw.[i+2] = '\r' && raw.[i+3] = '\n' then Some (i, i + 4)
    else if raw.[i] = '\n' && i + 1 < n && raw.[i+1] = '\n' then Some (i, i + 2)
    else find (i + 1)
  in match find 0 with
  | None -> (raw, "")
  | Some (hi, bi) -> (String.sub raw 0 hi, String.sub raw bi (n - bi))

(* Extract HPKE metadata from the .eml body:
   - Public-Keys header value (comma-separated key IDs)
   - wrapped_keys part content (keyid:ekhex:wrappedhex per line)
   - ciphertext part content (base64 encoded) *)
let parse_hpke_envelope eml_body =
  let hdrs_block, body = split_headers_body eml_body in
  let hdrs = parse_headers_raw hdrs_block in
  let ct = hdr_lookup "Content-Type" hdrs in
  let boundary = extract_boundary ct in
  if boundary = "" then ("", "", "")
  else
    let parts = split_multipart (trim body) boundary in
    let wraps = ref "" in
    let ct_b64 = ref "" in
    List.iter (fun part ->
      let part = trim_part_terminator part in
      let ph, pb = split_headers_body part in
      let phdrs = parse_headers_raw ph in
      let pct = String.lowercase_ascii (hdr_lookup "Content-Type" phdrs) in
      if starts_with pct "application/wrapped-keys" then begin
        wraps := hdr_lookup "Wraps" phdrs
      end else if starts_with pct "application/aes-gcm" then begin
        let cte = String.lowercase_ascii (hdr_lookup "Content-Transfer-Encoding" phdrs) in
        if cte = "base64" then
          ct_b64 := trim pb
        else
          ct_b64 := pb
      end
    ) parts;
    let pkeys = hdr_lookup "Public-Keys" hdrs in
    (pkeys, !wraps, !ct_b64)

(* ======== Inner MIME extraction (unchanged from original) ============== *)

let b64_chars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

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

let strip_base64_ws s =
  let buf = Buffer.create (String.length s) in
  String.iter (fun c ->
    match c with
    | ' ' | '\n' | '\r' | '\t' -> ()
    | _ -> Buffer.add_char buf c
  ) s;
  Buffer.contents buf

let extract_inner_text inner_mime =
  let hdrs_block, body = split_headers_body inner_mime in
  let hdrs = parse_headers_raw hdrs_block in
  let ct = hdr_lookup "Content-Type" hdrs in
  let boundary = extract_boundary ct in
  if boundary = "" then
    (hdr_lookup "Subject" hdrs, body, [])
  else
    let parts = split_multipart (trim body) boundary in
    let text = ref "" in
    let images = ref [] in
    List.iter (fun part ->
      let part = trim_part_terminator part in
      let ph, pb = split_headers_body part in
      let phdrs = parse_headers_raw ph in
      let pct = String.lowercase_ascii (hdr_lookup "Content-Type" phdrs) in
      if starts_with pct "text/markdown" || starts_with pct "text/plain" then
        text := !text ^ pb
      else if starts_with pct "application/octet-stream"
           || starts_with pct "image/" then begin
        let cte = String.lowercase_ascii (hdr_lookup "Content-Transfer-Encoding" phdrs) in
        let decoded = if cte = "base64" then
          base64_decode (strip_base64_ws pb)
        else pb in
        let filename =
          let scan_marker marker s =
            let mlen = String.length marker in
            let n = String.length s in
            let rec find i =
              if i + mlen > n then None
              else if String.sub s i mlen = marker then Some (i + mlen)
              else find (i + 1)
            in match find 0 with
            | None -> None
            | Some start ->
              if start < n && s.[start] = '"' then
                match String.index_from_opt s (start + 1) '"' with
                | None -> Some (String.sub s start (n - start))
                | Some e -> Some (String.sub s (start + 1) (e - start - 1))
              else
                let rec take i =
                  if i >= n then n
                  else let c = s.[i] in
                    if c = ';' || c = ' ' || c = '\t' || c = '\r' || c = '\n' then i
                    else take (i + 1)
                in Some (String.sub s start (take start - start))
          in
          let try_markers markers s =
            List.find_map (fun m -> scan_marker m s) markers
          in
          let disp = hdr_lookup "Content-Disposition" phdrs in
          match try_markers ["filename="; "name="] disp with Some f -> f | None ->
          match try_markers ["filename="; "name="] pct with Some f -> f | None -> "attachment"
        in
        images := (filename, decoded) :: !images
      end
    ) parts;
    (hdr_lookup "Subject" hdrs, !text, List.rev !images)

(* ======== Typed FFI bridge (zero Js.Unsafe) ============================ *)

external crane_decryptPost
  :  (Js.js_string Js.t -> unit) Js.callback -> unit
  = "crane_decryptPost"

external crane_sessionStorageGet : string -> string
  = "crane_sessionStorageGet"
external crane_sessionStorageSet : string -> string -> unit
  = "crane_sessionStorageSet"
external crane_sessionStorageRemove : string -> unit
  = "crane_sessionStorageRemove"

external crane_decryptBody
  :  string -> string -> (Js.js_string Js.t -> unit) Js.callback -> unit
  = "crane_decryptBody"

(* ======== DOM helpers ================================================== *)

let el_by_id id =
  try Some (Dom_html.getElementById id) with _ -> None

let el_text el =
  match Js.Opt.to_option (el##.textContent) with
  | Some s -> Js.to_string s | None -> ""

let show_el id =
  match el_by_id id with
  | Some el -> el##.style##.display := Js.string "block"
  | None -> ()

let hide_el id =
  match el_by_id id with
  | Some el -> el##.style##.display := Js.string "none"
  | None -> ()

let set_html id html =
  match el_by_id id with
  | Some el -> el##.innerHTML := Js.string html
  | None -> ()

let set_text id text =
  match el_by_id id with
  | Some el -> el##.innerHTML := Js.string text
  | None -> ()

(* ======== Minimal markdown-to-HTML ==================================== *)

(* HTML-escape helpers for inline text *)
let html_escape_line s =
  let buf = Buffer.create (String.length s) in
  String.iter (fun c ->
    match c with
    | '&' -> Buffer.add_string buf "&amp;"
    | '<' -> Buffer.add_string buf "&lt;"
    | '>' -> Buffer.add_string buf "&gt;"
    | '"' -> Buffer.add_string buf "&quot;"
    | _ -> Buffer.add_char buf c
  ) s;
  Buffer.contents buf

let html_escape_char_line s pos =
  match s.[pos] with
  | '&' -> "&amp;"
  | '<' -> "&lt;"
  | '>' -> "&gt;"
  | '"' -> "&quot;"
  | c -> String.make 1 c

(* Strip YAML-style frontmatter: everything between the first "---\n"
   and the next "\n---\n" or "\n---\r\n".  Returns the body after. *)
let strip_frontmatter s =
  if not (starts_with s "---\n" || starts_with s "---\r\n") then s
  else
    let after_open = if starts_with s "---\r\n" then 5 else 4 in
    let n = String.length s in
    let rec find_closing i =
      if i + 4 > n then None
      else if s.[i] = '\n' && i + 4 <= n
           && s.[i+1] = '-' && s.[i+2] = '-' && s.[i+3] = '-' then
        if i + 4 < n && s.[i+4] = '\n' then Some (i + 5)
        else if i + 5 < n && s.[i+4] = '\r' && s.[i+5] = '\n' then Some (i + 6)
        else find_closing (i + 1)
      else find_closing (i + 1)
    in
    match find_closing after_open with
    | None -> s
    | Some body_start -> String.sub s body_start (n - body_start)

(* Convert basic markdown to HTML: **bold**, *italic*, - lists, paragraphs *)
let markdown_to_html body =
  let body = strip_frontmatter body in
  let buf = Buffer.create (String.length body + 1024) in
  let n = String.length body in
  let i = ref 0 in
  let emit s = Buffer.add_string buf s in
  let skip_blanks () =
    while !i < n && (body.[!i] = '\n' || body.[!i] = '\r') do incr i done
  in
  (* scan_inline: returns (html_snippet, new_position) relative to body *)
  let rec scan_inline pos =
    if pos >= n then ("", pos)
    else
      let c = body.[pos] in
      if c = '*' && pos + 1 < n && body.[pos + 1] = '*' then begin
        let j = ref (pos + 2) in
        let found = ref false in
        while !j + 1 < n && not !found do
          if body.[!j] = '*' && body.[!j + 1] = '*' then found := true
          else incr j
        done;
        if !found then
          ("<strong>" ^ html_escape_line (String.sub body (pos + 2) (!j - pos - 2)) ^ "</strong>", !j + 2)
        else
          ("*", pos + 1)
      end else if c = '*' && (pos = 0 || body.[pos - 1] = ' ' || body.[pos - 1] = '\n' || body.[pos - 1] = '\r') then begin
        let j = ref (pos + 1) in
        let found = ref false in
        while !j < n && not !found do
          if body.[!j] = '*' then
            let next = !j + 1 in
            if next >= n || body.[next] = ' ' || body.[next] = '\n' || body.[next] = '\r' then found := true
            else incr j
          else incr j
        done;
        if !found then
          ("<em>" ^ html_escape_line (String.sub body (pos + 1) (!j - pos - 1)) ^ "</em>", !j + 1)
        else
          ("*", pos + 1)
      end else
        (html_escape_char_line body pos, pos + 1)
  in
  skip_blanks ();
  let in_para = ref false in
  let in_list = ref false in
  while !i < n do
    let line_start = !i in
    let line_end = ref line_start in
    while !line_end < n && body.[!line_end] <> '\n' && body.[!line_end] <> '\r' do incr line_end done;
    let line = String.sub body line_start (!line_end - line_start) in
    let line = String.trim line in
    i := !line_end;
    skip_blanks ();
    if line = "" then begin
      if !in_list then (emit "</ul>\n"; in_list := false)
      else if !in_para then (emit "</p>\n"; in_para := false)
    end else if String.length line >= 2 && line.[0] = '-' && line.[1] = ' ' then begin
      if not !in_list then (emit "<ul>\n"; in_list := true);
      emit "<li>";
      let pos = ref 2 in
      while !pos < String.length line do
        let html, next = scan_inline !pos in
        emit html;
        pos := next
      done;
      emit "</li>\n"
    end else begin
      if !in_list then (emit "</ul>\n"; in_list := false);
      if not !in_para then (emit "<p>"; in_para := true);
      let pos = ref 0 in
      while !pos < String.length line do
        let html, next = scan_inline !pos in
        emit html;
        pos := next
      done;
      emit "\n"
    end
  done;
  if !in_list then emit "</ul>\n";
  if !in_para then emit "</p>";
  Buffer.contents buf

(* ======== Post-page logic ============================================== *)

let render_decrypted plaintext =
  let subject, body_text, images = extract_inner_text plaintext in
  hide_el "encrypted-shell";
  hide_el "decrypt-ui";
  show_el "decrypted-content";
  if body_text = "" && images = [] then begin
    set_text "real-title" subject;
    set_text "real-body" "(The decrypted message contained no readable text.)"
  end else begin
    set_text "real-title" subject;
    set_html "real-body" (markdown_to_html body_text);
    if images <> [] then begin
      let img_names = List.map (fun (name, _data) -> name) images in
      set_text "real-images" ("Attachments: " ^ String.concat ", " img_names)
    end
  end

let decrypt_with_bridge () =
  let cb = Js.wrap_callback (fun result ->
    let s = Js.to_string result in
    if s = "" then begin
      crane_sessionStorageRemove "crane_key";
      show_el "decrypt-ui";
      show_el "decrypt-error";
      set_text "decrypt-error"
        ("Decryption failed. Make sure you have a reader key enrolled "
       ^ "and your key is listed as a recipient for this post.")
    end else
      render_decrypted s
  ) in
  crane_decryptPost cb

let init_post_page () =
  match el_by_id "ciphertext" with
  | None -> ()
  | Some _ciphertext_el ->
    let encrypted_key = crane_sessionStorageGet "crane_decrypted" in
    if encrypted_key = "1" then begin
      (* Already decrypted in a previous session visit *)
      show_el "decrypt-ui";
      set_text "decrypt-error" "This post was decrypted in an earlier session.";
      hide_el "decrypt-error"
    end else begin
      show_el "decrypt-ui";
      match el_by_id "decrypt-button" with
      | Some btn ->
          btn##.onclick := Dom.handler (fun _ev ->
            hide_el "decrypt-error";
            set_text "decrypt-status" "Decrypting...";
            decrypt_with_bridge ();
            Js._false
          )
      | None -> ();
      match el_by_id "clear-key-button" with
      | Some clr ->
          clr##.onclick := Dom.handler (fun _ev ->
            crane_sessionStorageRemove "crane_decrypted";
            hide_el "decrypted-content";
            hide_el "clear-key-button";
            show_el "encrypted-shell";
            show_el "decrypt-ui";
            Js._false
          )
      | None -> ()
    end

(* ======== Inbox-page logic ============================================ *)

let init_inbox_page () =
  let saved_key = crane_sessionStorageGet "crane_key" in
  if saved_key <> "" then
    set_html "inbox-status-msg" "All posts are readable with your key."

(* ======== Entry point ================================================== *)

let () =
  match el_by_id "ciphertext" with
  | Some _ -> init_post_page ()
  | None   -> init_inbox_page ()
