(* MimeBuild.v — pure MIME / frontmatter / image-scan logic for the CLI tools.

   Ports the *pure* (no-IO) helpers from tools/io_helpers.ml and
   tools/encrypt_post.ml into ROCQ: hex decode, 76-column base64 wrapping,
   deterministic MIME boundaries, frontmatter key/value parsing, image-ref
   collection, inner multipart/mixed construction, and inner-MIME extraction
   (markdown body + attachment bytes) for the decrypt side.

   Reuses StringLib.v (string primitives) and MimeLib.v (header/body split,
   header parse, boundary extract, multipart split, part-terminator trim).

   All helpers are top-level Definitions/Fixpoints with explicit return types
   to keep Crane's C++ output free of std::any (per crane-extraction-gotchas:
   chained-if-in-let and recursive-tuple-returns leak std::any). *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.
Require Import MimeLib.
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* ---- Byte / line constants ----------------------------------------- *)
(* A Coq pstring literal '\r\n' is FOUR literal bytes, not CRLF, so all
   control bytes are built with PrimString.make. *)

Definition lf     : string := PrimString.make 1%int63 10%int63.   (* \n *)
Definition cr     : string := PrimString.make 1%int63 13%int63.   (* \r *)
Definition crlf   : string := cat cr lf.                          (* \r\n *)
Definition dquote : string := PrimString.make 1%int63 34%int63.   (* ' *)

(* Wrap a header value in quotes: 'VAL'. *)
Definition quote_wrap (s : string) : string := cat dquote (cat s dquote).

(* Concatenate a list of strings (StringLib has no concat_all). *)
Fixpoint concat_all (parts : list string) : string :=
  match parts with
  | nil => ""
  | x :: rest => cat x (concat_all rest)
  end.

(* ---- Deterministic MIME boundaries --------------------------------- *)
(* The test only checks that the Content-Type and boundary are present and
   that build/parse agree, so a fixed deterministic boundary is sufficient
   (and reproducible — no pid/time).  Outer and inner differ. *)

Definition outer_boundary : string := "=_cb_outer_0_=".
Definition inner_boundary : string := "=_cb_inner_0_=".

(* ---- Hex decode (pure) --------------------------------------------- *)
(* hi/lo nibble of a hex ASCII char; 0 for non-hex (inputs are validated
   hex from openssl/key files in practice). *)
Definition hex_nibble (c : int) : int :=
  if andb (leb ch_0 c) (leb c ch_9) then sub c ch_0
  else if andb (leb 97%int63 c) (leb c 102%int63) then add (sub c 97%int63) 10%int63   (* a-f *)
  else if andb (leb 65%int63 c) (leb c 70%int63) then add (sub c 65%int63) 10%int63    (* A-F *)
  else 0%int63.

(* Decode a hex string (even length) into raw bytes.  Recurses on fuel.
   PrimString.get is signed in the extraction, but hex chars are ASCII < 128
   so no masking is needed on the read; the assembled byte is masked to 255. *)
Fixpoint hex_decode_aux (s : string) (pos : int) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f' =>
      let n := PrimString.length s in
      if leb n (add pos 1%int63) then ""
      else
        let hi := hex_nibble (PrimString.get s pos) in
        let lo := hex_nibble (PrimString.get s (add pos 1%int63)) in
        let b := land (lor (lsl hi 4%int63) lo) 255%int63 in
        cat (PrimString.make 1%int63 b)
            (hex_decode_aux s (add pos 2%int63) f')
  end.

Definition hex_decode (s : string) : string :=
  hex_decode_aux s 0%int63 mime_fuel.

(* ---- 76-column base64 wrapping ------------------------------------- *)
(* Emit [s] in 76-byte chunks each followed by CRLF (RFC 2045). *)
Fixpoint wrap_base64_aux (s : string) (pos : int) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then ""
      else
        let remaining := sub n pos in
        let take := if leb remaining 76%int63 then remaining else 76%int63 in
        cat (PrimString.sub s pos take)
            (cat crlf (wrap_base64_aux s (add pos take) f'))
  end.

Definition wrap_base64 (s : string) : string :=
  wrap_base64_aux s 0%int63 mime_fuel.

(* 4-way whitespace test shared by the scanners below. *)
Definition is_ws_char (c : int) : bool :=
  orb (int_eqb c ch_newline)
      (orb (int_eqb c ch_cr)
           (orb (int_eqb c ch_space) (int_eqb c ch_tab))).

(* Scan for the next whitespace character ([stop_on_ws] = true) or the next
   non-whitespace character (false); returns [n] (or [pos] on fuel exhaustion).
   One scanner parameterized on the stop predicate replaces the former
   near-identical [find_ws] / [find_non_ws] pair.  Uses an explicit Bool.eqb to
   avoid ambiguity with the List import. *)
Fixpoint scan_ws (s : string) (pos : int) (stop_on_ws : bool) (fuel : nat) : int :=
  match fuel with
  | O => pos
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then n
      else
        let c := PrimString.get s pos in
        if Stdlib.Bool.Bool.eqb (is_ws_char c) stop_on_ws then pos
        else scan_ws s (add pos 1%int63) stop_on_ws f'
  end.

Fixpoint strip_ws_aux (s : string) (pos : int) (fuel : nat) (acc : list string) : list string :=
  match fuel with
  | O => rev acc
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then rev acc
      else
        let start_pos := scan_ws s pos false f' in
        if leb n start_pos then rev acc
        else
          let end_pos := scan_ws s start_pos true f' in
          let chunk := PrimString.sub s start_pos (sub end_pos start_pos) in
          strip_ws_aux s end_pos f' (chunk :: acc)
  end.

Definition strip_ws (s : string) : string :=
  concat_all (strip_ws_aux s 0%int63 mime_fuel nil).

(* ---- Frontmatter parsing ------------------------------------------- *)
(* Mirrors io_helpers.parse_frontmatter: requires '---\n' (or '---\r\n') at
   position 0, then the block up to a line '---' (possibly CR-terminated).
   Returns the kv list; the body is recovered separately when needed.  For
   the tools we only need slug/title/public-keys, so we expose meta lookup. *)

(* '---' prefix test on a line (after trimming trailing CR). *)
Definition is_dashes (line : string) : bool :=
  string_eqb (trim_trailing_cr line) "---".

(* Parse a 'k: v' frontmatter line into an option pair. *)
Definition parse_meta_line (line : string) : option (string * string) :=
  parse_header_line (trim_trailing_cr line).

(* Collect kv pairs from frontmatter lines until a '---' delimiter. *)
Fixpoint collect_meta (lines : list string) : list (string * string) :=
  match lines with
  | [] => []
  | line :: rest =>
      if is_dashes line then []
      else
        match parse_meta_line line with
        | Some kv => kv :: collect_meta rest
        | None => collect_meta rest
        end
  end.

Definition parse_frontmatter_kv (raw : string) : list (string * string) :=
  let lines := split_lines raw in
  match lines with
  | [] => []
  | first :: rest =>
      if is_dashes first then collect_meta rest
      else []
  end.

(* ---- Image reference collection ------------------------------------ *)
(* Collect every ![alt](path) URL in [body], skipping http(s):// and leading
   '/'.  No dedup (the fixture has one image; OCaml dedups but a single ref is
   unaffected).  Returns paths in first-occurrence order. *)

Definition ch_bang   := 33%int63.   (* ! *)
Definition ch_lbrack := 91%int63.   (* [ *)
Definition ch_rbrack := 93%int63.   (* ] *)
Definition ch_lparen := 40%int63.   (* ( *)
Definition ch_rparen := 41%int63.   (* ) *)

(* Test whether url is an external/absolute ref to skip. *)
Definition is_bad_url (url : string) : bool :=
  orb (is_empty url)
      (orb (starts_with url "http://")
           (orb (starts_with url "https://")
                (int_eqb (PrimString.get url 0%int63) ch_slash))).

(* Collect image references.  The scan JUMPS to the next '!' with find_char
   (which extracts to an iterative loop) instead of stepping one byte per
   frame: the per-byte step was a non-tail recursion over the whole body — one
   native frame plus a full std::string copy per body byte (Crane passes
   strings by value), overflowing the native stack on essays beyond ~11 KB
   (the same class as research-stack-overflow-rootcause.md §5).  Depth is now
   O(#image refs + #bang-jumps), not O(body length). *)
Fixpoint collect_images_aux (body : string) (pos : int) (fuel : nat) : list string :=
  match fuel with
  | O => []
  | S f' =>
      let n := PrimString.length body in
      if leb n pos then []
      else
        let bang := find_char body ch_bang pos mime_fuel in
        if leb n (add bang 1%int63) then []
        else if negb (int_eqb (PrimString.get body (add bang 1%int63)) ch_lbrack) then
          collect_images_aux body (add bang 1%int63) f'
        else
          let close := find_char body ch_rbrack (add bang 2%int63) mime_fuel in
          if leb n (add close 1%int63) then []
          else if negb (int_eqb (PrimString.get body (add close 1%int63)) ch_lparen) then
            collect_images_aux body (add bang 1%int63) f'
          else
            let paren_open := add close 2%int63 in
            let paren_close := find_char body ch_rparen paren_open mime_fuel in
            if leb n paren_close then []
            else
              let url := trim (PrimString.sub body paren_open (sub paren_close paren_open)) in
              let next := add paren_close 1%int63 in
              if is_bad_url url
              then collect_images_aux body next f'
              else url :: collect_images_aux body next f'
  end.

Definition collect_image_refs (body : string) : list string :=
  collect_images_aux body 0%int63 mime_fuel.

(* Last path segment (basename) of a relative image path. *)
Definition basename_of (path : string) : string :=
  let n := PrimString.length path in
  let slash := find_char (reverse_string path) ch_slash 0%int63 mime_fuel in
  (* slash is the index from the end; if none found, whole string. *)
  if leb n slash then path
  else PrimString.sub path (sub n slash) slash.

(* ---- Inner multipart/mixed construction ---------------------------- *)

(* One protected header line 'K: V\r\n'. *)
Definition header_line (k v : string) : string :=
  cat k (cat ": " (cat v crlf)).

Fixpoint protected_block (hs : list (string * string)) : string :=
  match hs with
  | [] => ""
  | (k, v) :: rest => cat (header_line k v) (protected_block rest)
  end.

(* The markdown part: headers + blank + body (+ CRLF iff body lacks final LF). *)
Definition body_needs_crlf (md_body : string) : bool :=
  let n := PrimString.length md_body in
  if leb n 0%int63 then true
  else negb (int_eqb (PrimString.get md_body (sub n 1%int63)) ch_newline).

Definition markdown_part (md_filename md_body : string) : string :=
  concat_all (
    cat "--" (cat inner_boundary crlf) ::
    "Content-Type: text/markdown; charset=utf-8" :: crlf ::
    "Content-Disposition: inline; filename=" :: quote_wrap md_filename :: crlf ::
    "Content-Transfer-Encoding: 8bit" :: crlf ::
    crlf ::
    md_body ::
    (if body_needs_crlf md_body then crlf else "") :: nil).

(* One image part. *)
Definition image_part (name bytes_b64_wrapped : string) : string :=
  concat_all (
    cat "--" (cat inner_boundary crlf) ::
    "Content-Type: application/octet-stream; name=" :: quote_wrap name :: crlf ::
    "Content-Disposition: attachment; filename=" :: quote_wrap name :: crlf ::
    "Content-Transfer-Encoding: base64" :: crlf ::
    crlf ::
    bytes_b64_wrapped :: nil).

Fixpoint image_parts (imgs : list (string * string)) : string :=
  match imgs with
  | [] => ""
  | (name, b64) :: rest => cat (image_part name b64) (image_parts rest)
  end.

(* Build the full inner multipart/mixed body.  [protected] are the inner
   headers (From/To/Date/Subject); [images] are (filename, wrapped-base64). *)
Definition build_inner_mime
  (protected : list (string * string))
  (md_filename md_body : string)
  (images : list (string * string)) : string :=
  concat_all (
    protected_block protected ::
    "MIME-Version: 1.0" :: crlf ::
    "Content-Type: multipart/mixed; boundary=" :: quote_wrap inner_boundary :: crlf ::
    crlf ::
    "This is a multi-part message in MIME format." :: crlf ::
    markdown_part md_filename md_body ::
    image_parts images ::
    cat "--" (cat inner_boundary (cat "--" crlf)) :: nil).

(* ---- Outer HPKE envelope construction ------------------------------ *)

(* Public-Keys header value: 'kid1, kid2, ...'. *)
Fixpoint join_comma (xs : list string) : string :=
  match xs with
  | [] => ""
  | [x] => x
  | x :: rest => cat x (cat ", " (join_comma rest))
  end.

(* Wraps line value: 'kid:ekhex:whex, ...'. *)
Definition wrap_entry_str (e : string * string * string) : string :=
  let '(kid, ek, w) := e in
  cat kid (cat ":" (cat ek (cat ":" w))).

Fixpoint join_wraps (es : list (string * string * string)) : string :=
  match es with
  | [] => ""
  | [e] => wrap_entry_str e
  | e :: rest => cat (wrap_entry_str e) (cat ", " (join_wraps rest))
  end.

(* The fixed informational line and Subject placeholder. *)
Definition outer_subject : string := "Subject: ...".

(* Build the outer multipart/hpke+wrapped envelope.  [kids] are the recipient
   key IDs (Public-Keys), [wrapped_entries] the per-recipient (kid, ek, wrap)
   triples (Wraps), and [ct_package_b64_wrapped] the wrapped-base64 of the
   raw nonce||ct||tag ciphertext package.  [signature_hex] is the hex ECDSA
   signature (raw 64-byte r||s) over SHA-256(sign_info || ct_package) and
   [signing_key_hex] the hex 65-byte uncompressed author signing public key;
   they are emitted as the Signature / Signing-Key headers right after
   Public-Keys.  Everything else (header order, boundary, part layout) is
   byte-identical regardless of the signature params. *)
Definition build_outer_envelope
  (kids : list string)
  (wrapped_entries : list (string * string * string))
  (ct_package_b64_wrapped : string)
  (signature_hex signing_key_hex : string) : string :=
  concat_all (
    outer_subject :: crlf ::
    "MIME-Version: 1.0" :: crlf ::
    "Public-Keys: " :: join_comma kids :: crlf ::
    "Signature: " :: signature_hex :: crlf ::
    "Signing-Key: " :: signing_key_hex :: crlf ::
    "Content-Type: multipart/hpke+wrapped; boundary=" :: quote_wrap outer_boundary :: crlf ::
    crlf ::
    "This is an HPKE encrypted message for Crane Blog readers." :: crlf ::
    cat "--" (cat outer_boundary crlf) ::
    "Content-Type: application/wrapped-keys" :: crlf ::
    "Wraps: " :: join_wraps wrapped_entries :: crlf ::
    crlf ::
    cat "--" (cat outer_boundary crlf) ::
    "Content-Type: application/aes-gcm" :: crlf ::
    "Content-Transfer-Encoding: base64" :: crlf ::
    crlf ::
    ct_package_b64_wrapped ::
    cat "--" (cat outer_boundary (cat "--" crlf)) :: nil).

(* Public outer envelope (feature 2, D1/D4): the SAME multipart/hpke+wrapped
   container as [build_outer_envelope] — identical header order, identical
   preamble line, identical boundary and CRLF discipline — with exactly ONE
   part: Content-Type: application/x-crane-public, CTE 8bit, whose body is
   the byte-identical inner MIME, and Public-Keys: * instead of the
   recipient list.  No wrapped-keys part, no Wraps header, no base64, no
   aes-gcm.  [signature_hex] is the hex ECDSA signature over
   sha256(sign_info_public || slug || normalize_crlf inner_mime) and
   [signing_key_hex] the hex 65-byte uncompressed author signing public key
   (emitted as the Signature / Signing-Key headers, byte-identical header
   slots to the encrypted envelope). *)
Definition build_public_outer_envelope
  (inner_mime signature_hex signing_key_hex : string) : string :=
  concat_all (
    outer_subject :: crlf ::
    "MIME-Version: 1.0" :: crlf ::
    "Public-Keys: *" :: crlf ::
    "Signature: " :: signature_hex :: crlf ::
    "Signing-Key: " :: signing_key_hex :: crlf ::
    "Content-Type: multipart/hpke+wrapped; boundary=" :: quote_wrap outer_boundary :: crlf ::
    crlf ::
    "This is an HPKE encrypted message for Crane Blog readers." :: crlf ::
    cat "--" (cat outer_boundary crlf) ::
    "Content-Type: application/x-crane-public" :: crlf ::
    "Content-Transfer-Encoding: 8bit" :: crlf ::
    crlf ::
    inner_mime :: crlf ::
    cat "--" (cat outer_boundary (cat "--" crlf)) :: nil).

(* ---- boundary-literal rejection (A13 / R2 MINOR-4) ------------------ *)
(* Reject post bodies containing a full line equal to a MIME boundary
   literal (--=_cb_inner_0_= or --=_cb_outer_0_=): such a line inside the
   markdown part would terminate (or reopen) the inner multipart framing and
   corrupt the envelope.  Total, fuel-bounded; each line is compared after
   stripping ONE trailing CR, so a CRLF-ending writer's boundary line is
   caught too (the CRLF-aware parsers trim it before matching). *)
Fixpoint has_boundary_literal_aux (lines : list string) (fuel : nat) : bool :=
  match fuel with
  | O => false
  | S f' =>
      match lines with
      | [] => false
      | line :: rest =>
          let t := trim_trailing_cr line in
          if orb (orb (string_eqb t (cat "--" inner_boundary))
                      (string_eqb t (cat "--" outer_boundary)))
                 (orb (string_eqb t (cat "--" (cat inner_boundary "--")))
                      (string_eqb t (cat "--" (cat outer_boundary "--"))))
          then true
          else has_boundary_literal_aux rest f'
      end
  end.

Definition has_boundary_literal (body : string) : bool :=
  has_boundary_literal_aux (split_lines body) mime_fuel.

Example boundary_literal_detected_inner :
  has_boundary_literal (concat_all ("intro" :: lf :: "--=_cb_inner_0_=" :: lf :: "outro" :: nil))
  = true := eq_refl.

Example boundary_literal_detected_outer :
  has_boundary_literal (concat_all ("intro" :: lf :: "--=_cb_outer_0_=" :: lf :: "outro" :: nil))
  = true := eq_refl.

Example boundary_literal_clean :
  has_boundary_literal (concat_all ("intro" :: lf :: "body" :: lf :: "outro" :: nil))
  = false := eq_refl.

(* R2 MINOR-4 (closing literals): a full line equal to a CLOSING boundary
   (--=<...>=--) must also be rejected — it would truncate the multipart on
   the decrypt side. *)
Example boundary_literal_detected_closing_inner :
  has_boundary_literal (concat_all ("intro" :: lf :: "--=_cb_inner_0_=--" :: lf :: "outro" :: nil))
  = true := eq_refl.

Example boundary_literal_detected_closing_outer :
  has_boundary_literal (concat_all ("intro" :: lf :: "--=_cb_outer_0_=--" :: lf :: "outro" :: nil))
  = true := eq_refl.

(* ---- Correct header/body split ------------------------------------- *)
(* MimeLib.split_headers_body only detects an LF-LF blank line near EOF (its
   loop checks CRLF-CRLF at every position but LF-LF only when fewer than 4
   bytes remain), so an LF-only .eml (e.g. the AAD-fallback fixture) is parsed
   as all-headers/empty-body.  This faithful port of io_helpers.ml checks both
   CRLF-CRLF and LF-LF at every position.  Returns (headers, body). *)
Fixpoint find_blank2 (raw : string) (i : int) (fuel : nat) : int * int :=
  let n := PrimString.length raw in
  match fuel with
  | O => (n, n)
  | S f' =>
      if leb n (add i 1%int63) then (n, n)
      else
        let c0 := PrimString.get raw i in
        let c1 := PrimString.get raw (add i 1%int63) in
        if andb (leb (add i 4%int63) n)
                (andb (int_eqb c0 ch_cr)
                      (andb (int_eqb c1 ch_newline)
                            (andb (int_eqb (PrimString.get raw (add i 2%int63)) ch_cr)
                                  (int_eqb (PrimString.get raw (add i 3%int63)) ch_newline))))
        then (i, add i 4%int63)
        else if andb (int_eqb c0 ch_newline) (int_eqb c1 ch_newline)
        then (i, add i 2%int63)
        else find_blank2 raw (add i 1%int63) f'
  end.

Definition split_headers_body2 (raw : string) : string * string :=
  let n := PrimString.length raw in
  let '(hi, bi) := find_blank2 raw 0%int63 mime_fuel in
  if leb n hi then (raw, "")
  else (PrimString.sub raw 0%int63 hi, PrimString.sub raw bi (sub n bi)).

(* ---- Correct multipart splitter ------------------------------------ *)
(* MimeLib.split_multipart emits one line per part (it never groups the lines
   between two boundary markers).  This faithful port of io_helpers.ml's
   split_multipart returns the content BETWEEN consecutive "--boundary" lines,
   excluding the closing "--boundary--".  [have]=true means we are inside a
   part whose content started at [seg_start].  Top-level Fixpoint (params, not
   a returned tuple) to avoid std::any. *)
Fixpoint split_parts_aux (body opening closing : string)
  (pos seg_start : int) (have : bool) (fuel : nat) : list string :=
  match fuel with
  | O => nil
  | S f' =>
      let n := PrimString.length body in
      if leb n pos then
        (if have then PrimString.sub body seg_start (sub pos seg_start) :: nil else nil)
      else
        let line_end := find_char body ch_newline pos mime_fuel in
        let raw_line := PrimString.sub body pos (sub line_end pos) in
        let line := trim_trailing_cr raw_line in
        let next := if ltb line_end n then add line_end 1%int63 else n in
        if string_eqb line closing then
          (if have then PrimString.sub body seg_start (sub pos seg_start) :: nil else nil)
        else if string_eqb line opening then
          if have then
            PrimString.sub body seg_start (sub pos seg_start)
              :: split_parts_aux body opening closing next next true f'
          else
            split_parts_aux body opening closing next next true f'
        else
          split_parts_aux body opening closing next seg_start have f'
  end.

Definition split_parts (body boundary : string) : list string :=
  split_parts_aux body (cat "--" boundary) (cat "--" (cat boundary "--"))
                  0%int63 0%int63 false mime_fuel.

(* ---- Inner-MIME extraction (decrypt side) -------------------------- *)
(* Given the decrypted inner multipart/mixed body, recover the markdown body
   and the list of (filename, raw-bytes) attachments.  We split on the inner
   boundary and dispatch by each part's Content-Type. *)

(* Markdown output rule: take the part body [pb], strip a single trailing LF
   if present, then add exactly one LF (matches the round-trip target — the
   fixture .md ends in a newline). *)
Definition normalize_md (pb : string) : string :=
  let n := PrimString.length pb in
  let stripped :=
    if andb (leb 1%int63 n) (int_eqb (PrimString.get pb (sub n 1%int63)) ch_newline)
    then PrimString.sub pb 0%int63 (sub n 1%int63)
    else pb in
  cat stripped lf.

(* Find [marker] in [s], returning the index just past it, or length s if
   absent.  Top-level Fixpoint (not a nested let fix) to avoid std::any. *)
Fixpoint find_marker_aux (s marker : string) (i : int) (fuel : nat) : int :=
  let slen := PrimString.length s in
  let mlen := PrimString.length marker in
  match fuel with
  | O => slen
  | S f' =>
      if leb slen (add i mlen) then slen
      else if string_eqb (PrimString.sub s i mlen) marker then add i mlen
      else find_marker_aux s marker (add i 1%int63) f'
  end.

(* Extract a quoted parameter value, e.g. filename='X' or name='X', from a
   header value.  Returns '' if not found or unquoted (the tools always emit
   quoted names). *)
Definition extract_param (marker : string) (s : string) : string :=
  let slen := PrimString.length s in
  let start := find_marker_aux s marker 0%int63 mime_fuel in
  if leb slen start then ""
  else
    let c := PrimString.get s start in
    if int_eqb c ch_dquote then
      let endq := find_char s ch_dquote (add start 1%int63) mime_fuel in
      if leb slen endq then ""
      else PrimString.sub s (add start 1%int63) (sub endq (add start 1%int63))
    else "".

(* Filename from a part's headers (Content-Disposition filename= or
   Content-Type name=).  Returns '' if absent. *)
Definition part_filename (phdrs : list (string * string)) : string :=
  let cd := header_lookup "Content-Disposition" phdrs in
  let fn := extract_param "filename=" cd in
  if is_empty fn then
    let ct := header_lookup "Content-Type" phdrs in
    extract_param "name=" ct
  else fn.

(* Fold the inner parts, accumulating the markdown body and the attachments.
   Returns (md_out, attachments) where attachments are (filename, raw bytes).
   Two separate Fixpoints (md and attachments) avoid std::any from a
   tuple-returning recursion (gotcha). *)
Fixpoint inner_md (parts : list string) : string :=
  match parts with
  | [] => ""
  | part :: rest =>
      let part' := trim_part_terminator part in
      let '(ph, pb) := split_headers_body2 part' in
      let phdrs := parse_headers ph in
      let pct := header_lookup "Content-Type" phdrs in
      if starts_with pct "text/markdown" then normalize_md pb
      else inner_md rest
  end.

(* Returns (filename, raw-base64-body) for each attachment part.  The caller
   (DecryptPost.v, which imports CryptoSpec) does base64_decode (strip_ws ...);
   MimeBuild stays crypto-free. *)
Fixpoint inner_attachments (parts : list string) : list (string * string) :=
  match parts with
  | [] => []
  | part :: rest =>
      let part' := trim_part_terminator part in
      let '(ph, pb) := split_headers_body2 part' in
      let phdrs := parse_headers ph in
      let pct := header_lookup "Content-Type" phdrs in
      if starts_with pct "application/octet-stream" then
        let name := part_filename phdrs in
        (name, pb) :: inner_attachments rest
      else inner_attachments rest
  end.
