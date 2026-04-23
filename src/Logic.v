From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree Monads.IO Monads.Dir.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* [IO] is a [Notation], not a [Definition], so it unfolds at extraction
   time to [itree (dirE +' ioE)].  See the pre-encryption revision for the
   full rationale; keeping it a [Notation] preserves Crane's monad-table
   dispatch. *)
Notation IO := (itree (dirE +' ioE)).

Notation ch_tab := 9%int63.
Notation ch_newline := 10%int63.
Notation ch_cr := 13%int63.
Notation ch_space := 32%int63.
Notation ch_quote := 34%int63.
Notation ch_amp := 38%int63.
Notation ch_apos := 39%int63.
Notation ch_dot := 46%int63.
Notation ch_slash := 47%int63.
Notation ch_colon := 58%int63.
Notation ch_lt := 60%int63.
Notation ch_gt := 62%int63.
Notation ch_0 := 48%int63.
Notation ch_9 := 57%int63.

(* Upper bound on recursion depth for string scanners.  An encrypted post
   is an OpenPGP ASCII-armored MIME message; the body is largely base64
   and is typically a few kilobytes per image.  [fuel] is a scanner
   step count, one char per step. *)
Notation fuel := 2000000.

(* A 1-character primitive string containing LF.  Kept because the page
   shell composes newline-separated header rows. *)
Definition newline_str : string := "
".
Crane Extract Inlined Constant newline_str => "std::string(""\n"")".

(* ---- Low-level string primitives ---------------------------------- *)

Definition int_eqb (a b : int) : bool := eqb a b.

Definition is_empty (s : string) : bool :=
  leb (PrimString.length s) 0%int63.

Definition html_escape_char (s : string) (pos : int) : string :=
  let ch := PrimString.get s pos in
  if int_eqb ch ch_amp then "&amp;"
  else if int_eqb ch ch_lt then "&lt;"
  else if int_eqb ch ch_gt then "&gt;"
  else if int_eqb ch ch_quote then "&quot;"
  else if int_eqb ch ch_apos then "&#39;"
  else PrimString.sub s pos 1%int63.

Fixpoint html_escape_aux (s : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => ""
  | S remaining' =>
      if leb (PrimString.length s) pos then ""
      else cat (html_escape_char s pos) (html_escape_aux s (add pos 1%int63) remaining')
  end.

Definition html_escape (s : string) : string :=
  html_escape_aux s 0%int63 fuel.

Fixpoint concat_all (parts : list string) : string :=
  match parts with
  | nil => ""
  | x :: rest => cat x (concat_all rest)
  end.

Fixpoint nat_of_int_fuel (i : int) (remaining : nat) : nat :=
  match remaining with
  | O => O
  | S remaining' =>
      if leb i 0%int63 then O
      else S (nat_of_int_fuel (sub i 1%int63) remaining')
  end.

Definition nat_of_len (s : string) : nat :=
  nat_of_int_fuel (PrimString.length s) fuel.

Fixpoint starts_with_aux (s pref : string) (pos : int) (remaining : nat) : bool :=
  match remaining with
  | O => true
  | S remaining' =>
      if leb (PrimString.length pref) pos then true
      else if leb (PrimString.length s) pos then false
      else if int_eqb (PrimString.get s pos) (PrimString.get pref pos)
           then starts_with_aux s pref (add pos 1%int63) remaining'
           else false
  end.

Definition starts_with (s pref : string) : bool :=
  starts_with_aux s pref 0%int63 (nat_of_len pref).

Fixpoint find_char (s : string) (ch : int) (pos : int) (remaining : nat) : int :=
  match remaining with
  | O => PrimString.length s
  | S remaining' =>
      if leb (PrimString.length s) pos then PrimString.length s
      else if int_eqb (PrimString.get s pos) ch then pos
      else find_char s ch (add pos 1%int63) remaining'
  end.

Fixpoint string_eqb_aux (a b : string) (pos : int) (remaining : nat) : bool :=
  match remaining with
  | O => true
  | S remaining' =>
      if leb (PrimString.length a) pos then true
      else if int_eqb (PrimString.get a pos) (PrimString.get b pos)
           then string_eqb_aux a b (add pos 1%int63) remaining'
           else false
  end.

Definition string_eqb (a b : string) : bool :=
  if int_eqb (PrimString.length a) (PrimString.length b)
  then string_eqb_aux a b 0%int63 (nat_of_len a)
  else false.

Fixpoint string_ge_aux (a b : string) (pos : int) (remaining : nat) : bool :=
  match remaining with
  | O => true
  | S remaining' =>
      let la := PrimString.length a in
      let lb := PrimString.length b in
      if andb (leb la pos) (leb lb pos) then true
      else if leb la pos then false
      else if leb lb pos then true
      else
        let ca := PrimString.get a pos in
        let cb := PrimString.get b pos in
        if int_eqb ca cb then string_ge_aux a b (add pos 1%int63) remaining'
        else leb cb ca
  end.

Definition string_ge (a b : string) : bool :=
  string_ge_aux a b 0%int63 fuel.

Definition substring_from (s : string) (start : int) : string :=
  PrimString.sub s start (sub (PrimString.length s) start).

Fixpoint reverse_string_acc (s acc : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => acc
  | S remaining' =>
      if leb (PrimString.length s) pos then acc
      else
        let ch := PrimString.sub s pos 1%int63 in
        reverse_string_acc s (cat ch acc) (add pos 1%int63) remaining'
  end.

Definition reverse_string (s : string) : string :=
  reverse_string_acc s "" 0%int63 fuel.

Fixpoint trim_left_from (s : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => substring_from s pos
  | S remaining' =>
      if leb (PrimString.length s) pos then ""
      else
        let ch := PrimString.get s pos in
        if orb (int_eqb ch ch_space)
           (orb (int_eqb ch ch_tab)
           (orb (int_eqb ch ch_newline)
                (int_eqb ch ch_cr)))
        then trim_left_from s (add pos 1%int63) remaining'
        else substring_from s pos
  end.

Definition trim_left (s : string) : string :=
  trim_left_from s 0%int63 fuel.

Definition trim_right (s : string) : string :=
  reverse_string (trim_left (reverse_string s)).

Definition trim (s : string) : string :=
  trim_right (trim_left s).

Definition has_suffix (s suffix : string) : bool :=
  let len_s := PrimString.length s in
  let len_suffix := PrimString.length suffix in
  if ltb len_s len_suffix then false
  else string_eqb (PrimString.sub s (sub len_s len_suffix) len_suffix) suffix.

Fixpoint last_segment_aux (s : string) (pos last : int) (remaining : nat) : string :=
  match remaining with
  | O => substring_from s last
  | S remaining' =>
      if leb (PrimString.length s) pos then substring_from s last
      else if int_eqb (PrimString.get s pos) ch_slash
           then last_segment_aux s (add pos 1%int63) (add pos 1%int63) remaining'
           else last_segment_aux s (add pos 1%int63) last remaining'
  end.

Definition last_segment (s : string) : string :=
  last_segment_aux s 0%int63 0%int63 fuel.

(* Strip a trailing [".eml"] from the last path segment; whatever remains is
   used verbatim as the URL slug. *)
Definition file_stem_eml (path : string) : string :=
  let name := last_segment path in
  let len_name := PrimString.length name in
  if has_suffix name ".eml"
  then PrimString.sub name 0%int63 (sub len_name 4%int63)
  else name.

(* ---- Output-path helpers ----------------------------------------- *)

Definition rel_stylesheet (depth : string) : string :=
  cat depth "styles/site.css".

Definition rel_index (depth : string) : string :=
  cat depth "index.html".

Definition file_output_path (output_dir slug : string) : string :=
  cat output_dir (cat "/" (cat slug "/index.html")).

Definition styles_output_path (output_dir : string) : string :=
  cat output_dir "/styles/site.css".

Definition index_output_path (output_dir : string) : string :=
  cat output_dir "/index.html".

Definition dirname_output_path (output_dir slug : string) : string :=
  cat output_dir (cat "/" slug).

(* ---- Encrypted post model ---------------------------------------- *)

(* An [EncryptedPost] is the opaque view the generator has of a
   [posts-encrypted/<slug>.eml] file.  The file itself is a
   fully-formed RFC 3156 PGP/MIME message produced by the pre-commit
   hook; the generator only needs the four headers that populate the
   fake mail-client chrome, plus the raw body (everything after the
   first blank line) to print verbatim inside a [<pre>].

   [ep_body] is deliberately untouched: MIME boundaries, the
   [application/pgp-encrypted] part, the armored
   [-----BEGIN PGP MESSAGE-----] block, and the armor's CRC-24 trailer
   all appear as they were written by [gpg].  The generator never
   parses MIME semantics and never touches OpenPGP bytes. *)
Record EncryptedPost : Type := mkEncryptedPost {
  ep_slug : string;
  ep_from : string;
  ep_to : string;
  ep_date : string;
  ep_subject : string;
  ep_body : string
}.

Definition empty_ep : EncryptedPost :=
  mkEncryptedPost "" "" "" "" "" "".

(* ---- .eml header parsing ----------------------------------------- *)

(* Split a raw [.eml] byte string at the first blank line.  Returns the
   header block (without the blank line) and the body (everything after
   the blank line).  [\r] is tolerated: a line consisting solely of
   [\r] counts as blank.  The hook emits LF-only output, so this is
   defensive. *)
Definition is_blank_line (line : string) : bool :=
  let t := trim line in
  is_empty t.

Fixpoint split_headers_body (s : string) (pos : int) (remaining : nat) : string * string :=
  match remaining with
  | O => (s, "")
  | S remaining' =>
      let len := PrimString.length s in
      if leb len pos then (s, "")
      else
        let eol := find_char s ch_newline pos fuel in
        let line := PrimString.sub s pos (sub eol pos) in
        if is_blank_line line
        then
          let header := PrimString.sub s 0%int63 pos in
          let body_start := if ltb eol len then add eol 1%int63 else len in
          let body := PrimString.sub s body_start (sub (PrimString.length s) body_start) in
          (header, body)
        else
          let next := if ltb eol len then add eol 1%int63 else len in
          split_headers_body s next remaining'
  end.

(* [Header] lines are [Key: Value]; the header block is already free of
   RFC 5322 line folding because the hook emits each header on a single
   line.  A line that does not contain [':'] is ignored. *)
Definition parse_header_line (line : string) : string * string :=
  let len := PrimString.length line in
  let colon := find_char line ch_colon 0%int63 fuel in
  if leb len colon then ("", "")
  else
    let key := PrimString.sub line 0%int63 colon in
    let value_start := add colon 1%int63 in
    let value :=
      if leb len value_start then ""
      else PrimString.sub line value_start (sub len value_start) in
    (trim key, trim value).

Fixpoint lookup_header_aux (s : string) (needle : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => ""
  | S remaining' =>
      let len := PrimString.length s in
      if leb len pos then ""
      else
        let eol := find_char s ch_newline pos fuel in
        let line := PrimString.sub s pos (sub eol pos) in
        let '(key, value) := parse_header_line line in
        if string_eqb key needle
        then value
        else
          let next := if ltb eol len then add eol 1%int63 else len in
          lookup_header_aux s needle next remaining'
  end.

Definition lookup_header (headers needle : string) : string :=
  lookup_header_aux headers needle 0%int63 fuel.

Definition parse_eml (slug raw : string) : EncryptedPost :=
  let '(headers, body) := split_headers_body raw 0%int63 fuel in
  mkEncryptedPost
    slug
    (lookup_header headers "From")
    (lookup_header headers "To")
    (lookup_header headers "Date")
    (lookup_header headers "Subject")
    body.

(* ---- Rendering --------------------------------------------------- *)

Definition page_shell (depth page_title body_class nav_label nav_href body_content : string) : string :=
  concat_all (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><meta name='color-scheme' content='light dark'>" ::
    "<title>" :: html_escape page_title ::
    (if string_eqb page_title "wklm.github.io" then "" else " — wklm.github.io") ::
    "</title>" ::
    "<link rel='stylesheet' href='" :: html_escape (rel_stylesheet depth) :: "'>" ::
    "</head><body class='" :: body_class :: "'>" ::
    "<a class='skip-link' href='#main'>skip to text</a>" ::
    "<div class='page-shell'>" ::
    "<header class='site-header'><a class='site-mark' href='" :: html_escape (rel_index depth) :: "'>wklm.github.io</a>" ::
    (if is_empty nav_label then ""
     else concat_all ("<nav class='site-nav'><a href='" :: html_escape nav_href :: "'>" :: html_escape nav_label :: "</a></nav>" :: nil)) ::
    "</header>" ::
    body_content ::
    "</div></body></html>" :: nil).

Definition header_row (label value : string) : string :=
  concat_all (
    "<div class='eml-header'><dt>" :: html_escape label :: "</dt>" ::
    "<dd>" :: html_escape value :: "</dd></div>" :: nil).

(* The four visible headers are [From], [To], [Date], and [Subject].
   [MIME-Version] and [Content-Type] are rendered as literal strings
   so the reader sees the same envelope a mail client would show for
   any RFC 3156 message. *)
Definition render_eml_page (ep : EncryptedPost) : string :=
  let title := cat "Subject: " ep.(ep_subject) in
  let body :=
    concat_all (
      "<main id='main' class='eml'>" ::
      "<dl class='eml-headers'>" ::
      header_row "From" ep.(ep_from) ::
      header_row "To" ep.(ep_to) ::
      header_row "Date" ep.(ep_date) ::
      header_row "Subject" ep.(ep_subject) ::
      header_row "MIME-Version" "1.0" ::
      header_row "Content-Type" "multipart/encrypted; protocol=application/pgp-encrypted" ::
      "</dl>" ::
      "<hr class='eml-rule'>" ::
      "<pre class='eml-body'>" :: html_escape ep.(ep_body) :: "</pre>" ::
      "</main>" :: nil) in
  page_shell "../" title "eml" "index" "../index.html" body.

Definition inbox_row (ep : EncryptedPost) : string :=
  concat_all (
    "<li class='inbox-row'>" ::
    "<span class='inbox-from'>" :: html_escape ep.(ep_from) :: "</span>" ::
    "<time class='inbox-date' datetime='" :: html_escape ep.(ep_date) :: "'>" :: html_escape ep.(ep_date) :: "</time>" ::
    "<a class='inbox-subject' href='" :: html_escape (cat ep.(ep_slug) "/index.html") :: "'>" ::
    "Subject: " :: html_escape ep.(ep_subject) ::
    "</a>" ::
    "</li>" :: nil).

Fixpoint render_inbox_rows (eps : list EncryptedPost) : list string :=
  match eps with
  | nil => nil
  | ep :: rest => inbox_row ep :: render_inbox_rows rest
  end.

Definition render_inbox_page (eps : list EncryptedPost) : string :=
  let body :=
    concat_all (
      "<main id='main' class='inbox'>" ::
      "<ol class='inbox-list'>" ::
      concat_all (render_inbox_rows eps) ::
      "</ol>" :: "</main>" :: nil) in
  page_shell "" "wklm.github.io" "inbox" "" "" body.

(* ---- Stylesheet --------------------------------------------------
   The visual target is a plain, lightly-styled email client.  A single
   warm off-white background, near-black ink, a muted rule colour.
   Headers and body are monospaced to sell the "raw .eml" register.
   The inbox keeps the same monospace family for the same reason. *)
Definition stylesheet : string :=
  concat_all (
    ":root{--paper:#f4f0e8;--ink:#171717;--muted:#5c554c;--rule:#d9d2c2;--accent:#b08d57}" ::
    "@media (prefers-color-scheme: dark){:root{--paper:#141414;--ink:#e8e8e8;--muted:#9a9a9a;--rule:#2e2e2e;--accent:#b08d57}}" ::
    "*,*::before,*::after{box-sizing:border-box}" ::
    "html{-webkit-text-size-adjust:100%}" ::
    "body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 ui-monospace,'SF Mono',Menlo,Consolas,'DejaVu Sans Mono',monospace;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased}" ::
    "a{color:inherit;text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:.18em}" ::
    "a:hover{text-decoration-thickness:2px}" ::
    "a:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}" ::
    ".skip-link{position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden}" ::
    ".skip-link:focus{position:static;width:auto;height:auto;padding:.25rem .5rem;background:var(--ink);color:var(--paper)}" ::
    ".page-shell{max-width:54rem;margin:0 auto;padding:2rem 1.25rem 4rem}" ::
    ".site-header{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;margin-bottom:2.5rem;font-size:.9rem;border-top:2px solid var(--ink);padding-top:.75rem}" ::
    ".site-mark{text-decoration:none;font-weight:600;letter-spacing:.02em}" ::
    ".site-nav a{color:var(--muted);text-decoration:none}" ::
    ".site-nav a:hover{color:var(--ink);text-decoration:underline}" ::
    ".eml-headers{margin:0 0 1rem;padding:0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule)}" ::
    ".eml-header{display:grid;grid-template-columns:9rem 1fr;gap:1rem;padding:.25rem 0;border-bottom:1px dotted var(--rule)}" ::
    ".eml-header:last-child{border-bottom:0}" ::
    ".eml-header dt{margin:0;color:var(--muted);font-weight:600}" ::
    ".eml-header dd{margin:0;word-break:break-word}" ::
    ".eml-rule{border:0;border-top:1px solid var(--rule);margin:1rem 0}" ::
    ".eml-body{margin:0;padding:1rem;background:transparent;color:var(--ink);white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere;font-size:.85rem;line-height:1.45}" ::
    ".inbox-list{list-style:none;padding:0;margin:0;border-top:1px solid var(--rule)}" ::
    ".inbox-row{display:grid;grid-template-columns:14rem 10rem 1fr;gap:1rem;padding:.5rem 0;border-bottom:1px dotted var(--rule);align-items:baseline}" ::
    ".inbox-from{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}" ::
    ".inbox-date{color:var(--muted);font-variant-numeric:tabular-nums}" ::
    ".inbox-subject{text-decoration:none}" ::
    ".inbox-subject:hover{text-decoration:underline}" ::
    "@media (max-width:40rem){.page-shell{padding:1.25rem 1rem 3rem}.site-header{margin-bottom:1.5rem}.eml-header{grid-template-columns:6rem 1fr;gap:.5rem}.inbox-row{grid-template-columns:1fr;gap:.1em;padding:.6rem 0}.inbox-from,.inbox-date{font-size:.8rem}}" ::
    "@media print{.site-nav{display:none}body{background:#fff;color:#000}a{text-decoration:none;color:#000}}" :: nil).

(* ---- IO pipeline ------------------------------------------------- *)

Fixpoint read_eml_list (paths : list string) : IO (list EncryptedPost) :=
  match paths with
  | nil => Ret nil
  | path :: rest =>
      raw <- read path ;;
      parsed_rest <- read_eml_list rest ;;
      Ret (parse_eml (file_stem_eml path) raw :: parsed_rest)
  end.

(* Descending sort by [ep_date].  The hook writes an RFC 5322 date, which
   is not lexicographic; we therefore sort by the value in the header,
   accepting that the order is *date-header* order.  When the hook emits
   ISO-8601-ish dates (as it does here, via Python's
   [email.utils.format_datetime]) lex order does not match calendar order
   for dates before 1970 or after 9999, which is outside this repo's
   scope.  For conventional RFC 5322 dates we fall back to insertion
   order as a tie-breaker. *)
Fixpoint insert_ep (ep : EncryptedPost) (eps : list EncryptedPost) : list EncryptedPost :=
  match eps with
  | nil => ep :: nil
  | q :: rest =>
      if string_ge ep.(ep_date) q.(ep_date)
      then ep :: q :: rest
      else q :: insert_ep ep rest
  end.

Fixpoint sort_eps (eps : list EncryptedPost) : list EncryptedPost :=
  match eps with
  | nil => nil
  | ep :: rest => insert_ep ep (sort_eps rest)
  end.

Fixpoint write_eml_pages (output_dir : string) (eps : list EncryptedPost) : IO unit :=
  match eps with
  | nil => Ret tt
  | ep :: rest =>
      _ <- create_directory (dirname_output_path output_dir ep.(ep_slug)) ;;
      _ <- write_file (file_output_path output_dir ep.(ep_slug)) (render_eml_page ep) ;;
      write_eml_pages output_dir rest
  end.

(* [run] is the extracted entry point.  It reads the ciphertext tree
   from [./posts-encrypted/], emits one page per [.eml] under
   [_site/<slug>/], plus the inbox index and stylesheet.  No plaintext
   attachments are copied anywhere; every byte of the original post
   lives inside the armored body. *)
Definition run : IO unit :=
  files <- list_directory "./posts-encrypted" ;;
  let eml_paths := map (fun name => cat "./posts-encrypted/" name)
                       (filter (fun name => has_suffix name ".eml") files) in
  parsed <- read_eml_list eml_paths ;;
  let eps := sort_eps parsed in
  _ <- create_directory "./_site" ;;
  _ <- create_directory "./_site/styles" ;;
  _ <- write_file (styles_output_path "./_site") stylesheet ;;
  _ <- write_file (index_output_path "./_site") (render_inbox_page eps) ;;
  write_eml_pages "./_site" eps.

Set Warnings "-crane-extraction-default-directory".

(* Linear-time [concat_all] override — same rationale as the pre-encryption
   revision.  The Coq definition is kept for proof-level reasoning; only
   the C++ call site is redirected to the helper in [blog_helpers.h]. *)
Crane Extract Inlined Constant concat_all => "concat_all_std(%a0)" From "blog_helpers.h".

Crane Extraction "blog" run.
