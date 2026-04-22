From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree Monads.IO Monads.Dir.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* [IO] is a [Notation], not a [Definition], so it unfolds at extraction
   time to [itree (dirE +' ioE)].  Crane's monad table registers [itree]
   (see [Crane.Monads.ITree]); if we kept [IO] as a [Definition] it would
   surface in ML as an opaque [Tglob] reference that is *not* in the
   monad table, and Crane would incorrectly mark IO-returning C++
   functions with [__attribute__((pure))]. *)
Notation IO := (itree (dirE +' ioE)).

Notation ch_newline := 10%int63.
Notation ch_space := 32%int63.
Notation ch_quote := 34%int63.
Notation ch_amp := 38%int63.
Notation ch_apos := 39%int63.
Notation ch_lparen := 40%int63.
Notation ch_rparen := 41%int63.
Notation ch_star := 42%int63.
Notation ch_dot := 46%int63.
Notation ch_slash := 47%int63.
Notation ch_colon := 58%int63.
Notation ch_lt := 60%int63.
Notation ch_gt := 62%int63.
Notation ch_lbracket := 91%int63.
Notation ch_rbracket := 93%int63.
Notation ch_backtick := 96%int63.

(* Upper bound on recursion depth for string scanners and other fuel-indexed
   fixpoints.  All scanners consume at least one character per step, so any
   input shorter than [fuel] chars is scanned in full.  Bumped from 4000 to
   cover realistic post bodies; any post exceeding this would otherwise be
   silently truncated. *)
Notation fuel := 200000.

(* A 1-character primitive string containing LF.
   Extracted as a C++ expression using an escape to avoid an embedded raw
   newline in the generated .h file. *)
Definition newline_str : string := "
".
Crane Extract Inlined Constant newline_str => "std::string(""\n"")".

Inductive Inline :=
  | Text (s : string)
  | Link (label url : string)
  | CodeSpan (s : string)
  | Emphasis (parts : list Inline)
  | Strong (parts : list Inline).

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

Definition post_asset_href (candidate : string) : string :=
  if is_empty candidate then "" else cat "../posts/" candidate.

Fixpoint concat_all (parts : list string) : string :=
  match parts with
  | nil => ""
  | x :: rest => cat x (concat_all rest)
  end.

Fixpoint join_with (sep : string) (parts : list string) : string :=
  match parts with
  | nil => ""
  | x :: nil => x
  | x :: rest => cat x (cat sep (join_with sep rest))
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

(* Whitelist-based URL sanitizer.  Rejects [javascript:], [data:], and other
   script-carrying schemes by mapping anything outside the allowed set to
   ["#"], which is safe to resolve and visible to the author.  Relative paths,
   fragments, http(s), and mailto are preserved. *)
Definition safe_url (url : string) : string :=
  if orb (starts_with url "http://")
    (orb (starts_with url "https://")
    (orb (starts_with url "mailto:")
    (orb (starts_with url "/")
    (orb (starts_with url "#")
    (orb (starts_with url "./")
         (starts_with url "../"))))))
  then url
  else "#".

(* Fuel-based recursion: [fuel] bounds the nesting depth of emphasis/strong
   wrappers.  Real input sources cannot nest markdown inline decoration to a
   depth exceeding the very large [fuel] default. *)
Fixpoint render_inline_list_aux (fuel : nat) (parts : list Inline) : string :=
  match fuel with
  | O => ""
  | S fuel' =>
      match parts with
      | nil => ""
      | Text s :: rest =>
          cat (html_escape s) (render_inline_list_aux fuel' rest)
      | CodeSpan s :: rest =>
          cat (cat "<code>" (cat (html_escape s) "</code>"))
              (render_inline_list_aux fuel' rest)
      | Link label url :: rest =>
          cat (cat "<a href='" (cat (html_escape (safe_url url))
                (cat "'>" (cat (html_escape label) "</a>"))))
              (render_inline_list_aux fuel' rest)
      | Emphasis inner :: rest =>
          cat (cat "<em>" (cat (render_inline_list_aux fuel' inner) "</em>"))
              (render_inline_list_aux fuel' rest)
      | Strong inner :: rest =>
          cat (cat "<strong>" (cat (render_inline_list_aux fuel' inner) "</strong>"))
              (render_inline_list_aux fuel' rest)
      end
  end.

Definition render_inline_list (parts : list Inline) : string :=
  render_inline_list_aux fuel parts.

Inductive Block :=
  | Heading2 (s : string)
  | Heading3 (s : string)
  | Paragraph (parts : list Inline)
  | CodeBlock (lang : string) (code_lines : list string)
  | ImageBlock (alt src : string).

Record Meta : Type := mkMeta {
  meta_title : string;
  meta_date : string;
  meta_slug : string;
  meta_summary : string;
  meta_topic : string;
  meta_lead_image : string;
  meta_lead_image_alt : string;
  meta_draft : bool
}.

Record Post : Type := mkPost {
  post_meta : Meta;
  post_body : list Block
}.

Definition empty_meta : Meta :=
  mkMeta "" "" "" "" "" "" "" false.

Fixpoint find_char (s : string) (ch : int) (pos : int) (remaining : nat) : int :=
  match remaining with
  | O => PrimString.length s
  | S remaining' =>
      if leb (PrimString.length s) pos then PrimString.length s
      else if int_eqb (PrimString.get s pos) ch then pos
      else find_char s ch (add pos 1%int63) remaining'
  end.

Definition get_line_at (s : string) (start : int) : string * int :=
  let eol := find_char s ch_newline start fuel in
  let line := PrimString.sub s start (sub eol start) in
  (line, add eol 1%int63).

Fixpoint split_lines (s : string) (start : int) (remaining : nat) : list string :=
  match remaining with
  | O => nil
  | S remaining' =>
      if leb (PrimString.length s) start then nil
      else
        let '(line, next) := get_line_at s start in
        line :: split_lines s next remaining'
  end.

Definition to_lines (s : string) : list string :=
  split_lines s 0%int63 fuel.

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
      if leb (PrimString.length a) pos then true
      else
        let ch_a := PrimString.get a pos in
        let ch_b := PrimString.get b pos in
        if int_eqb ch_a ch_b
        then string_ge_aux a b (add pos 1%int63) remaining'
        else negb (leb ch_a ch_b)
  end.

Definition string_ge (a b : string) : bool :=
  let len_a := PrimString.length a in
  let len_b := PrimString.length b in
  if leb len_a len_b
  then if int_eqb len_a len_b
       then string_ge_aux a b 0%int63 (nat_of_len a)
       else false
  else if starts_with a b
       then true
       else string_ge_aux a b 0%int63 (nat_of_len b).

Definition substring_from (s : string) (start : int) : string :=
  PrimString.sub s start (sub (PrimString.length s) start).

Fixpoint reverse_string_acc (s acc : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => acc
  | S remaining' =>
      if leb pos 0%int63 then acc
      else
        let next := sub pos 1%int63 in
        reverse_string_acc s (cat acc (PrimString.sub s next 1%int63)) next remaining'
  end.

Definition reverse_string (s : string) : string :=
  reverse_string_acc s "" (PrimString.length s) fuel.

Fixpoint trim_left_from (s : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => s
  | S remaining' =>
      if leb (PrimString.length s) pos then ""
      else if int_eqb (PrimString.get s pos) ch_space
           then trim_left_from s (add pos 1%int63) remaining'
           else substring_from s pos
  end.

Definition trim_left (s : string) : string :=
  trim_left_from s 0%int63 fuel.

Definition trim_right (s : string) : string :=
  reverse_string (trim_left (reverse_string s)).

Definition trim (s : string) : string :=
  trim_right (trim_left s).

Definition drop_prefix (s : string) (n : int) : string :=
  substring_from s n.

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

Definition file_stem (path : string) : string :=
  let name := last_segment path in
  let len_name := PrimString.length name in
  if has_suffix name ".md"
  then PrimString.sub name 0%int63 (sub len_name 3%int63)
  else name.

Definition slugify_char (s : string) (pos : int) : string :=
  let ch := PrimString.get s pos in
  if int_eqb ch ch_space then "-"
  else if int_eqb ch ch_slash then "-"
  else if int_eqb ch ch_dot then "-"
  else PrimString.sub s pos 1%int63.

Fixpoint slugify_aux (s : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => ""
  | S remaining' =>
      if leb (PrimString.length s) pos then ""
      else cat (slugify_char s pos) (slugify_aux s (add pos 1%int63) remaining')
  end.

Definition slugify (candidate fallback : string) : string :=
  let base := trim candidate in
  if is_empty base then fallback else slugify_aux base 0%int63 fuel.

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

Definition classify_ticks (line : string) : option string :=
  if starts_with line "```" then Some (trim (drop_prefix line 3%int63)) else None.

Definition parse_image_line (line : string) : option (string * string) :=
  if negb (starts_with line "![") then None
  else
    let alt_end := find_char line ch_rbracket 2%int63 fuel in
    let url_start := add alt_end 2%int63 in
    let url_end := find_char line ch_rparen url_start fuel in
    if leb (PrimString.length line) alt_end then None
    else if leb (PrimString.length line) url_end then None
    else if negb (int_eqb (PrimString.get line (add alt_end 1%int63)) ch_lparen) then None
         else Some (
           PrimString.sub line 2%int63 (sub alt_end 2%int63),
           PrimString.sub line url_start (sub url_end url_start)
         ).

(* Return the position of the next [**] at or after [pos], or [length s]
   if there is none within [remaining] steps. *)
Fixpoint find_double_star (s : string) (pos : int) (remaining : nat) : int :=
  match remaining with
  | O => PrimString.length s
  | S remaining' =>
      let len := PrimString.length s in
      if leb len (add pos 1%int63) then len
      else if andb (int_eqb (PrimString.get s pos) ch_star)
                   (int_eqb (PrimString.get s (add pos 1%int63)) ch_star)
           then pos
           else find_double_star s (add pos 1%int63) remaining'
  end.

(* Return the position of the next lone [*] at or after [pos] that is not
   part of a [**] pair, or [length s] if none. *)
Fixpoint find_single_star (s : string) (pos : int) (remaining : nat) : int :=
  match remaining with
  | O => PrimString.length s
  | S remaining' =>
      let len := PrimString.length s in
      if leb len pos then len
      else if int_eqb (PrimString.get s pos) ch_star then
        let next := add pos 1%int63 in
        if leb len next then pos
        else if int_eqb (PrimString.get s next) ch_star
             then find_single_star s (add pos 2%int63) remaining'
             else pos
      else find_single_star s (add pos 1%int63) remaining'
  end.

Fixpoint parse_inlines_aux (s : string) (pos : int) (remaining : nat) : list Inline :=
  match remaining with
  | O => nil
  | S remaining' =>
      if leb (PrimString.length s) pos then nil
      else
        let ch := PrimString.get s pos in
        if int_eqb ch ch_backtick then
          let end_pos := find_char s ch_backtick (add pos 1%int63) fuel in
          if leb (PrimString.length s) end_pos then Text (substring_from s pos) :: nil
          else CodeSpan (PrimString.sub s (add pos 1%int63) (sub end_pos (add pos 1%int63)))
                 :: parse_inlines_aux s (add end_pos 1%int63) remaining'
        else if int_eqb ch ch_lbracket then
          let label_end := find_char s ch_rbracket (add pos 1%int63) fuel in
          let url_open := add label_end 1%int63 in
          let url_start := add label_end 2%int63 in
          let url_end := find_char s ch_rparen url_start fuel in
          if leb (PrimString.length s) label_end then Text (substring_from s pos) :: nil
          else if leb (PrimString.length s) url_end then Text (substring_from s pos) :: nil
          else if negb (int_eqb (PrimString.get s url_open) ch_lparen) then Text (substring_from s pos) :: nil
               else Link
                 (PrimString.sub s (add pos 1%int63) (sub label_end (add pos 1%int63)))
                 (PrimString.sub s url_start (sub url_end url_start))
                 :: parse_inlines_aux s (add url_end 1%int63) remaining'
        else if int_eqb ch ch_star then
          (* Try [**strong**] first; fall back to [*emphasis*]; if no closer,
             emit a literal asterisk so we never lose characters. *)
          let next := add pos 1%int63 in
          let len := PrimString.length s in
          let is_strong_open :=
            andb (leb next (sub len 1%int63))
                 (int_eqb (PrimString.get s next) ch_star) in
          if is_strong_open then
            let inner_start := add pos 2%int63 in
            let close := find_double_star s inner_start fuel in
            if leb len (add close 1%int63) then
              (* unterminated [**] -> literal *)
              Text "*" :: parse_inlines_aux s next remaining'
            else
              let inner := PrimString.sub s inner_start (sub close inner_start) in
              Strong (parse_inlines_aux inner 0%int63 remaining')
                :: parse_inlines_aux s (add close 2%int63) remaining'
          else
            let close := find_single_star s next fuel in
            if leb len close then
              Text "*" :: parse_inlines_aux s next remaining'
            else
              let inner := PrimString.sub s next (sub close next) in
              Emphasis (parse_inlines_aux inner 0%int63 remaining')
                :: parse_inlines_aux s (add close 1%int63) remaining'
        else
          let next_link := find_char s ch_lbracket pos fuel in
          let next_code := find_char s ch_backtick pos fuel in
          let next_emph := find_char s ch_star pos fuel in
          let m1 := if leb next_link next_code then next_link else next_code in
          let next_break := if leb m1 next_emph then m1 else next_emph in
          if leb (PrimString.length s) next_break then Text (substring_from s pos) :: nil
          else if int_eqb next_break pos then Text (PrimString.sub s pos 1%int63) :: parse_inlines_aux s (add pos 1%int63) remaining'
               else Text (PrimString.sub s pos (sub next_break pos)) :: parse_inlines_aux s next_break remaining'
  end.

Definition parse_inlines (s : string) : list Inline :=
  parse_inlines_aux s 0%int63 fuel.

Fixpoint collect_code_lines (lines : list string) (acc : list string) : list string * list string :=
  match lines with
  | nil => (rev acc, nil)
  | l :: rest =>
      match classify_ticks l with
      | Some _ => (rev acc, rest)
      | None => collect_code_lines rest (l :: acc)
      end
  end.

Definition flush_paragraph (acc : list string) (tail : list Block) : list Block :=
  match acc with
  | nil => tail
  | _ => Paragraph (parse_inlines (join_with " " (rev acc))) :: tail
  end.

Fixpoint parse_blocks (remaining : nat) (lines : list string) (acc : list string) : list Block :=
  match remaining with
  | O => flush_paragraph acc nil
  | S remaining' =>
      match lines with
      | nil => flush_paragraph acc nil
      | l :: rest =>
          match classify_ticks l with
          | Some lang =>
              let '(code_lines, remaining_lines) := collect_code_lines rest nil in
              flush_paragraph acc (CodeBlock (trim lang) code_lines :: parse_blocks remaining' remaining_lines nil)
          | None =>
              (* Heading policy (see README): both "# " and "## " map to
                 Heading2.  The post title is rendered as the sole H1 in the
                 page shell, so any top-level heading in the body must be H2
                 to keep exactly one H1 per page.  "### " stays Heading3. *)
              if is_empty (trim l) then flush_paragraph acc (parse_blocks remaining' rest nil)
              else if starts_with l "# " then flush_paragraph acc (Heading2 (trim (drop_prefix l 2%int63)) :: parse_blocks remaining' rest nil)
              else if starts_with l "## " then flush_paragraph acc (Heading2 (trim (drop_prefix l 3%int63)) :: parse_blocks remaining' rest nil)
              else if starts_with l "### " then flush_paragraph acc (Heading3 (trim (drop_prefix l 4%int63)) :: parse_blocks remaining' rest nil)
              else match parse_image_line (trim l) with
                   | Some (alt, src) => flush_paragraph acc (ImageBlock (trim alt) (trim src) :: parse_blocks remaining' rest nil)
                   | None => parse_blocks remaining' rest (trim l :: acc)
                   end
          end
      end
  end.

(* Returns [Some (meta, body_lines)] if a closing [---] was seen; [None] if
   the frontmatter block is unterminated.  The caller should treat an
   unterminated block as "no frontmatter" and re-parse the raw lines as body,
   so authors who start a file with [---] but forget the closer don't lose
   their content. *)
Fixpoint parse_frontmatter_lines (lines : list string) (meta : Meta) : option (Meta * list string) :=
  match lines with
  | nil => None
  | l :: rest =>
      if string_eqb (trim l) "---" then Some (meta, rest)
      else
        let colon := find_char l ch_colon 0%int63 fuel in
        if leb (PrimString.length l) colon then parse_frontmatter_lines rest meta
        else
          let key := trim (PrimString.sub l 0%int63 colon) in
          let value := trim (substring_from l (add colon 1%int63)) in
          let meta' :=
            if string_eqb key "title" then mkMeta value meta.(meta_date) meta.(meta_slug) meta.(meta_summary) meta.(meta_topic) meta.(meta_lead_image) meta.(meta_lead_image_alt) meta.(meta_draft)
            else if string_eqb key "date" then mkMeta meta.(meta_title) value meta.(meta_slug) meta.(meta_summary) meta.(meta_topic) meta.(meta_lead_image) meta.(meta_lead_image_alt) meta.(meta_draft)
            else if string_eqb key "slug" then mkMeta meta.(meta_title) meta.(meta_date) value meta.(meta_summary) meta.(meta_topic) meta.(meta_lead_image) meta.(meta_lead_image_alt) meta.(meta_draft)
            else if string_eqb key "summary" then mkMeta meta.(meta_title) meta.(meta_date) meta.(meta_slug) value meta.(meta_topic) meta.(meta_lead_image) meta.(meta_lead_image_alt) meta.(meta_draft)
            else if string_eqb key "topic" then mkMeta meta.(meta_title) meta.(meta_date) meta.(meta_slug) meta.(meta_summary) value meta.(meta_lead_image) meta.(meta_lead_image_alt) meta.(meta_draft)
            else if string_eqb key "lead_image" then mkMeta meta.(meta_title) meta.(meta_date) meta.(meta_slug) meta.(meta_summary) meta.(meta_topic) value meta.(meta_lead_image_alt) meta.(meta_draft)
            else if string_eqb key "lead_image_alt" then mkMeta meta.(meta_title) meta.(meta_date) meta.(meta_slug) meta.(meta_summary) meta.(meta_topic) meta.(meta_lead_image) value meta.(meta_draft)
            else if string_eqb key "draft" then mkMeta meta.(meta_title) meta.(meta_date) meta.(meta_slug) meta.(meta_summary) meta.(meta_topic) meta.(meta_lead_image) meta.(meta_lead_image_alt) (string_eqb value "true")
            else meta
          in
          parse_frontmatter_lines rest meta'
  end.

Fixpoint first_heading_title (body : list Block) : string :=
  match body with
  | nil => "Untitled"
  | Heading2 s :: _ => s
  | Heading3 s :: _ => s
  | _ :: rest => first_heading_title rest
  end.

Definition fallback_title (meta : Meta) (body : list Block) : string :=
  if negb (is_empty meta.(meta_title)) then meta.(meta_title)
  else first_heading_title body.

Definition finalize_meta (path : string) (meta : Meta) (body : list Block) : Meta :=
  mkMeta
    (fallback_title meta body)
    meta.(meta_date)
    (slugify meta.(meta_slug) (file_stem path))
    meta.(meta_summary)
    meta.(meta_topic)
    (trim meta.(meta_lead_image))
    meta.(meta_lead_image_alt)
    meta.(meta_draft).

Definition parse_post (path raw : string) : Post :=
  let lines := to_lines raw in
  let '(meta, body_lines) :=
    match lines with
    | first :: rest =>
        if string_eqb (trim first) "---"
        then match parse_frontmatter_lines rest empty_meta with
             | Some fm => fm
             (* Unterminated frontmatter: keep the original lines as body so
                no content is silently lost. *)
             | None => (empty_meta, lines)
             end
        else (empty_meta, lines)
    | nil => (empty_meta, nil)
    end in
  let blocks := parse_blocks 10000 body_lines nil in
  mkPost (finalize_meta path meta blocks) blocks.

Definition render_block_impl (_ : unit) (b : Block) : string :=
  match b with
  | Heading2 s => cat "<h2>" (cat (html_escape s) "</h2>")
  | Heading3 s => cat "<h3>" (cat (html_escape s) "</h3>")
  | Paragraph parts => cat "<p>" (cat (render_inline_list parts) "</p>")
  | CodeBlock lang code_lines =>
      cat "<pre class='code-block'><code"
        (cat (if is_empty lang then "" else cat " data-lang='" (cat (html_escape lang) "'"))
          (cat ">"
            (cat (join_with newline_str (map html_escape code_lines))
                 "</code></pre>")))
  | ImageBlock alt src =>
      cat "<figure class='plate'><img src='"
        (cat (html_escape (post_asset_href src))
          (cat "' alt='" (cat (html_escape alt) "'></figure>")))
  end.

Fixpoint render_blocks (blocks : list Block) : string :=
  match blocks with
  | nil => ""
  | b :: rest => cat (render_block_impl tt b) (render_blocks rest)
  end.

(* Returns the raw (unescaped) "topic / date" line.  Callers are expected to
   apply [html_escape] exactly once.  Escaping here as well would
   double-encode ampersands and angle brackets. *)
Definition meta_line (m : Meta) : string :=
  let parts := filter (fun s => negb (is_empty s)) (m.(meta_topic) :: m.(meta_date) :: nil) in
  join_with " / " parts.

Definition lead_media (m : Meta) : string :=
  if is_empty m.(meta_lead_image) then
    "<div class='lead-field' aria-hidden='true'></div>"
  else
    cat "<figure class='lead-figure'><img src='"
      (cat (html_escape (post_asset_href m.(meta_lead_image)))
        (cat "' alt='" (cat (html_escape m.(meta_lead_image_alt)) "'></figure>"))).

Definition page_shell (depth page_title body_class nav_label nav_href body_content : string) : string :=
  concat_all (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>" ::
    "<title>" :: html_escape page_title :: "</title>" ::
    "<link rel='stylesheet' href='" :: html_escape (rel_stylesheet depth) :: "'>" ::
    "</head><body class='" :: body_class :: "'><div class='page-shell'>" ::
    "<header class='site-header'><div class='site-mark'><a href='" :: html_escape (rel_index depth) :: "'>wklm.online</a></div>" ::
    "<div class='site-note'>technical essays on verification, tooling, and design</div>" ::
    "<nav class='site-nav'><a href='" :: html_escape nav_href :: "'>" :: html_escape nav_label :: "</a></nav></header>" ::
    body_content ::
    "<footer class='site-footer'><p>built from a small, explicit core</p></footer></div></body></html>" :: nil).

Definition render_post_page (p : Post) : string :=
  let m := p.(post_meta) in
  let body := concat_all (
    "<main class='post-layout'><aside class='meta-rail'><div class='index-chip'>" ::
    html_escape m.(meta_topic) ::
    "</div><div class='rail-date'>" :: html_escape m.(meta_date) :: "</div></aside>" ::
    "<article class='post-article'><header class='post-header'><p class='post-meta'>" :: html_escape (meta_line m) ::
    "</p><h1>" :: html_escape m.(meta_title) :: "</h1><p class='post-deck'>" :: html_escape m.(meta_summary) :: "</p>" ::
    lead_media m :: "</header><div class='post-body'>" :: render_blocks p.(post_body) :: "</div></article></main>" :: nil) in
  page_shell "../" m.(meta_title) "post-page" "index" "../index.html" body.

Fixpoint nat_to_string_aux (remaining : nat) (n : nat) (acc : string) : string :=
  match remaining with
  | O => acc
  | S remaining' =>
      let d := Nat.modulo n 10 in
      let n' := Nat.div n 10 in
      let c := match d with
               | 0 => "0" | 1 => "1" | 2 => "2" | 3 => "3" | 4 => "4"
               | 5 => "5" | 6 => "6" | 7 => "7" | 8 => "8" | _ => "9"
               end in
      let acc' := cat c acc in
      if Nat.eqb n' 0 then acc' else nat_to_string_aux remaining' n' acc'
  end.

Definition nat_to_string (n : nat) : string :=
  nat_to_string_aux 20 n "".

Definition post_list_item (n : nat) (p : Post) : string :=
  let m := p.(post_meta) in
  concat_all (
    "<li class='post-row'><div class='post-number'>" :: html_escape (nat_to_string n) ::
    "</div><div class='post-copy'><p class='post-row-meta'>" :: html_escape (meta_line m) :: "</p>" ::
    "<h2><a href='" :: html_escape (cat m.(meta_slug) "/index.html") :: "'>" :: html_escape m.(meta_title) :: "</a></h2>" ::
    "<p class='post-row-deck'>" :: html_escape m.(meta_summary) :: "</p></div></li>" :: nil).

Fixpoint number_posts (posts : list Post) (n : nat) : list string :=
  match posts with
  | nil => nil
  | p :: rest => post_list_item n p :: number_posts rest (S n)
  end.

Definition render_index_page (posts : list Post) : string :=
  let body := concat_all (
    "<main class='index-layout'><section class='index-intro'><p class='intro-kicker'>essays</p><h1>wklm.online</h1><p class='intro-deck'>A numbered index of technical notes on formal systems, software construction, and visual design.</p></section>" ::
    "<ol class='post-list'>" :: concat_all (number_posts posts 1%nat) :: "</ol></main>" :: nil) in
  page_shell "" "wklm.online" "index-page" "archive" "index.html" body.

Definition stylesheet : string :=
  "body{margin:0;background:#f4f0e8;color:#171717;font:18px/1.65 Georgia,serif}a{color:inherit;text-decoration-color:#b08d57;text-underline-offset:.18em}img{display:block;max-width:100%;height:auto}.page-shell{max-width:72rem;margin:0 auto;padding:1.25rem}.site-header,.site-footer{display:flex;justify-content:space-between;gap:1rem;align-items:end}.site-header{padding:1rem 0 2rem;border-top:.25rem solid #171717}.site-mark,.site-note,.site-nav,.site-footer{font-family:Arial,Helvetica,sans-serif;letter-spacing:.12em;text-transform:uppercase}.site-mark a,.post-copy h2 a{text-decoration:none}.site-note,.site-nav,.site-footer,.post-row-meta,.post-meta,.intro-kicker,.index-chip,.rail-date{font-size:.78rem;color:#5c554c}.index-intro h1,.post-header h1{font-family:Arial,Helvetica,sans-serif;line-height:.95;text-transform:lowercase}.index-intro h1{font-size:clamp(3rem,10vw,6rem)}.intro-deck,.post-deck{max-width:36rem;color:#1d2733}.post-list{list-style:none;padding-left:0;margin:0}.post-row{margin:1.5rem 0;display:grid;grid-template-columns:3rem 1fr;gap:1rem;align-items:start}.post-number{font-family:Arial,Helvetica,sans-serif;font-weight:700;font-size:1.5rem;line-height:1;padding-top:.25rem;border-top:.2rem solid #171717}.post-copy h2{margin:.25rem 0 .4rem;font-family:Georgia,serif;font-size:1.6rem;line-height:1.15}.post-copy p.post-row-deck{margin:0;color:#1d2733}.post-layout{display:grid;grid-template-columns:12rem minmax(0,42rem);gap:1.5rem}.post-article,.post-body{min-width:0}.post-body p,.post-body li{overflow-wrap:break-word}.code-block{padding:1rem;background:#12202c;color:#f4f0e8;border-top:.2rem solid #b08d57;overflow-x:auto;white-space:pre;font-size:.9rem;line-height:1.5}.post-header .post-meta{display:none}.plate img,.lead-figure img,.lead-field{border:1px solid #6f665c}.lead-field{height:16rem;background:#ece6da}@media(max-width:900px){.site-header,.site-footer{display:block}.post-layout{grid-template-columns:1fr}.meta-rail{display:none}.post-header .post-meta{display:block}}".

Definition should_publish (p : Post) : bool :=
  negb p.(post_meta).(meta_draft).

Definition filter_posts (posts : list Post) : list Post :=
  filter should_publish posts.

Fixpoint read_posts (paths : list string) : IO (list Post) :=
  match paths with
  | nil => Ret nil
  | path :: rest =>
      raw <- read path ;;
      parsed_rest <- read_posts rest ;;
      Ret (parse_post path raw :: parsed_rest)
  end.

Fixpoint copy_post_assets (source_dir output_dir : string) (names : list string) : IO unit :=
  match names with
  | nil => Ret tt
  | name :: rest =>
      (* Defensive filters: skip markdown (handled by the post pipeline) and
         dotfiles (which may include ".", "..", or hidden files surfaced by
         [list_directory]). *)
      if orb (has_suffix name ".md") (starts_with name ".")
      then copy_post_assets source_dir output_dir rest
      else
        raw <- read (cat source_dir (cat "/" name)) ;;
        _ <- write_file (cat output_dir (cat "/" name)) raw ;;
        copy_post_assets source_dir output_dir rest
  end.

Fixpoint insert_post (p : Post) (posts : list Post) : list Post :=
  match posts with
  | nil => p :: nil
  | q :: rest =>
      if string_ge p.(post_meta).(meta_date) q.(post_meta).(meta_date)
      then p :: q :: rest
      else q :: insert_post p rest
  end.

Fixpoint sort_posts (posts : list Post) : list Post :=
  match posts with
  | nil => nil
  | p :: rest => insert_post p (sort_posts rest)
  end.

Fixpoint write_post_pages (output_dir : string) (posts : list Post) : IO unit :=
  match posts with
  | nil => Ret tt
  | p :: rest =>
      _ <- create_directory (dirname_output_path output_dir p.(post_meta).(meta_slug)) ;;
      _ <- write_file (file_output_path output_dir p.(post_meta).(meta_slug)) (render_post_page p) ;;
      write_post_pages output_dir rest
  end.

(* Asset reference collection: returns every asset filename referenced by
   published posts (lead images plus inline image-block sources).  Used to
   filter the raw directory listing so drafts' assets don't leak into
   [_site/posts/]. *)
Fixpoint block_image_srcs (body : list Block) : list string :=
  match body with
  | nil => nil
  | ImageBlock _ src :: rest => src :: block_image_srcs rest
  | _ :: rest => block_image_srcs rest
  end.

Definition post_asset_refs (p : Post) : list string :=
  let lead := p.(post_meta).(meta_lead_image) in
  let leads := if is_empty lead then nil else lead :: nil in
  app leads (block_image_srcs p.(post_body)).

Fixpoint collect_asset_refs (posts : list Post) : list string :=
  match posts with
  | nil => nil
  | p :: rest => app (post_asset_refs p) (collect_asset_refs rest)
  end.

Fixpoint member_string (x : string) (xs : list string) : bool :=
  match xs with
  | nil => false
  | y :: rest => if string_eqb x y then true else member_string x rest
  end.

Definition run : IO unit :=
  files <- list_directory "./posts" ;;
  let md_paths := map (fun name => cat "./posts/" name) (filter (fun name => has_suffix name ".md") files) in
  parsed_posts <- read_posts md_paths ;;
  let posts := sort_posts (filter_posts parsed_posts) in
  (* Only copy assets referenced by a published post, so drafts don't leak
     their images into [_site/posts/]. *)
  let referenced := collect_asset_refs posts in
  let asset_names := filter (fun name => member_string name referenced) files in
  _ <- create_directory "./_site" ;;
  _ <- create_directory "./_site/posts" ;;
  _ <- create_directory "./_site/styles" ;;
  _ <- copy_post_assets "./posts" "./_site/posts" asset_names ;;
  _ <- write_file (styles_output_path "./_site") stylesheet ;;
  _ <- write_file (index_output_path "./_site") (render_index_page posts) ;;
  write_post_pages "./_site" posts.

Set Warnings "-crane-extraction-default-directory".
Crane Extraction "blog" run.
