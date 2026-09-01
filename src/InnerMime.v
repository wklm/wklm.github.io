(* InnerMime.v — pure port of static/decrypt.ml's [extract_inner_text] and
   [body_to_html] (+ [strip_frontmatter]): given the decrypted inner MIME, pull
   out the Subject, the concatenated text body, and the attachment filenames,
   then render the body to HTML for the decrypted reading view.

   [body_to_html] was replaced by the markdown renderer [md_to_html]
   (InnerMime.v below): the accessible #real-body view now honours headings,
   bold/emphasis/code spans, links, https/http images, lists, blockquotes, rules
   and fenced code blocks, while every input byte still flows through
   [escape_byte]/[escape_url_byte] and all emitted tags are fixed literals, so
   the T1 escaping discipline holds for the new renderer exactly as it did for
   the escape-only one.

   Reuses StringLib.v (string primitives) and MimeLib.v / MimeBuild.v (header /
   body split, boundary extraction, multipart split, part-filename, terminator
   trim).  All helpers are top-level Definitions / Fixpoints with explicit
   return types to keep Crane's C++ free of std::any, and every recursive
   helper is tail-recursive (the check-tail-position.sh CI gate enforces this
   on the extracted C++).

   T1 (privacy): the only sink for untrusted decrypted text is set_text_content;
   [md_to_html] HTML-escapes every metacharacter (ampersand, angle brackets,
   double-quote — and single-quote inside URLs) so the single escaped-HTML sink
   (set_inner_html) can never inject markup. *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.
Require Import MimeLib.
Require Import MimeBuild.
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* ---- Inner-MIME field extraction ----------------------------------- *)

(* Concatenate the text/markdown + text/plain part bodies, in order.  (decrypt.ml
   appends each matching part's body to a running [text].) *)
(* AIDEV-NOTE: tail-recursive [acc] (was [cat pb (collect_text rest)] — non-tail,
   one frame per MIME part; same stack-overflow class as body_to_html_aux). *)
Fixpoint collect_text (parts : list string) (acc : string) : string :=
  match parts with
  | [] => acc
  | part :: rest =>
      let part' := trim_part_terminator part in
      let '(ph, pb) := split_headers_body2 part' in
      let phdrs := parse_headers ph in
      let pct := header_lookup "Content-Type" phdrs in
      if orb (starts_with pct "text/markdown") (starts_with pct "text/plain")
      then collect_text rest (cat acc pb)
      else collect_text rest acc
  end.

(* Collect attachment filenames (application/octet-stream or image subtypes),
   in order.  decrypt.ml falls back to the literal name attachment when none. *)
(* AIDEV-NOTE: tail-recursive [acc] + [rev_append] (was [name :: collect_image_names
   rest] — non-tail).  rev_append (not List.rev) finalises in tail position so the
   reverse itself cannot overflow either. *)
Fixpoint collect_image_names (parts : list string) (acc : list string) : list string :=
  match parts with
  | [] => rev_append acc []
  | part :: rest =>
      let part' := trim_part_terminator part in
      let '(ph, _pb) := split_headers_body2 part' in
      let phdrs := parse_headers ph in
      let pct := header_lookup "Content-Type" phdrs in
      if orb (starts_with pct "application/octet-stream")
             (starts_with pct "image/")
      then
        let fn := part_filename phdrs in
        let name := if is_empty fn then "attachment" else fn in
        collect_image_names rest (name :: acc)
      else collect_image_names rest acc
  end.

(* The result of parsing the inner MIME: subject, concatenated text body, and
   attachment filenames. *)
Record inner_content := mkInner {
  inner_subject : string;
  inner_body    : string;
  inner_images  : list string
}.

(* Port of extract_inner_text: split headers/body, read Subject, find the
   declared boundary; if none, the body IS the text (no parts); otherwise split
   on the inner MIME's own boundary and dispatch parts by Content-Type. *)
Definition extract_inner_text (inner_mime : string) : inner_content :=
  let '(hdrs_block, body) := split_headers_body2 inner_mime in
  let hdrs := parse_headers hdrs_block in
  let subject := header_lookup "Subject" hdrs in
  let ct := header_lookup "Content-Type" hdrs in
  let boundary := extract_boundary ct in
  if is_empty boundary then
    mkInner subject body []
  else
    let parts := split_parts (trim body) boundary in
    mkInner subject (collect_text parts "") (collect_image_names parts []).

(* ---- Frontmatter stripping (port of strip_frontmatter) ------------- *)
(* If [s] begins with "---\n" (or "---\r\n"), drop everything through the next
   line that is exactly "---" (optionally CR-terminated) followed by a newline.
   Otherwise return [s] unchanged.  Top-level Fixpoint (not a nested let fix) to
   avoid std::any. *)

Definition starts_dashes_lf (s : string) : bool :=
  orb (starts_with s (cat "---" lf))
      (starts_with s (cat "---" (cat cr lf))).

(* Scan from [i] for a '\n' that begins a "---" line; return the index just past
   the closing delimiter's trailing newline, or length s if none. *)
Fixpoint find_close_dashes (s : string) (i : int) (fuel : nat) : int :=
  let n := PrimString.length s in
  match fuel with
  | O => n
  | S f' =>
      if leb n (add i 4%int63) then n
      else
        let c0 := PrimString.get s i in
        let c1 := PrimString.get s (add i 1%int63) in
        let c2 := PrimString.get s (add i 2%int63) in
        let c3 := PrimString.get s (add i 3%int63) in
        if andb (int_eqb c0 ch_newline)
                (andb (int_eqb c1 45%int63)
                      (andb (int_eqb c2 45%int63) (int_eqb c3 45%int63)))
        then
          (* line is "---"; consume its trailing newline (LF or CRLF). *)
          if leb n (add i 4%int63) then n
          else if int_eqb (PrimString.get s (add i 4%int63)) ch_newline
               then add i 5%int63
          else if leb n (add i 5%int63) then n
          else if andb (int_eqb (PrimString.get s (add i 4%int63)) ch_cr)
                       (int_eqb (PrimString.get s (add i 5%int63)) ch_newline)
               then add i 6%int63
          else find_close_dashes s (add i 1%int63) f'
        else find_close_dashes s (add i 1%int63) f'
  end.

(* after_open as a top-level [: int] Definition: a bare [let after_open := if ..]
   inside strip_frontmatter extracts to [std::any after_open]
   (crane-extraction-gotchas: conditional-in-let leaks std::any — cf.
   fm_after_open). *)
Definition fm_after_open (s : string) : int :=
  if starts_with s (cat "---" (cat cr lf)) then 5%int63 else 4%int63.

Definition strip_frontmatter (s : string) : string :=
  if negb (starts_dashes_lf s) then s
  else
    let n := PrimString.length s in
    let after_open := fm_after_open s in
    let body_start := find_close_dashes s after_open mime_fuel in
    if leb n body_start then s
    else PrimString.sub s body_start (sub n body_start).

(* ---- HTML escaping + Markdown -> HTML (md_to_html) ------------------ *)
(* Escape one byte for HTML text context (amp, lt, gt, dquote); else verbatim. *)
Definition escape_byte (c : int) : string :=
  if int_eqb c ch_amp then "&amp;"
  else if int_eqb c ch_lt then "&lt;"
  else if int_eqb c ch_gt then "&gt;"
  else if int_eqb c ch_quote then "&quot;"
  else PrimString.make 1%int63 c.

(* Escape the bytes of [s] in [pos, stop) into [acc] (tail-recursive).  This is
   the single escape primitive the whole markdown renderer funnels untrusted
   text through, so the T1 discipline ("the only sink is escaped HTML") holds
   by construction: every emitted tag below is a FIXED literal, never derived
   from input. *)
Fixpoint escape_run (s : string) (pos stop : int) (fuel : nat) (acc : string) : string :=
  let n := PrimString.length s in
  match fuel with
  | O => acc
  | S f' =>
      if orb (leb stop pos) (leb n pos) then acc
      else escape_run s (add pos 1%int63) stop f'
               (cat acc (escape_byte (PrimString.get s pos)))
  end.

(* Escape one byte inside a URL in a single-quoted HTML attribute: same as
   [escape_byte] but ALSO escapes the single quote (&#39;) so a URL can never
   break out of the attribute delimiter. *)
Definition escape_url_byte (c : int) : string :=
  if int_eqb c 39%int63 then "&#39;"   (* ' *)
  else escape_byte c.

Fixpoint escape_url_run (s : string) (pos stop : int) (fuel : nat) (acc : string) : string :=
  let n := PrimString.length s in
  match fuel with
  | O => acc
  | S f' =>
      if orb (leb stop pos) (leb n pos) then acc
      else escape_url_run s (add pos 1%int63) stop f'
               (cat acc (escape_url_byte (PrimString.get s pos)))
  end.

(* ---- Inline delimiter scanners ------------------------------------- *)
(* All four return the index of the closing delimiter (or [n] = length of s
   when the delimiter is never found, so the caller falls back to literal
   text).  Tail-recursive, fuel-bounded. *)

(* First "**" at or after [pos]. *)
Fixpoint find_dd (s : string) (pos : int) (fuel : nat) : int :=
  let n := PrimString.length s in
  match fuel with
  | O => n
  | S f' =>
      if leb n (add pos 1%int63) then n
      else if andb (int_eqb (PrimString.get s pos) 42%int63)
                   (int_eqb (PrimString.get s (add pos 1%int63)) 42%int63)
           then pos
           else find_dd s (add pos 1%int63) f'
  end.

(* First single "*" at or after [pos] (emphasis closer). *)
Fixpoint find_star (s : string) (pos : int) (fuel : nat) : int :=
  let n := PrimString.length s in
  match fuel with
  | O => n
  | S f' =>
      if leb n pos then n
      else if int_eqb (PrimString.get s pos) 42%int63
           then pos
           else find_star s (add pos 1%int63) f'
  end.

(* First "`" at or after [pos] (code-span closer). *)
Fixpoint find_tick (s : string) (pos : int) (fuel : nat) : int :=
  let n := PrimString.length s in
  match fuel with
  | O => n
  | S f' =>
      if leb n pos then n
      else if int_eqb (PrimString.get s pos) 96%int63
           then pos
           else find_tick s (add pos 1%int63) f'
  end.

(* First "]" at or after [pos] (link label terminator). *)
Fixpoint find_rbracket (s : string) (pos : int) (fuel : nat) : int :=
  let n := PrimString.length s in
  match fuel with
  | O => n
  | S f' =>
      if leb n pos then n
      else if int_eqb (PrimString.get s pos) 93%int63
           then pos
           else find_rbracket s (add pos 1%int63) f'
  end.

(* First ")" at or after [pos] (link URL terminator). *)
Fixpoint find_rparen (s : string) (pos : int) (fuel : nat) : int :=
  let n := PrimString.length s in
  match fuel with
  | O => n
  | S f' =>
      if leb n pos then n
      else if int_eqb (PrimString.get s pos) 41%int63
           then pos
           else find_rparen s (add pos 1%int63) f'
  end.

(* ---- Inline renderer ------------------------------------------------ *)
(* Render the inline markdown of one line: escapes every byte, and expands
   **bold**, *italic*, `code`, [text](url) and ![alt](http(s)://...) to
   fixed-literal tags whose CONTENT is escaped by [escape_run] (URLs included).
   Relative image refs stay bang+link.  Unmatched delimiters stay literal.
   No nesting (span content is escaped flat) so the whole function is
   tail-recursive — one frame per byte, TCO-able by em++ -O2, and fuel-bounded. *)
Fixpoint md_inline_aux (s : string) (pos : int) (fuel : nat) (acc : string) : string :=
  let n := PrimString.length s in
  match fuel with
  | O => acc
  | S f' =>
      if leb n pos then acc
      else
        let c := PrimString.get s pos in
        (* 42 = '*', 96 = '`', 91 = '[', 93 = ']', 40 = '(', 41 = ')' *)
        if int_eqb c 42%int63 then
          if andb (ltb (add pos 1%int63) n)
                  (int_eqb (PrimString.get s (add pos 1%int63)) 42%int63)
          then (* **strong** *)
            let closer := find_dd s (add pos 2%int63) f' in
            if leb n closer then
              md_inline_aux s (add pos 2%int63) f' (cat acc "**")
            else
              md_inline_aux s (add closer 2%int63) f'
                (cat acc (cat "<strong>"
                   (cat (escape_run s (add pos 2%int63) closer f' "") "</strong>")))
          else (* *em* *)
            let closer := find_star s (add pos 1%int63) f' in
            if leb n closer then
              md_inline_aux s (add pos 1%int63) f' (cat acc "*")
            else
              md_inline_aux s (add closer 1%int63) f'
                (cat acc (cat "<em>"
                   (cat (escape_run s (add pos 1%int63) closer f' "") "</em>")))
        else if int_eqb c 96%int63 then (* `code` *)
          let closer := find_tick s (add pos 1%int63) f' in
          if leb n closer then
            md_inline_aux s (add pos 1%int63) f' (cat acc "`")
          else
            md_inline_aux s (add closer 1%int63) f'
              (cat acc (cat "<code>"
                 (cat (escape_run s (add pos 1%int63) closer f' "") "</code>")))
        else if int_eqb c 33%int63 then (* '!' — ![alt](http(s)://url) *)
          if andb (ltb (add pos 1%int63) n)
                  (int_eqb (PrimString.get s (add pos 1%int63)) 91%int63)
          then
            let lb := add pos 1%int63 in
            let dm := find_rbracket s (add lb 1%int63) f' in
            let has_open := andb (ltb dm n) (ltb (add dm 1%int63) n) in
            let is_bang_link := andb has_open
               (int_eqb (PrimString.get s (add dm 1%int63)) 40%int63) in
            if is_bang_link then
              let url_start := add dm 2%int63 in
              let rp := find_rparen s url_start f' in
              if leb n rp then
                md_inline_aux s (add pos 1%int63) f' (cat acc "!")
              else
                let url := PrimString.sub s url_start (sub rp url_start) in
                if orb (starts_with url "https://") (starts_with url "http://")
                then
                  md_inline_aux s (add rp 1%int63) f'
                    (cat acc (cat "<img src='"
                       (cat (escape_url_run s url_start rp f' "")
                         (cat "' alt='"
                           (cat (escape_run s (add lb 1%int63) dm f' "") "'>")))))
                else
                  md_inline_aux s (add pos 1%int63) f' (cat acc "!")
            else
              md_inline_aux s (add pos 1%int63) f' (cat acc "!")
          else
            md_inline_aux s (add pos 1%int63) f' (cat acc "!")
        else if int_eqb c 91%int63 then (* [text](url) *)
          let dm := find_rbracket s (add pos 1%int63) f' in
          let has_open := andb (ltb dm n) (ltb (add dm 1%int63) n) in
          let is_link := andb has_open
             (int_eqb (PrimString.get s (add dm 1%int63)) 40%int63) in
          if is_link then
            let url_start := add dm 2%int63 in
            let rp := find_rparen s url_start f' in
            if leb n rp then
              md_inline_aux s (add pos 1%int63) f' (cat acc "[")
            else
              md_inline_aux s (add rp 1%int63) f'
                (cat acc (cat "<a href='"
                   (cat (escape_url_run s url_start rp f' "")
                     (cat "'>"
                       (cat (escape_run s (add pos 1%int63) dm f' "") "</a>")))))
          else
            md_inline_aux s (add pos 1%int63) f' (cat acc "[")
        else
          md_inline_aux s (add pos 1%int63) f' (cat acc (escape_byte c))
  end.

Definition md_inline (s : string) : string :=
  md_inline_aux s 0%int63 mime_fuel "".

(* Raw substring (no escaping) — the canvas path consumes this, where the
   text is painted glyph-by-glyph and there is no HTML context to escape. *)
Definition md_slice (s : string) (a b : int) : string :=
  PrimString.sub s a (sub b a).

(* ---- Inline stripper (plain text, for the canvas path) -------------- *)
(* Drop the markdown delimiters so the Verified-Reader canvas reads cleanly:
   **bold** -> bold, *em* -> em, `code` -> code, [label](url) -> label,
   ![alt](http(s)://...) -> (dropped; photos live in #real-body).
   Same scanners as [md_inline_aux]; emits RAW bytes (no HTML escaping).
   Tail-recursive, fuel-bounded. *)
Fixpoint md_strip_aux (s : string) (pos : int) (fuel : nat) (acc : string) : string :=
  let n := PrimString.length s in
  match fuel with
  | O => acc
  | S f' =>
      if leb n pos then acc
      else
        let c := PrimString.get s pos in
        if int_eqb c 42%int63 then
          if andb (ltb (add pos 1%int63) n)
                  (int_eqb (PrimString.get s (add pos 1%int63)) 42%int63)
          then (* **strong** *)
            let closer := find_dd s (add pos 2%int63) f' in
            if leb n closer then
              md_strip_aux s (add pos 2%int63) f' (cat acc "**")
            else
              md_strip_aux s (add closer 2%int63) f'
                (cat acc (md_slice s (add pos 2%int63) closer))
          else (* *em* *)
            let closer := find_star s (add pos 1%int63) f' in
            if leb n closer then
              md_strip_aux s (add pos 1%int63) f' (cat acc "*")
            else
              md_strip_aux s (add closer 1%int63) f'
                (cat acc (md_slice s (add pos 1%int63) closer))
        else if int_eqb c 96%int63 then (* `code` *)
          let closer := find_tick s (add pos 1%int63) f' in
          if leb n closer then
            md_strip_aux s (add pos 1%int63) f' (cat acc "`")
          else
            md_strip_aux s (add closer 1%int63) f'
              (cat acc (md_slice s (add pos 1%int63) closer))
        else if int_eqb c 33%int63 then (* '!' — drop https/http images *)
          if andb (ltb (add pos 1%int63) n)
                  (int_eqb (PrimString.get s (add pos 1%int63)) 91%int63)
          then
            let lb := add pos 1%int63 in
            let dm := find_rbracket s (add lb 1%int63) f' in
            let has_open := andb (ltb dm n) (ltb (add dm 1%int63) n) in
            let is_bang_link := andb has_open
               (int_eqb (PrimString.get s (add dm 1%int63)) 40%int63) in
            if is_bang_link then
              let url_start := add dm 2%int63 in
              let rp := find_rparen s url_start f' in
              if leb n rp then
                md_strip_aux s (add pos 1%int63) f' (cat acc "!")
              else
                let url := PrimString.sub s url_start (sub rp url_start) in
                if orb (starts_with url "https://") (starts_with url "http://")
                then md_strip_aux s (add rp 1%int63) f' acc
                else md_strip_aux s (add pos 1%int63) f' (cat acc "!")
            else
              md_strip_aux s (add pos 1%int63) f' (cat acc "!")
          else
            md_strip_aux s (add pos 1%int63) f' (cat acc "!")
        else if int_eqb c 91%int63 then (* [label](url) *)
          let dm := find_rbracket s (add pos 1%int63) f' in
          let has_open := andb (ltb dm n) (ltb (add dm 1%int63) n) in
          let is_link := andb has_open
             (int_eqb (PrimString.get s (add dm 1%int63)) 40%int63) in
          if is_link then
            let rp := find_rparen s (add dm 2%int63) f' in
            if leb n rp then
              md_strip_aux s (add pos 1%int63) f' (cat acc "[")
            else
              md_strip_aux s (add rp 1%int63) f'
                (cat acc (md_slice s (add pos 1%int63) dm))
          else
            md_strip_aux s (add pos 1%int63) f' (cat acc "[")
        else
          md_strip_aux s (add pos 1%int63) f' (cat acc (PrimString.make 1%int63 c))
  end.

Definition md_strip_inline (s : string) : string :=
  md_strip_aux s 0%int63 mime_fuel "".

(* ---- Block-level classification ------------------------------------- *)
(* All classifiers take the TRIMMED line [t].  Return "" / 0 / false when the
   line is not of the kind — single-type returns, no tuples (std::any trap). *)

(* Fenced code: a trimmed line starting with three backticks. *)
Definition md_fence (t : string) : bool := starts_with t "```".

(* Count leading '#' at [pos].  Tail-recursive accumulator (the gate rejects
   the operand form `1 + count_hashes ...`). *)
Fixpoint count_hashes (t : string) (pos : int) (fuel : nat) (acc : int) : int :=
  match fuel with
  | O => acc
  | S f' =>
      if andb (ltb pos (PrimString.length t))
              (int_eqb (PrimString.get t pos) 35%int63)
      then count_hashes t (add pos 1%int63) f' (add acc 1%int63)
      else acc
  end.

(* Heading level 1..6, or 0 when [t] is not an ATX heading (# ...). *)
Definition md_heading_level (t : string) : int :=
  let c := count_hashes t 0%int63 8%nat 0%int63 in
  if andb (ltb 0%int63 c) (leb c 6%int63) then
    let n := PrimString.length t in
    if orb (int_eqb n c) (int_eqb (PrimString.get t c) 32%int63)
    then c else 0%int63
  else 0%int63.

(* Text after the '#' run (and one separating space) of a heading. *)
Definition md_heading_content (t : string) (lvl : int) : string :=
  trim_left (PrimString.sub t lvl (sub (PrimString.length t) lvl)).

(* Is [t] a run of 3+ identical '-', '*' or '_' (horizontal rule)? *)
Fixpoint all_of (t : string) (pos : int) (c : int) (fuel : nat) : bool :=
  match fuel with
  | O => true
  | S f' =>
      if leb (PrimString.length t) pos then true
      else if int_eqb (PrimString.get t pos) c
           then all_of t (add pos 1%int63) c f'
           else false
  end.

Definition md_is_hr (t : string) : bool :=
  andb (leb 3%int63 (PrimString.length t))
    (orb (all_of t 0%int63 45%int63 4096%nat)
     (orb (all_of t 0%int63 42%int63 4096%nat)
          (all_of t 0%int63 95%int63 4096%nat))).

(* Is [t] a blockquote line (leading '>')? *)
Definition md_is_quote (t : string) : bool :=
  andb (negb (is_empty t)) (int_eqb (PrimString.get t 0%int63) 62%int63).

(* Content after the '>' (and one optional space). *)
Definition md_quote_content (t : string) : string :=
  if md_is_quote t then
    let n := PrimString.length t in
    trim_left (PrimString.sub t 1%int63 (sub n 1%int63))
  else "".

(* Unordered list: "- ", "* ", "+ " at start. *)
Definition md_is_ul (t : string) : bool :=
  let n := PrimString.length t in
  andb (leb 2%int63 n)
    (orb (andb (int_eqb (PrimString.get t 0%int63) 45%int63)
               (int_eqb (PrimString.get t 1%int63) 32%int63))
     (orb (andb (int_eqb (PrimString.get t 0%int63) 42%int63)
                (int_eqb (PrimString.get t 1%int63) 32%int63))
          (andb (int_eqb (PrimString.get t 0%int63) 43%int63)
                (int_eqb (PrimString.get t 1%int63) 32%int63)))).

(* Skip a run of digits at [pos]; returns the first non-digit index. *)
Fixpoint skip_digits (t : string) (pos : int) (fuel : nat) : int :=
  match fuel with
  | O => pos
  | S f' =>
      if andb (ltb pos (PrimString.length t))
              (andb (leb 48%int63 (PrimString.get t pos))
                    (leb (PrimString.get t pos) 57%int63))
      then skip_digits t (add pos 1%int63) f'
      else pos
  end.

(* Ordered list: digits then ". " (e.g. "1. item"). *)
Definition md_is_ol (t : string) : bool :=
  let n := PrimString.length t in
  let d := skip_digits t 0%int63 16%nat in
  andb (ltb 0%int63 d)
    (andb (ltb (add d 1%int63) n)
      (andb (int_eqb (PrimString.get t d) 46%int63)
            (int_eqb (PrimString.get t (add d 1%int63)) 32%int63))).

(* List item content (after the marker), "" when not a list item. *)
Definition md_list_body (t : string) : string :=
  let n := PrimString.length t in
  if md_is_ul t then PrimString.sub t 2%int63 (sub n 2%int63)
  else if md_is_ol t then
    let d := skip_digits t 0%int63 16%nat in
    PrimString.sub t (add d 2%int63) (sub n (add d 2%int63))
  else "".

(* ---- Block-level emit helpers ---------------------------------------- *)
(* Fixed-literal tags.  [lvl] is known 1..6 by the caller. *)
Definition md_hopen (lvl : int) : string :=
  if int_eqb lvl 1%int63 then "<h1>"
  else if int_eqb lvl 2%int63 then "<h2>"
  else if int_eqb lvl 3%int63 then "<h3>"
  else if int_eqb lvl 4%int63 then "<h4>"
  else if int_eqb lvl 5%int63 then "<h5>"
  else "<h6>".

Definition md_hclose (lvl : int) : string :=
  if int_eqb lvl 1%int63 then "</h1>"
  else if int_eqb lvl 2%int63 then "</h2>"
  else if int_eqb lvl 3%int63 then "</h3>"
  else if int_eqb lvl 4%int63 then "</h4>"
  else if int_eqb lvl 5%int63 then "</h5>"
  else "</h6>".

(* Close a block's tag(s) when it is open.  A quote block opens BOTH
   <blockquote> and <p>, so it closes as "</p></blockquote>". *)
Definition md_close_p (acc : string) (in_p : bool) : string :=
  if in_p then cat acc "</p>" else acc.

Definition md_close_ul (acc : string) (in_ul : bool) : string :=
  if in_ul then cat acc "</ul>" else acc.

Definition md_close_ol (acc : string) (in_ol : bool) : string :=
  if in_ol then cat acc "</ol>" else acc.

Definition md_close_quote (acc : string) (in_quote : bool) : string :=
  if in_quote then cat acc "</p></blockquote>" else acc.

(* Close every open block (no nesting, so order only matters for the quote's
   two tags, which are adjacent). *)
Definition md_close_all (acc : string) (in_p in_ul in_ol in_quote : bool) : string :=
  md_close_p (md_close_quote (md_close_ol (md_close_ul acc in_ul) in_ol) in_quote) in_p.

(* ---- Block renderer -------------------------------------------------- *)
(* Line-by-line tail-recursive state machine.  State is carried as separate
   parameters (in_p / in_ul / in_ol / in_quote / in_code) — never a tuple — so
   Crane extracts plain tail calls (em++ -O2 -> loop, shallow Asyncify stack).
   Each line closes whichever blocks it must leave, opens what it enters, and
   appends its (escaped / inline-rendered) content to [acc]. *)
Fixpoint md_block (ls : list string) (acc : string)
  (in_p in_ul in_ol in_quote in_code : bool) (fuel : nat) : string :=
  match fuel with
  | O => acc
  | S f' =>
      match ls with
      | nil => md_close_all acc in_p in_ul in_ol in_quote
      | l :: rest =>
          let t := trim l in
          if in_code then
            if md_fence t then
              md_block rest (cat acc "</code></pre>") false false false false false f'
            else
              md_block rest (cat acc (cat (escape_run l 0%int63 (PrimString.length l) f' "") lf))
                       false false false false true f'
          else if string_eqb t "" then
            md_block rest (md_close_all acc in_p in_ul in_ol in_quote)
                     false false false false false f'
          else if md_fence t then
            md_block rest (cat (md_close_all acc in_p in_ul in_ol in_quote) "<pre><code>")
                     false false false false true f'
          else
            let lvl := md_heading_level t in
            if ltb 0%int63 lvl then
              md_block rest
                (cat (md_close_all acc in_p in_ul in_ol in_quote)
                  (cat (md_hopen lvl)
                    (cat (md_inline_aux (md_heading_content t lvl) 0%int63 f' "")
                         (md_hclose lvl))))
                false false false false false f'
            else if md_is_hr t then
              md_block rest (cat (md_close_all acc in_p in_ul in_ol in_quote) "<hr>")
                       false false false false false f'
            else if md_is_quote t then
              let acc1 := md_close_p acc in_p in
              let acc2 := md_close_ul acc1 in_ul in
              let acc3 := md_close_ol acc2 in_ol in
              let acc4 := if in_quote then acc3 else cat acc3 "<blockquote><p>" in
              let acc5 := if in_quote then cat acc4 "</p><p>" else acc4 in
              md_block rest
                (cat acc5 (md_inline_aux (md_quote_content t) 0%int63 f' ""))
                false false false true false f'
            else if md_is_ul t then
              let acc1 := md_close_p acc in_p in
              let acc2 := md_close_ol acc1 in_ol in
              let acc3 := md_close_quote acc2 in_quote in
              let acc4 := if in_ul then acc3 else cat acc3 "<ul>" in
              md_block rest
                (cat acc4 (cat "<li>" (cat (md_inline_aux (md_list_body t) 0%int63 f' "") "</li>")))
                false true false false false f'
            else if md_is_ol t then
              let acc1 := md_close_p acc in_p in
              let acc2 := md_close_ul acc1 in_ul in
              let acc3 := md_close_quote acc2 in_quote in
              let acc4 := if in_ol then acc3 else cat acc3 "<ol>" in
              md_block rest
                (cat acc4 (cat "<li>" (cat (md_inline_aux (md_list_body t) 0%int63 f' "") "</li>")))
                false false true false false f'
            else (* plain paragraph line *)
              let acc1 := md_close_ul acc in_ul in
              let acc2 := md_close_ol acc1 in_ol in
              let acc3 := md_close_quote acc2 in_quote in
              let acc4 := if in_p then acc3 else cat acc3 "<p>" in
              let acc5 := if in_p then cat acc4 "<br>" else acc4 in
              md_block rest (cat acc5 (md_inline_aux t 0%int63 f' ""))
                       true false false false false f'
      end
  end.

Definition md_to_html (s : string) : string :=
  md_block (split_lines (strip_frontmatter s)) ""
           false false false false false mime_fuel.

(* ---- Attachment label ("Attachments: a, b, ...") ------------------- *)
Definition images_label (names : list string) : string :=
  cat "Attachments: " (join_comma names).
