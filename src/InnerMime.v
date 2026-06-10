(* InnerMime.v — pure port of static/decrypt.ml's [extract_inner_text] and
   [body_to_html] (+ [strip_frontmatter]): given the decrypted inner MIME, pull
   out the Subject, the concatenated text body, and the attachment filenames,
   then render the body to escaped HTML for the decrypted reading view.

   Reuses StringLib.v (string primitives) and MimeLib.v / MimeBuild.v (header /
   body split, boundary extraction, multipart split, part-filename, terminator
   trim).  All helpers are top-level Definitions / Fixpoints with explicit
   return types to keep Crane's C++ free of std::any.

   T1 (privacy): the only sink for untrusted decrypted text is set_text_content;
   [body_to_html] HTML-escapes every metacharacter (ampersand, angle brackets,
   double-quote) so the single escaped-HTML sink (set_inner_html) can never
   inject markup. *)

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

(* ---- HTML escaping + paragraph conversion (port of body_to_html) --- *)
(* Escape one byte for HTML text context (amp, lt, gt, dquote); else verbatim. *)
Definition escape_byte (c : int) : string :=
  if int_eqb c ch_amp then "&amp;"
  else if int_eqb c ch_lt then "&lt;"
  else if int_eqb c ch_gt then "&gt;"
  else if int_eqb c ch_quote then "&quot;"
  else PrimString.make 1%int63 c.

(* Walk [s] from [pos], emitting escaped text; "\n\n" -> "</p><p>", a lone "\n"
   -> "<br>".  Top-level Fixpoint (params, single string return) to avoid
   std::any (no nested let fix, no tuple recursion). *)
(* AIDEV-NOTE: STACK-SAFETY TRAP (the "Maximum call stack size exceeded" crash).
   [body_to_html] runs on EVERY decrypt (render_decrypted, DecryptApp.v:342 —
   unconditionally; the max_canvas_body 4000-char guard only gates render_canvas).
   The previous shape recursed once per body byte with the recursive call as an
   ARGUMENT to [cat] (non-tail), so em++ -O2 could not TCO it and each byte cost
   one Asyncify frame — capped only by mime_fuel=65536 — overflowing the 32 MB
   WASM stack (the __emscripten_memcpy_js at the trace top is [cat]'s per-frame
   std::string copy; binary-confirmed: func[119] self-recursing at 0x2783a).
   ROCQ totality proved a normal form EXISTS, not that the native stack is
   bounded — the fuel that proves termination is exactly the frame count that
   overflowed.  Fix: tail-recursive [acc] (the call is now the whole RHS -> TCO
   to a loop -> O(1) stack).  We accumulate with [cat acc piece] (append RIGHT),
   so output order is preserved WITHOUT a finalising [rev]/[++] — important
   because Coq's [List.rev]/[app] extract to NON-tail O(n^2) C++ and would just
   relocate the overflow.  [PrimString.cat] is a primitive (O(1) stack). *)
Fixpoint body_to_html_aux (s : string) (pos : int) (fuel : nat) (acc : string) : string :=
  let n := PrimString.length s in
  match fuel with
  | O => acc
  | S f' =>
      if leb n pos then acc
      else
        let c := PrimString.get s pos in
        if int_eqb c ch_newline then
          if andb (ltb (add pos 1%int63) n)
                  (int_eqb (PrimString.get s (add pos 1%int63)) ch_newline)
          then body_to_html_aux s (add pos 2%int63) f' (cat acc "</p><p>")
          else body_to_html_aux s (add pos 1%int63) f' (cat acc "<br>")
        else
          body_to_html_aux s (add pos 1%int63) f' (cat acc (escape_byte c))
  end.

Definition body_to_html (s : string) : string :=
  let stripped := strip_frontmatter s in
  cat "<p>" (cat (body_to_html_aux stripped 0%int63 mime_fuel "") "</p>").

(* ---- Attachment label ("Attachments: a, b, ...") ------------------- *)
Definition images_label (names : list string) : string :=
  cat "Attachments: " (join_comma names).
