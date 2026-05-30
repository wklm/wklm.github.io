(* PostBuild.v — pure markdown + frontmatter assembly and slug derivation for
   the SMTP listener.  Mirrors smtp/listener.py's [_slug_from_subject] and
   [_build_md].

   slug(subject, ts):
     lower-case the subject; replace every maximal run of non-[a-z0-9] with a
     single '-'; strip leading/trailing '-'; if the result is empty OR longer
     than 64 chars, use [ts]; finally truncate to 64.

   build_md(author, subject, body, date, public_keys, author_kid):
     ---\n title: <subject>\n slug: <slug>\n author: <author>\n date: <date>\n
     [public-keys: <pk or author_kid>\n] ---\n\n <body> (+\n iff body lacks a
     trailing newline). *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.
Require Import MimeBuild.    (* lf, concat_all *)
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* ---- slug derivation ----------------------------------------------- *)

Definition is_slug_char (c : int) : bool :=
  orb (andb (leb 97%int63 c) (leb c 122%int63))   (* a-z *)
      (andb (leb 48%int63 c) (leb c 57%int63)).    (* 0-9 *)

(* Lower-case then map runs of non-slug chars to a single '-'.  [prev_dash]
   tracks whether the last emitted char was '-' so runs collapse.  Leading
   '-' is suppressed by starting prev_dash=true. *)
Fixpoint slugify_aux (s : string) (pos : int) (prev_dash : bool) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then ""
      else
        let c0 := PrimString.get s pos in
        let c := if andb (leb 65%int63 c0) (leb c0 90%int63) then add c0 32%int63 else c0 in
        if is_slug_char c then
          cat (PrimString.make 1%int63 c) (slugify_aux s (add pos 1%int63) false f')
        else if prev_dash then
          slugify_aux s (add pos 1%int63) true f'
        else
          cat (PrimString.make 1%int63 45%int63) (* '-' *)
              (slugify_aux s (add pos 1%int63) true f')
  end.

(* Strip a single trailing '-' (runs were already collapsed so at most one). *)
Definition strip_trailing_dash (s : string) : string :=
  let n := PrimString.length s in
  if andb (leb 1%int63 n) (int_eqb (PrimString.get s (sub n 1%int63)) 45%int63)
  then PrimString.sub s 0%int63 (sub n 1%int63)
  else s.

Definition truncate64 (s : string) : string :=
  let n := PrimString.length s in
  if leb n 64%int63 then s else PrimString.sub s 0%int63 64%int63.

Definition slug_from_subject (subject ts : string) : string :=
  let core := strip_trailing_dash (slugify_aux subject 0%int63 true mime_fuel) in
  let chosen :=
    if orb (is_empty core) (ltb 64%int63 (PrimString.length core)) then ts else core in
  truncate64 chosen.

(* ---- frontmatter assembly ------------------------------------------ *)

Definition fm_line (k v : string) : string :=
  cat k (cat ": " (cat v lf)).

(* Choose the public-keys value: the email/env public_keys if non-empty, else
   the author key id if non-empty, else omit the line entirely. *)
Definition public_keys_line (public_keys author_kid : string) : string :=
  if negb (is_empty public_keys) then fm_line "public-keys" public_keys
  else if negb (is_empty author_kid) then fm_line "public-keys" author_kid
  else "".

(* Append a trailing LF iff [body] does not already end in one. *)
Definition ensure_trailing_lf (body : string) : string :=
  let n := PrimString.length body in
  if leb n 0%int63 then cat body lf
  else if int_eqb (PrimString.get body (sub n 1%int63)) ch_newline then body
  else cat body lf.

Definition build_md (author subject body date public_keys author_kid slug : string)
                    : string :=
  concat_all (
    "---" :: lf ::
    fm_line "title" subject ::
    fm_line "slug" slug ::
    fm_line "author" author ::
    fm_line "date" date ::
    public_keys_line public_keys author_kid ::
    "---" :: lf :: lf ::
    ensure_trailing_lf body :: nil).
