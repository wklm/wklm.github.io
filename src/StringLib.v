(* StringLib.v — Consolidated string primitives.
   Single source of truth for character constants, string operations,
   hex encoding, and trim functions shared across the FormalBlog theory.

   This file is imported by Logic.v, CryptoSpec.v, Decrypt.v, and
   future MimeLib.v / HpkeEnvelope.v.  It avoids Crane extraction
   directives; Crane overrides live in Logic.v. *)

From Corelib Require Import PrimString PrimInt63.
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* ---- Character constants ------------------------------------------- *)

Notation ch_tab      :=  9%int63.
Notation ch_newline  := 10%int63.
Notation ch_cr       := 13%int63.
Notation ch_space    := 32%int63.
Notation ch_quote    := 34%int63.
Notation ch_amp      := 38%int63.
Notation ch_apos     := 39%int63.
Notation ch_comma    := 44%int63.
Notation ch_dot      := 46%int63.
Notation ch_slash    := 47%int63.
Notation ch_semicolon:= 59%int63.
Notation ch_colon    := 58%int63.
Notation ch_lt       := 60%int63.
Notation ch_gt       := 62%int63.
Notation ch_dquote   := 34%int63.
Notation ch_0        := 48%int63.
Notation ch_9        := 57%int63.

(* ---- Fuel bounds --------------------------------------------------- *)

Notation scanner_fuel := 2000000%nat.
Notation mime_fuel    := 65536%nat.
Notation lookup_fuel  := 2048%nat.

(* Sentinel returned when fuel is exhausted.  Empty string "" is a
   valid result for empty plaintext/headers; this sentinel ensures
   callers can distinguish exhaustion from legitimate empty output. *)
Definition fuel_exhausted : string := "__FUEL_EXHAUSTED__".

(* ---- Basic primitives ---------------------------------------------- *)

Definition int_eqb (a b : int) : bool := eqb a b.

Definition is_empty (s : string) : bool :=
  leb (PrimString.length s) 0%int63.

Definition cat (a b : string) : string :=
  PrimString.cat a b.

Definition emptyb (s : string) : bool :=
  leb (PrimString.length s) 0%int63.

(* ---- String equality / comparison ---------------------------------- *)

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
  let pref_len :=
    let fix go(i : int) (f : nat) : nat :=
      match f with
      | O => O
      | S f' =>
          if leb (PrimString.length pref) i then O
          else S (go (add i 1%int63) f')
      end
    in go 0%int63 scanner_fuel
  in
  starts_with_aux s pref 0%int63 pref_len.

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

Fixpoint nat_of_int_fuel (i : int) (remaining : nat) : nat :=
  match remaining with
  | O => O
  | S remaining' =>
      if leb i 0%int63 then O
      else S (nat_of_int_fuel (sub i 1%int63) remaining')
  end.

Definition nat_of_len (s : string) : nat :=
  nat_of_int_fuel (PrimString.length s) scanner_fuel.

Definition string_eqb (a b : string) : bool :=
  if int_eqb (PrimString.length a) (PrimString.length b)
  then string_eqb_aux a b 0%int63 (nat_of_len a)
  else false.

(* ---- Split on character (line breaking) ---------------------------- *)

Fixpoint split_on_char_fuel (s : string) (ch : int) (pos : int) (f : nat) : list string :=
  match f with
  | O => []
  | S f' =>
      let len := PrimString.length s in
      if leb len pos then []
      else
        let nl := find_char s ch pos mime_fuel in
        let piece := PrimString.sub s pos (sub nl pos) in
        if leb len nl then piece :: []
        else piece :: split_on_char_fuel s ch (add nl 1%int63) f'
  end.

Definition split_lines (s : string) : list string :=
  split_on_char_fuel s ch_newline 0%int63 mime_fuel.

(* ---- Trimming ------------------------------------------------------ *)

Definition substring_from (s : string) (start : int) : string :=
  PrimString.sub s start (sub (PrimString.length s) start).

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
  trim_left_from s 0%int63 scanner_fuel.

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
  reverse_string_acc s "" 0%int63 scanner_fuel.

Definition trim_right (s : string) : string :=
  reverse_string (trim_left (reverse_string s)).

Definition trim (s : string) : string :=
  trim_right (trim_left s).

Definition trim_trailing_cr (s : string) : string :=
  let n := PrimString.length s in
  if andb (leb 1%int63 n)
          (int_eqb (PrimString.get s (sub n 1%int63)) ch_cr)
  then PrimString.sub s 0%int63 (sub n 1%int63)
  else s.

(* ---- Hexadecimal encoding (for key display) ------------------------ *)

Definition hex_chars : string := "0123456789abcdef".

(* Mask the input to a byte first: Crane realizes PrimString.get as signed
   char, so bytes >= 128 arrive negative; an unmasked [lsr b 4] then produces
   a negative/huge index into the 16-byte [hex_chars], crashing substr.
   (crane-extraction-gotchas: "Signed PrimString.get -> mask land 255".) *)
Definition byte_to_hex (b0 : int) : string :=
  let b := land b0 255%int63 in
  let hi := lsr b 4%int63 in
  let lo := land b 15%int63 in
  cat (PrimString.sub hex_chars hi 1%int63)
      (PrimString.sub hex_chars lo 1%int63).

Fixpoint hex_encode_aux (s : string) (pos : int) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f =>
    if leb (PrimString.length s) pos then ""
    else cat (byte_to_hex (PrimString.get s pos))
             (hex_encode_aux s (add pos 1%int63) f)
  end.

Definition hex_encode (s : string) : string :=
  hex_encode_aux s 0%int63 mime_fuel.

(* ---- ASCII case folding -------------------------------------------- *)
(* Used by the SMTP state machine (verb upcasing, address/header lowercasing).
   ASCII-only; non-letters pass through unchanged. *)

Definition up_byte (c : int) : int :=
  if andb (leb 97%int63 c) (leb c 122%int63) then sub c 32%int63 else c.

Definition down_byte (c : int) : int :=
  if andb (leb 65%int63 c) (leb c 90%int63) then add c 32%int63 else c.

Fixpoint upcase_aux (s : string) (pos : int) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f' =>
      if leb (PrimString.length s) pos then ""
      else cat (PrimString.make 1%int63 (up_byte (PrimString.get s pos)))
               (upcase_aux s (add pos 1%int63) f')
  end.
Definition upcase (s : string) : string := upcase_aux s 0%int63 mime_fuel.

Fixpoint downcase_aux (s : string) (pos : int) (fuel : nat) : string :=
  match fuel with
  | O => ""
  | S f' =>
      if leb (PrimString.length s) pos then ""
      else cat (PrimString.make 1%int63 (down_byte (PrimString.get s pos)))
               (downcase_aux s (add pos 1%int63) f')
  end.
Definition downcase (s : string) : string := downcase_aux s 0%int63 mime_fuel.
