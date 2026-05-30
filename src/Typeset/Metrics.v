(* Typeset/Metrics.v --- Trusted Latin font-metric table + text shaping.

   Milestone 2.  This is the TeX ".tfm" analogue: a TRUSTED table of
   per-glyph advance widths (in scaled points) and a small set of kern
   pairs, expressed as Coq data, plus a [string -> paragraph] function that
   turns text into the box/glue/penalty stream that KnuthPlass.v consumes.

   Per the plan (Part 2 sec 2.3): metrics/kerns/ligatures are TRUSTED DATA,
   not computed.  The table below is a REPRESENTATIVE Latin-1 subset; adding
   glyphs is purely adding rows to the width predicates / [kern_pairs] -- no
   algorithm changes.  Scope is Latin + common European punctuation; no
   Arabic/Indic shaping.

   Code points are kept as machine [int] (int63) -- the masked byte from
   PrimString.get -- so the byte stream maps directly to glyph ids and no
   nat<->int conversion is needed.  Widths are at a 10pt design size, in sp
   (1pt = 65536 sp), roughly Computer-Modern-roman; the exact numbers are
   immaterial to the algorithms, only that they are fixed integers. *)

From Stdlib Require Import ZArith List Bool.
From Corelib Require Import PrimString PrimInt63.
Require Import Typeset.Boxes.
Import ListNotations.

Open Scope Z_scope.
Open Scope pstring_scope.

(* ===================================================================== *)
(* Width classes (10pt design size, sp)                                   *)
(* ===================================================================== *)

Definition w_space    : sp := 218453.   (* interword natural ~ 1/3 em *)
Definition w_narrow   : sp := 181817.   (* i l j . , ; : ' ! ( ) ~ .28 em *)
Definition w_normal   : sp := 327680.   (* most lowercase ~ 1/2 em *)
Definition w_wide     : sp := 458752.   (* m w, uppercase ~ .7 em *)
Definition w_digit    : sp := 327680.   (* digits tabular ~ 1/2 em *)

(* ===================================================================== *)
(* Code-point constants (ASCII), as int63                                 *)
(* ===================================================================== *)

Definition cp_space : int := 32%int63.

(* int63 equality / ordering shorthands. *)
Definition ieqb := PrimInt63.eqb.
Definition ileb := PrimInt63.leb.
Definition iand := PrimInt63.land.
Definition iadd := PrimInt63.add.

(* Is [c] a narrow glyph (thin punctuation / i l j t f r)?  Code points:
   33=excl 34=dquote 39=apos 40=lparen 41=rparen 44=comma 46=period
   58=colon 59=semicolon 45=hyphen 105=i 108=l 106=j 116=t 102=f 114=r. *)
Definition is_narrow_cp (c : int) : bool :=
  ieqb c 33 || ieqb c 34 || ieqb c 39 ||
  ieqb c 40 || ieqb c 41 || ieqb c 44 ||
  ieqb c 46 || ieqb c 58 || ieqb c 59 ||
  ieqb c 45 ||
  ieqb c 105 || ieqb c 108 || ieqb c 106 ||
  ieqb c 116 || ieqb c 102 || ieqb c 114.

(* Is [c] a wide glyph?  109=m 119=w, or uppercase A-Z (65..90). *)
Definition is_wide_cp (c : int) : bool :=
  ieqb c 109 || ieqb c 119 ||
  (ileb 65 c && ileb c 90).

Definition is_digit_cp (c : int) : bool :=
  ileb 48 c && ileb c 57.

(* The advance width of a glyph by code point (TRUSTED table, total). *)
Definition advance_of (c : int) : sp :=
  if ieqb c cp_space then w_space
  else if is_narrow_cp c then w_narrow
  else if is_wide_cp c then w_wide
  else if is_digit_cp c then w_digit
  else w_normal.

(* ===================================================================== *)
(* Kern pairs (trusted)                                                   *)
(* ===================================================================== *)

(* (left, right, delta): when [left] is immediately followed by [right],
   add [delta] sp (usually negative).  Representative CM pairs.  Extending =
   adding rows. *)
Definition kern_pairs : list (int * int * sp) := [
  (65%int63, 86%int63, -65536); (65%int63, 87%int63, -65536); (65%int63, 89%int63, -65536);
  (86%int63, 65%int63, -65536); (87%int63, 65%int63, -65536); (89%int63, 65%int63, -65536);
  (84%int63, 111%int63, -54613); (84%int63, 101%int63, -54613); (84%int63, 97%int63, -54613);
  (102%int63, 105%int63, -10923);
  (111%int63, 118%int63, -10923); (111%int63, 119%int63, -10923)
].

(* Linear scan over the (small, fixed) kern table -- structural recursion. *)
Fixpoint kern_lookup (l r : int) (tbl : list (int * int * sp)) : sp :=
  match tbl with
  | [] => 0
  | (a, b, d) :: tl =>
      if ieqb a l && ieqb b r then d
      else kern_lookup l r tl
  end.

Definition kern_of (l r : int) : sp := kern_lookup l r kern_pairs.

(* ===================================================================== *)
(* Interword glue (trusted, cmr10)                                        *)
(* ===================================================================== *)

(* TeX cmr10 interword glue: 3.33pt natural, 1.67pt stretch, 1.11pt shrink,
   in sp (rounded to integers). *)
Definition interword : glue :=
  mkGlue 218453 109226 72818.

(* ===================================================================== *)
(* String -> paragraph (text shaping)                                     *)
(* ===================================================================== *)

(* Read the byte at [i] of [s] as a code point.  Mask with 255 because
   Crane realizes PrimString.get as a SIGNED char (the canonical signed-get
   gotcha): bytes >= 128 would otherwise arrive negative. *)
Definition cp_at (s : string) (i : int) : int :=
  iand (PrimString.get s i) 255%int63.

Definition is_space_byte (c : int) : bool := ieqb c cp_space.

(* Fuel bound: a paragraph never exceeds this many bytes for our purposes. *)
Definition shape_fuel : nat := 65536.

(* Sum advances (with kerns) of the word starting at [pos] up to the next
   space or end of string.  [prev] is the previous code point for kerning
   (sentinel 0 = NUL at word start kerns with nothing).  Split from
   glyph-collection so neither recursive fn returns a tuple (std::any trap). *)
Fixpoint word_width (s : string) (pos : int) (prev : int) (fuel : nat) : sp :=
  match fuel with
  | O => 0
  | S f =>
      if ileb (PrimString.length s) pos then 0
      else
        let c := cp_at s pos in
        if is_space_byte c then 0
        else
          advance_of c + kern_of prev c +
          word_width s (iadd pos 1%int63) c f
  end.

(* Collect glyph ids of the word starting at [pos]. *)
Fixpoint word_glyphs (s : string) (pos : int) (fuel : nat) : list glyph_id :=
  match fuel with
  | O => []
  | S f =>
      if ileb (PrimString.length s) pos then []
      else
        let c := cp_at s pos in
        if is_space_byte c then []
        else c :: word_glyphs s (iadd pos 1%int63) f
  end.

(* Advance [pos] to the end of the current word (first space or EOS). *)
Fixpoint skip_word (s : string) (pos : int) (fuel : nat) : int :=
  match fuel with
  | O => pos
  | S f =>
      if ileb (PrimString.length s) pos then pos
      else if is_space_byte (cp_at s pos) then pos
      else skip_word s (iadd pos 1%int63) f
  end.

(* Advance [pos] past a run of spaces. *)
Fixpoint skip_spaces (s : string) (pos : int) (fuel : nat) : int :=
  match fuel with
  | O => pos
  | S f =>
      if ileb (PrimString.length s) pos then pos
      else if is_space_byte (cp_at s pos) then skip_spaces s (iadd pos 1%int63) f
      else pos
  end.

(* The main shaper.  Alternates word-boxes and interword glue:
     box(word) , glue , box(word) , glue , ... , box(lastword)
   Leading/trailing space runs are collapsed.  Each word is one rigid box;
   intra-word breakpoints are added later by Hyphenation.v. *)
Fixpoint shape_aux (s : string) (pos : int) (fuel : nat) : paragraph :=
  match fuel with
  | O => []
  | S f =>
      if ileb (PrimString.length s) pos then []
      else if is_space_byte (cp_at s pos) then
        let pos' := skip_spaces s pos shape_fuel in
        if ileb (PrimString.length s) pos' then []
        else IGlue interword :: shape_aux s pos' f
      else
        let w  := word_width s pos 0%int63 shape_fuel in
        let gs := word_glyphs s pos shape_fuel in
        let pos' := skip_word s pos shape_fuel in
        IBox (mkBox w gs) :: shape_aux s pos' f
  end.

(* Public entry: text -> Knuth-Plass node list (strips a leading space run
   so the paragraph starts with a box). *)
Definition shape (s : string) : paragraph :=
  let p0 := skip_spaces s 0%int63 shape_fuel in
  shape_aux s p0 shape_fuel.

(* The Knuth-Plass paragraph terminator: a large-stretch glue then a forced
   break, so the final line is set ragged and the breaker always has a
   feasible last line.  [big_stretch] dwarfs any reasonable measure. *)
Definition big_stretch : sp := pt 100000.

Definition shape_paragraph (s : string) : paragraph :=
  shape s ++ [ par_finish_glue big_stretch ; forced_break ].
