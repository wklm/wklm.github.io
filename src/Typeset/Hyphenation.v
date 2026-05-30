(* Typeset/Hyphenation.v --- Liang's competing-patterns hyphenation.

   Milestone 4.  Implements Frank Liang's 1983 algorithm (the one TeX uses):
   a set of "competing" patterns, each a short letter sequence interleaved
   with priority digits, anchored optionally to word boundaries.  For a
   given lower-cased word, every pattern that matches a substring deposits
   its digits at the corresponding inter-letter positions; at each position
   the MAXIMUM digit wins.  An ODD winning digit is a legal hyphen point;
   an EVEN one inhibits hyphenation there.

   The patterns are TRUSTED ROCQ DATA (a [.tex]-style hyphenation table),
   exactly like the metric table -- a representative subset; adding patterns
   is adding rows.  We recurse structurally over the word (bounded by its
   length) and over the fixed pattern list.

   The output is a list of zero-based inter-letter hyphen positions, which
   the box/glue builder turns into FLAGGED penalties (Boxes.flagged_penalty_of)
   that compose with KnuthPlass: a flagged discretionary break carries the
   hyphen-width box on the line that takes it, and two consecutive flagged
   breaks incur the double-hyphen demerit already modelled in
   [KnuthPlass.line_demerits]. *)

From Stdlib Require Import ZArith List Bool Uint63.
From Corelib Require Import PrimString PrimInt63.
Require Import Typeset.Boxes.
Import ListNotations.

Open Scope Z_scope.
Open Scope pstring_scope.

(* int63 shorthands (mirroring Metrics.v). *)
Definition heqb := PrimInt63.eqb.
Definition hleb := PrimInt63.leb.
Definition hand := PrimInt63.land.
Definition hadd := PrimInt63.add.

(* nat <-> int63 conversions.  We work with [nat] slot/position indices for
   the pattern competition (so [nth] into the value vectors is natural) and
   convert to [int] only for [PrimString.get]/[length] comparisons.  The
   word-bounded fuel keeps these total.  [int_of_nat] uses repeated
   increment (Crane realizes [add]); [nat_of_int] uses a fuel-bounded
   decrement like StringLib. *)
Fixpoint int_of_nat (n : nat) : int :=
  match n with O => 0%int63 | S k => hadd (int_of_nat k) 1%int63 end.

Fixpoint nat_of_int_fuel (i : int) (fuel : nat) : nat :=
  match fuel with
  | O => O
  | S f => if hleb i 0%int63 then O else S (nat_of_int_fuel (PrimInt63.sub i 1%int63) f)
  end.

(* ===================================================================== *)
(* Patterns                                                               *)
(* ===================================================================== *)

(* A Liang pattern is stored as:
     - [pat_anchor_l] : true if the pattern is anchored at word start (.)
     - [pat_anchor_r] : true if anchored at word end (.)
     - [pat_letters]  : the letter code points (lower-case ASCII), in order
     - [pat_values]   : priority digits at the (length+1) inter-letter slots
       i.e. value before letter 0, between 0 and 1, ..., after last letter.
   This is the standard "interleaved digits" form with the letters and the
   value vector separated so the data is flat (no parsing of digit-letters
   at runtime). *)
Record pattern : Set := mkPattern {
  pat_anchor_l : bool;
  pat_anchor_r : bool;
  pat_letters  : list int;   (* code points *)
  pat_values   : list nat    (* length = length pat_letters + 1 *)
}.

(* Code-point helpers for writing patterns readably. *)
Definition c_a : int := 97%int63.
Definition c_b : int := 98%int63.
Definition c_c : int := 99%int63.
Definition c_e : int := 101%int63.
Definition c_g : int := 103%int63.
Definition c_h : int := 104%int63.
Definition c_i : int := 105%int63.
Definition c_l : int := 108%int63.
Definition c_m : int := 109%int63.
Definition c_n : int := 110%int63.
Definition c_o : int := 111%int63.
Definition c_p : int := 112%int63.
Definition c_r : int := 114%int63.
Definition c_s : int := 115%int63.
Definition c_t : int := 116%int63.
Definition c_u : int := 117%int63.
Definition c_v : int := 118%int63.
Definition c_y : int := 121%int63.

(* A SMALL representative pattern set (a faithful subset of the English
   patterns Liang/TeX ship).  Each row is one [mkPattern].  Values follow
   TeX convention: digit appears just before the letter it precedes in the
   classic "3" / "1" notation; here as the inter-letter vector.

   Examples encoded:
     .in2     -> anchor-left, letters [i;n], values [0;0;2;0]
     1tion    -> letters [t;i;o;n], value 1 before 't': [1;0;0;0;0]
     2io      -> letters [i;o], values [0;0;0]  (inhibit between i,o via 2)
     be3gin   -> letters [b;e;g;i;n], value 3 between e,g
     y1l      -> letters [y;l], value 1 between
     1c2c     -> letters [c;c], values [1;2;0]
     hy3ph    -> letters [h;y;p;h], value 3 between y,p
     2l1l     -> letters [l;l], values [2;1;0]
   These suffice to hyphenate the demo words below; more patterns are more
   rows here. *)
Definition patterns : list pattern := [
  (* .in2  : encourage break after a leading "in" *)
  mkPattern true false [c_i; c_n] [0;0;2;0]%nat;
  (* be3gin : be-gin *)
  mkPattern false false [c_b; c_e; c_g; c_i; c_n] [0;0;0;3;0;0]%nat;
  (* hy3ph : hy-phen *)
  mkPattern false false [c_h; c_y; c_p; c_h] [0;0;0;3;0]%nat;
  (* 1tion : a hyphen may precede "tion" *)
  mkPattern false false [c_t; c_i; c_o; c_n] [1;0;0;0;0]%nat;
  (* 2io  : inhibit splitting "io" *)
  mkPattern false false [c_i; c_o] [0;0;2]%nat;
  (* y1l : example-y-l *)
  mkPattern false false [c_y; c_l] [0;1;0]%nat;
  (* 2l1l : prefer not to split between double-l, but allow after *)
  mkPattern false false [c_l; c_l] [0;2;1]%nat;
  (* com3pu : com-pu(ter) *)
  mkPattern false false [c_c; c_o; c_m; c_p; c_u] [0;0;0;3;0;0]%nat;
  (* o2v : keep o,v together *)
  mkPattern false false [c_o; c_v] [0;0;2]%nat;
  (* 1na : allow hyphen before "na" *)
  mkPattern false false [c_n; c_a] [1;0;0]%nat
].

(* ===================================================================== *)
(* Lower-case normalisation                                               *)
(* ===================================================================== *)

(* Map an ASCII code point to lower-case (A-Z -> a-z); leave others. *)
Definition to_lower (c : int) : int :=
  if andb (hleb 65 c) (hleb c 90) then hadd c 32%int63 else c.

(* Read the masked, lower-cased byte at position i. *)
Definition lc_at (w : string) (i : int) : int :=
  to_lower (hand (PrimString.get w i) 255%int63).

(* ===================================================================== *)
(* Matching one pattern at one word position                              *)
(* ===================================================================== *)

(* Does [pat_letters] match the word [w] starting at byte index [start]?
   Structural recursion on the letter list. *)
Fixpoint letters_match (w : string) (start : int) (ls : list int) : bool :=
  match ls with
  | [] => true
  | c :: rest =>
      if hleb (PrimString.length w) start then false
      else if heqb (lc_at w start) c
           then letters_match w (hadd start 1%int63) rest
           else false
  end.

(* A pattern matches at word position [start] (0-based byte index) when:
   its letters match there, AND its anchors are satisfied:
     anchor_l => start = 0
     anchor_r => the letters end exactly at the word end. *)
Definition pattern_matches (w : string) (start : int) (p : pattern) : bool :=
  let n := List.length (pat_letters p) in
  let endpos := hadd start (int_of_nat n) in
  andb (letters_match w start (pat_letters p))
  (andb (if pat_anchor_l p then heqb start 0%int63 else true)
        (if pat_anchor_r p then heqb endpos (PrimString.length w) else true)).

(* ===================================================================== *)
(* The competition: max digit per inter-letter slot                       *)
(* ===================================================================== *)

(* We compute, for each inter-letter slot [k] in [0 .. length w], the
   maximum value contributed by ANY pattern matching at ANY start position.
   A pattern matching at [start] contributes [pat_values] indexed so that
   its slot j lands at word slot (start + j).

   To keep extraction flat (no nested fix returning lists/tuples), we
   compute the winning value at a single slot [k] by folding the pattern
   list and, within each pattern, all start positions in [0..k].  The
   per-pattern contribution at slot [k] is: for each start s with
   s <= k <= s + len(p), the value at index (k - s). *)

(* nth value of a pattern's value vector, default 0. *)
Definition pat_val_at (p : pattern) (j : nat) : nat := nth j (pat_values p) 0%nat.

(* Contribution of pattern [p] to word-slot [k] when matched at start [s]. *)
Definition contrib_at (w : string) (p : pattern) (s : nat) (k : nat) : nat :=
  if pattern_matches w (int_of_nat s) p
  then if andb (Nat.leb s k) (Nat.leb (k - s) (List.length (pat_letters p)))
       then pat_val_at p (k - s)
       else 0%nat
  else 0%nat.

(* Max over all start positions s in [0..wlen] of contrib_at, for one
   pattern.  Structural recursion on a [starts] list we precompute. *)
Fixpoint max_over_starts (w : string) (p : pattern) (k : nat) (starts : list nat) : nat :=
  match starts with
  | [] => 0%nat
  | s :: rest => Nat.max (contrib_at w p s k) (max_over_starts w p k rest)
  end.

(* Max over all patterns. *)
Fixpoint max_over_patterns (w : string) (k : nat) (ps : list pattern) (starts : list nat) : nat :=
  match ps with
  | [] => 0%nat
  | p :: rest => Nat.max (max_over_starts w p k starts) (max_over_patterns w k rest starts)
  end.

(* [seq 0 (n+1)] of candidate start positions / slots. *)
Definition upto (n : nat) : list nat := seq 0 (S n).

(* The winning value at word-slot [k]. *)
Definition slot_value (w : string) (wlen : nat) (k : nat) : nat :=
  max_over_patterns w k patterns (upto wlen).

(* ===================================================================== *)
(* Legal hyphen positions                                                 *)
(* ===================================================================== *)

(* \lefthyphenmin / \righthyphenmin : no hyphen within this many letters of
   either word edge (TeX defaults 2 and 3). *)
Definition left_min  : nat := 2.
Definition right_min : nat := 3.

(* A slot [k] (the gap BEFORE letter index k, k in 1..wlen-1) is a legal
   hyphen point iff its winning value is ODD and it respects the edge
   minima. *)
Definition is_hyphen_slot (w : string) (wlen : nat) (k : nat) : bool :=
  andb (Nat.odd (slot_value w wlen k))
  (andb (Nat.leb left_min k) (Nat.leb (k + right_min) wlen)).

(* Word length as a nat (bounded scan).  A word never exceeds this fuel. *)
Definition hyphen_fuel : nat := 1024.
Definition word_len_nat (w : string) : nat :=
  nat_of_int_fuel (PrimString.length w) hyphen_fuel.

(* Collect all legal hyphen slots of a word, ascending.  Structural
   recursion over the candidate slot list. *)
Definition hyphenate_word (w : string) : list nat :=
  let wlen := word_len_nat w in
  filter (fun k => is_hyphen_slot w wlen k) (seq 1 (Nat.pred wlen)).

(* ===================================================================== *)
(* Integration with the box model                                         *)
(* ===================================================================== *)

(* The TeX hyphen-char width at 10pt (cmr10 '-' is ~ 0.333em). *)
Definition hyphen_width : sp := 218453.

(* A discretionary break: a FLAGGED penalty whose cost is the hyphen
   penalty (TeX \hyphenpenalty = 50).  The hyphen glyph that would appear
   at end-of-line is modelled by the breaker adding [hyphen_width] when this
   break is taken; here we expose both the penalty and the width so the
   integrator (GlyphLayout / a future box-splitter) can place them. *)
Definition hyphen_penalty_val : Z := 50.

Definition disc_break : item := flagged_penalty_of hyphen_penalty_val.

(* Given a word's glyph ids and its hyphen slots, splice flagged penalties
   into the glyph run, producing the item list for that word: a sequence of
   sub-boxes separated by discretionary (flagged) penalties.  The per-glyph
   advance widths must be supplied (from Metrics.advance_of) so each
   sub-box carries the right width.

   We keep this as a structural recursion over the glyph list, tracking the
   current slot index; when the current boundary is a hyphen slot we emit a
   [disc_break] between the sub-boxes.  To avoid a recursive function
   returning a tuple, the caller pre-pairs each glyph with its advance. *)

(* Is inter-glyph slot [k] in the hyphen list? *)
Definition slot_in (k : nat) (hs : list nat) : bool :=
  existsb (Nat.eqb k) hs.

(* Build items for a word given (glyph, advance) pairs and hyphen slots.
   [k] is the index of the gap BEFORE the next glyph.  We accumulate each
   glyph into a singleton box and insert [disc_break] at hyphen slots.  This
   is the simplest faithful encoding (one box per glyph); a later pass may
   coalesce adjacent boxes for fewer draw calls. *)
Fixpoint word_items_aux (gas : list (glyph_id * sp)) (k : nat) (hs : list nat)
  : paragraph :=
  match gas with
  | [] => []
  | (g, a) :: rest =>
      let this_box := box_of a [g] in
      match rest with
      | [] => [this_box]
      | _ =>
          if slot_in k hs
          then this_box :: disc_break :: word_items_aux rest (S k) hs
          else this_box :: word_items_aux rest (S k) hs
      end
  end.

Definition word_items (gas : list (glyph_id * sp)) (hs : list nat) : paragraph :=
  word_items_aux gas 1 hs.
