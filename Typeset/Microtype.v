(* Typeset/Microtype.v --- Han The Thanh font expansion + char protrusion.

   Milestone 5.  The microtypographic extensions pdfTeX introduced (Thanh
   2000), expressed in fixed-point integer arithmetic over scaled points:

   (1) FONT EXPANSION: horizontally scaling glyph advances by a bounded
       permille factor (e.g. +-20 per-mille = +-2%) so a line can be made
       to fit its measure with less interword-glue distortion.  We model the
       expansion as an integer permille applied to box widths.

   (2) CHARACTER PROTRUSION (optical margin alignment): letting certain
       glyphs hang slightly into the margin (hyphens, punctuation, the round
       sides of o/c, etc.) so the visual edge of the column is straight.
       Per-glyph left/right protrusion amounts are TRUSTED DATA (a permille
       of the glyph's width), exactly like the metric/kern tables.

   Both feed back into the SAME box/glue model (Boxes.v): expansion adjusts a
   box's [bx_width]; protrusion is applied at line edges by the layout pass
   as a width credit.  All integer, deterministic, total. *)

From Stdlib Require Import ZArith List Bool Lia.
From Corelib Require Import PrimInt63.
Require Import Typeset.Boxes.
Require Import Typeset.Metrics.
Import ListNotations.

Open Scope Z_scope.

(* int63 eq shorthand. *)
Definition meqb := PrimInt63.eqb.

(* ===================================================================== *)
(* (1) Font expansion                                                     *)
(* ===================================================================== *)

(* Expansion is a signed permille (parts per 1000): +20 means stretch each
   glyph advance by 2%, -30 means shrink by 3%.  pdfTeX bounds this to a
   small range; we clamp to [-50, +50] (+-5%, generous). *)
Definition max_expansion : Z := 50.

Definition clamp_expansion (e : Z) : Z :=
  if Z.ltb e (- max_expansion) then - max_expansion
  else if Z.ltb max_expansion e then max_expansion
  else e.

(* Apply an expansion permille [e] to a width [w] (sp), exact integer:
   w' = w + w*e/1000.  Rounding is toward zero (truncating division), which
   is deterministic. *)
Definition expand_width (e : Z) (w : sp) : sp :=
  let e' := clamp_expansion e in
  w + Z.quot (w * e') 1000.

(* Expand every box in a paragraph by [e]; glue/penalties are untouched
   (interword glue carries its own stretch/shrink and is not "expanded").
   Structural map -> total. *)
Definition expand_item (e : Z) (it : item) : item :=
  match it with
  | IBox b => IBox (mkBox (expand_width e (bx_width b)) (bx_glyphs b))
  | _ => it
  end.

Definition expand_paragraph (e : Z) (p : paragraph) : paragraph :=
  map (expand_item e) p.

(* Monotonicity / bound facts used to argue expansion stays within +-5%:
   the clamped expansion never exceeds the bound in magnitude. *)
Lemma clamp_expansion_bounded :
  forall e, - max_expansion <= clamp_expansion e <= max_expansion.
Proof.
  intros e. unfold clamp_expansion, max_expansion in *.
  destruct (e <? -50) eqn:E1; destruct (50 <? e) eqn:E2;
  try apply Z.ltb_lt in E1; try apply Z.ltb_ge in E1;
  try apply Z.ltb_lt in E2; try apply Z.ltb_ge in E2;
  lia.
Qed.

(* Expanding by 0 is the identity on widths. *)
Lemma expand_width_zero : forall w, expand_width 0 w = w.
Proof.
  intros; unfold expand_width; change (clamp_expansion 0) with 0;
  rewrite Z.mul_0_r; reflexivity.
Qed.

(* ===================================================================== *)
(* (2) Character protrusion (optical margins)                             *)
(* ===================================================================== *)

(* Per-glyph protrusion, as a permille of the glyph's OWN advance, for the
   left and right edges.  TRUSTED DATA (a representative subset; extend by
   adding rows).  Positive = the glyph may hang that fraction of its width
   into the margin.  Classic values: hyphen ~70%, period/comma ~70%,
   'o'/'c'/'e' right side ~20-50, capital 'A' left ~50, 'T' ... etc. *)

(* (code_point, left_permille, right_permille). *)
Definition protrusion_table : list (int * Z * Z) := [
  (45%int63, 0, 700);    (* hyphen '-' : strong right protrusion *)
  (46%int63, 0, 700);    (* period '.' *)
  (44%int63, 0, 700);    (* comma ',' *)
  (59%int63, 0, 500);    (* semicolon *)
  (58%int63, 0, 500);    (* colon *)
  (111%int63, 20, 20);   (* 'o' both sides *)
  (99%int63, 40, 0);     (* 'c' left *)
  (101%int63, 0, 20);    (* 'e' right *)
  (65%int63, 50, 0);     (* 'A' left *)
  (84%int63, 0, 70);     (* 'T' right *)
  (87%int63, 0, 70);     (* 'W' right *)
  (86%int63, 0, 70)      (* 'V' right *)
].

(* Look up a glyph's (left,right) protrusion permille; default (0,0).  We
   return the two values via two single-value lookups to avoid a recursive
   function returning a tuple (std::any trap). *)
Fixpoint protr_left_lookup (c : int) (tbl : list (int * Z * Z)) : Z :=
  match tbl with
  | [] => 0
  | (g, l, _) :: tl => if meqb g c then l else protr_left_lookup c tl
  end.

Fixpoint protr_right_lookup (c : int) (tbl : list (int * Z * Z)) : Z :=
  match tbl with
  | [] => 0
  | (g, _, r) :: tl => if meqb g c then r else protr_right_lookup c tl
  end.

Definition protr_left  (c : int) : Z := protr_left_lookup  c protrusion_table.
Definition protr_right (c : int) : Z := protr_right_lookup c protrusion_table.

(* The protrusion WIDTH credit (sp) for a glyph at the right margin: the
   permille of its advance.  This is subtracted from the line's natural
   width when the glyph is the last on the line, letting it hang out. *)
Definition protr_right_sp (c : int) : sp :=
  (advance_of c * protr_right c) / 1000.

Definition protr_left_sp (c : int) : sp :=
  (advance_of c * protr_left c) / 1000.

(* Given the glyphs of the box ENDING a line, the right-margin credit is the
   protrusion of its last glyph.  Given the glyphs of the box STARTING a
   line, the left credit is the protrusion of its first glyph.  We expose
   helpers operating on a box's glyph list. *)
Fixpoint last_glyph (gs : list glyph_id) : option glyph_id :=
  match gs with
  | [] => None
  | g :: [] => Some g
  | _ :: t => last_glyph t
  end.

Definition first_glyph (gs : list glyph_id) : option glyph_id :=
  match gs with [] => None | g :: _ => Some g end.

Definition box_right_protrusion (b : box) : sp :=
  match last_glyph (bx_glyphs b) with
  | None => 0
  | Some g => protr_right_sp g
  end.

Definition box_left_protrusion (b : box) : sp :=
  match first_glyph (bx_glyphs b) with
  | None => 0
  | Some g => protr_left_sp g
  end.

(* ===================================================================== *)
(* Combined: an expansion+protrusion-aware effective line width            *)
(* ===================================================================== *)

(* The effective natural width of a line that, after expansion [e], spans
   boxes whose first/last boxes are [bl]/[br], is the expanded sum minus the
   left+right protrusion credits.  This is the quantity a microtype-aware
   KnuthPlass would feed into [badness_of] instead of the raw width.  We
   expose it so GlyphLayout / a future integrated breaker can use it; the
   integer arithmetic keeps determinism. *)
Definition effective_line_width
    (e : Z) (raw_width : sp) (bl br : box) : sp :=
  expand_width e raw_width
    - box_left_protrusion bl
    - box_right_protrusion br.

(* Sanity: with no expansion and no protrusion (empty glyph boxes), the
   effective width is the raw width. *)
Lemma effective_width_trivial :
  forall raw, effective_line_width 0 raw (mkBox raw []) (mkBox raw []) = raw.
Proof.
  intros; unfold effective_line_width, box_left_protrusion, box_right_protrusion;
  rewrite expand_width_zero; lia.
Qed.
