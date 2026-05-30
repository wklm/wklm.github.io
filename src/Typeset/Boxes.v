(* Typeset/Boxes.v --- The box / glue / penalty model (Knuth-Plass).

   This is milestone 1 of the Verified Reader typesetter: the data model
   that every later stage (Metrics, KnuthPlass, Hyphenation, Microtype,
   GlyphLayout) consumes and produces.

   DESIGN NOTES (see plan Part 2, sec 2.3-2.4):
   - Fixed-point integers ONLY.  Horizontal dimensions are TeX "scaled
     points" (sp = 2^-16 pt), represented as Coq [Z].  No floats: floats
     extract under Crane but their proofs are axiom-bound, and we want T6/T7
     to be real theorems.  All arithmetic here is exact integer arithmetic.
   - A paragraph is a [list item]: a flat sequence of boxes, glue and
     penalties, exactly as in Knuth & Plass 1981.  Keeping it a flat list
     (rather than a tree) matches Crane's young recursion support: every
     consumer folds over a fixed list.
   - Records are kept field-flat (all fields [Z]/[bool]/[nat]) so Crane
     emits a plain C++ struct, never [std::any].

   Latin + European punctuation/diacritics scope only: shaping is NOT
   modelled here; a [box] is an already-shaped rigid run whose width is
   trusted data from [Metrics.v]. *)

From Stdlib Require Import ZArith List Bool.
From Corelib Require Import PrimInt63.
Import ListNotations.

Open Scope Z_scope.

(* ===================================================================== *)
(* Scaled points                                                          *)
(* ===================================================================== *)

(* A horizontal/vertical dimension in scaled points (sp = 2^-16 pt).
   65536 sp = 1 pt.  We keep this a transparent alias of [Z] so the
   arithmetic lemmas in [ZArith] apply directly and Crane extracts it
   as its native integer type. *)
Definition sp := Z.

(* One typographic point, in sp. *)
Definition pt_unit : sp := 65536.

(* Convert an integer number of points to sp (exact). *)
Definition pt (n : Z) : sp := n * pt_unit.

(* ===================================================================== *)
(* Glyph references                                                       *)
(* ===================================================================== *)

(* A glyph is referenced by an index into the trusted MSDF atlas / metric
   table (see Metrics.v, GlyphLayout.v).  The width is carried separately
   in the [box] so the line-breaker never needs the atlas.  We use [int]
   (machine int63 = Crane's native C++ integer) rather than [nat] so glyph
   ids and downstream quad coordinates extract to plain ints, and so the
   shaper can use it directly from a masked [PrimString.get]. *)
Definition glyph_id := int.

(* ===================================================================== *)
(* The three node kinds                                                   *)
(* ===================================================================== *)

(* A BOX is a rigid, unbreakable run of set material with a fixed natural
   width.  [bx_glyphs] records which glyphs it draws (used downstream by
   GlyphLayout.v); the line-breaker only consumes [bx_width]. *)
Record box : Set := mkBox {
  bx_width  : sp;           (* natural advance width, sp *)
  bx_glyphs : list glyph_id (* glyphs composing this box, in order *)
}.

(* A GLUE is stretchable/shrinkable white space.  Stretch and shrink are
   non-negative magnitudes (sp); the natural width may be any sign but is
   normally >= 0.  We model only finite (order-0) stretch/shrink, which is
   all interword/interletter spacing needs for justified Latin text; we do
   NOT model TeX's infinite glue orders (fil/fill) because the reader never
   uses centered/ragged display math.  This keeps badness a total integer
   function (see KnuthPlass.v). *)
Record glue : Set := mkGlue {
  gl_width   : sp;   (* natural width, sp *)
  gl_stretch : sp;   (* additional stretchability (>= 0), sp *)
  gl_shrink  : sp    (* available shrinkability (>= 0), sp *)
}.

(* A PENALTY marks a legal, forced, or forbidden breakpoint and the
   aesthetic cost of breaking there.

   - [pn_penalty]: the break cost.  A break is FORBIDDEN at +inf-class
     penalties and FORCED at -inf-class penalties; we encode those classes
     with the predicates below rather than a literal infinity so all
     arithmetic stays in [Z].
   - [pn_flagged]: a flagged penalty (e.g. a discretionary hyphen).  Two
     consecutive flagged breaks incur an extra demerit (Knuth-Plass
     "double hyphen" penalty), composed in KnuthPlass.v. *)
Record penalty : Set := mkPenalty {
  pn_penalty : Z;     (* break cost (may be negative to encourage a break) *)
  pn_flagged : bool   (* flagged break (hyphen-like) *)
}.

(* The infinity threshold.  Any penalty >= [inf_penalty] forbids breaking;
   any penalty <= -[inf_penalty] forces a break.  10000 is TeX's value. *)
Definition inf_penalty : Z := 10000.

Definition penalty_forbidden (p : penalty) : bool :=
  Z.leb inf_penalty (pn_penalty p).

Definition penalty_forced (p : penalty) : bool :=
  Z.leb (pn_penalty p) (- inf_penalty).

(* ===================================================================== *)
(* Items                                                                  *)
(* ===================================================================== *)

(* A paragraph item is exactly one of the three node kinds.  This is the
   canonical Knuth-Plass node list.  We use a tagged inductive (not a
   record sum) so pattern matches extract to a C++ [switch]; the payload
   of each constructor is a single flat record, never a tuple, to dodge
   the "recursive function returning tuples => std::any" trap. *)
Inductive item : Set :=
  | IBox     : box     -> item
  | IGlue    : glue    -> item
  | IPenalty : penalty -> item.

Definition paragraph := list item.

(* ===================================================================== *)
(* Smart constructors                                                     *)
(* ===================================================================== *)

(* Rigid box from a width and its glyphs. *)
Definition box_of (w : sp) (gs : list glyph_id) : item :=
  IBox (mkBox w gs).

(* Ordinary interword glue.  TeX's default is ~ 1/3 em natural, 1/6 em
   stretch, 1/9 em shrink, but the caller supplies concrete sp so this
   stays data-driven from Metrics.v. *)
Definition glue_of (w st sh : sp) : item :=
  IGlue (mkGlue w st sh).

(* A finite optional breakpoint with a given cost, unflagged. *)
Definition penalty_of (p : Z) : item :=
  IPenalty (mkPenalty p false).

(* A flagged optional breakpoint (used by Hyphenation.v at hyphen points). *)
Definition flagged_penalty_of (p : Z) : item :=
  IPenalty (mkPenalty p true).

(* A forced break (end of a display line / explicit newline). *)
Definition forced_break : item :=
  IPenalty (mkPenalty (- inf_penalty) false).

(* A forbidden break (glue that must not break, e.g. a non-breaking
   space is a box-glue-box around a +inf penalty). *)
Definition forbidden_break : item :=
  IPenalty (mkPenalty inf_penalty false).

(* The mandatory finishing penalty Knuth-Plass appends to every paragraph:
   infinite-stretch glue then a forced break, so the last line is set
   ragged-right.  We expose the forced break here; the trailing glue is
   added by the caller in KnuthPlass.v with a large (finite) stretch. *)
Definition par_finish_glue (big_stretch : sp) : item :=
  IGlue (mkGlue 0 big_stretch 0).

(* ===================================================================== *)
(* Width / stretch / shrink accumulation                                  *)
(* ===================================================================== *)

(* The natural width contribution of a single item to a running line.
   Penalties contribute zero width unless a break is taken there (then the
   penalty's own width, which we model as zero, is irrelevant). *)
Definition item_width (it : item) : sp :=
  match it with
  | IBox b     => bx_width b
  | IGlue g    => gl_width g
  | IPenalty _ => 0
  end.

Definition item_stretch (it : item) : sp :=
  match it with
  | IGlue g    => gl_stretch g
  | _          => 0
  end.

Definition item_shrink (it : item) : sp :=
  match it with
  | IGlue g    => gl_shrink g
  | _          => 0
  end.

(* Fold a (sub)list of items into its total natural width, stretch and
   shrink.  These are the three quantities the line-breaker needs to size
   a candidate line; computing them as a left fold keeps Crane extraction
   flat (no nested recursion).

   CRANE-EXTRACTION NOTE: we deliberately do NOT reuse [item_width] etc. as
   the fold body here.  A standalone [item_width : item -> sp] gets attached
   by Crane as a METHOD on the [item] inductive's C++ struct, and is then
   re-emitted once per importing module (Boxes, Metrics, ...), producing a
   "class member cannot be redeclared" error in the native compile.  By
   inlining the match into each fold lambda, no method is attached and the
   struct is emitted once.  [item_width]/[item_stretch]/[item_shrink] below
   are kept ONLY for the proof layer (they are not referenced by any
   extracted entry point, so Crane never emits them). *)
Definition total_width   (p : paragraph) : sp :=
  fold_left (fun acc it =>
    acc + match it with IBox b => bx_width b | IGlue g => gl_width g | IPenalty _ => 0 end)
    p 0.
Definition total_stretch (p : paragraph) : sp :=
  fold_left (fun acc it =>
    acc + match it with IGlue g => gl_stretch g | _ => 0 end)
    p 0.
Definition total_shrink  (p : paragraph) : sp :=
  fold_left (fun acc it =>
    acc + match it with IGlue g => gl_shrink g | _ => 0 end)
    p 0.

(* ===================================================================== *)
(* Basic algebraic facts (used by KnuthPlass.v T6/T7)                     *)
(* ===================================================================== *)

(* Width of the empty paragraph is zero. *)
Lemma total_width_nil : total_width [] = 0.
Proof. reflexivity. Qed.

(* A general fold accumulator lemma: folding [f] from a start [a] equals
   [a] plus folding from 0.  This is the standard "fold_left is additive"
   fact, proved by induction with the accumulator generalised. *)
Lemma fold_left_add_start :
  forall (p : paragraph) (f : item -> sp) (a : Z),
    fold_left (fun acc it => acc + f it) p a
    = a + fold_left (fun acc it => acc + f it) p 0.
Proof.
  induction p as [| it p IH]; intros f a; simpl.
  - now rewrite Z.add_0_r.
  - rewrite (IH f (a + f it)), (IH f (f it)).
    now rewrite Z.add_assoc.
Qed.

(* Total width is additive over concatenation: width(p ++ q) =
   width(p) + width(q).  KnuthPlass uses this to size a line [i..j] as a
   difference of prefix sums. *)
Lemma total_width_app :
  forall p q, total_width (p ++ q) = total_width p + total_width q.
Proof.
  intros p q. unfold total_width.
  rewrite fold_left_app.
  now rewrite (fold_left_add_start q
    (fun it => match it with IBox b => bx_width b | IGlue g => gl_width g | IPenalty _ => 0 end)
    (fold_left _ p 0)).
Qed.

Lemma total_stretch_app :
  forall p q, total_stretch (p ++ q) = total_stretch p + total_stretch q.
Proof.
  intros p q. unfold total_stretch.
  rewrite fold_left_app.
  now rewrite (fold_left_add_start q
    (fun it => match it with IGlue g => gl_stretch g | _ => 0 end)
    (fold_left _ p 0)).
Qed.

Lemma total_shrink_app :
  forall p q, total_shrink (p ++ q) = total_shrink p + total_shrink q.
Proof.
  intros p q. unfold total_shrink.
  rewrite fold_left_app.
  now rewrite (fold_left_add_start q
    (fun it => match it with IGlue g => gl_shrink g | _ => 0 end)
    (fold_left _ p 0)).
Qed.

(* Stretch and shrink are non-negative whenever every glue's are.  We state
   the per-item facts; the list-level versions follow by induction in
   KnuthPlass.v where they are needed for the badness sign argument. *)
Definition glue_wellformed (g : glue) : Prop :=
  0 <= gl_stretch g /\ 0 <= gl_shrink g.

Definition item_wellformed (it : item) : Prop :=
  match it with
  | IGlue g => glue_wellformed g
  | _       => True
  end.

Definition paragraph_wellformed (p : paragraph) : Prop :=
  Forall item_wellformed p.

Lemma item_stretch_nonneg :
  forall it, item_wellformed it -> 0 <= item_stretch it.
Proof.
  intros [b|g|pn]; simpl; try (intros; apply Z.le_refl).
  intros [Hst _]; exact Hst.
Qed.

Lemma item_shrink_nonneg :
  forall it, item_wellformed it -> 0 <= item_shrink it.
Proof.
  intros [b|g|pn]; simpl; try (intros; apply Z.le_refl).
  intros [_ Hsh]; exact Hsh.
Qed.
