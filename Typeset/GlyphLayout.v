(* Typeset/GlyphLayout.v --- broken+justified paragraph -> integer quad buffer.

   Milestone 6.  Takes the output of the Knuth-Plass breaker and the shaped
   node list and produces a flat buffer of integer glyph QUADS:

       quad = (x, y, uv)   -- pen x/y in sp, atlas UV index (= glyph id)

   ready to hand to a single GPU draw call.  The actual MSDF atlas and the
   [draw_glyph_quads] FFI (catalog entry C13) are a LATER WASM-integration
   step; here we only build the integer buffer (pure ROCQ, no FFI).

   JUSTIFICATION: for each line we compute the adjustment needed to fill the
   measure and distribute it across the line's glue in proportion to each
   glue's stretch (when short) or shrink (when long), in integer sp.  The
   baseline y advances by a fixed leading per line (baseline grid).  All
   arithmetic is integer and total. *)

From Stdlib Require Import ZArith List Bool.
From Corelib Require Import PrimInt63.
Require Import Typeset.Boxes.
Require Import Typeset.KnuthPlass.
Import ListNotations.

Open Scope Z_scope.

(* ===================================================================== *)
(* Quad buffer                                                            *)
(* ===================================================================== *)

(* One glyph quad.  [q_uv] indexes the MSDF atlas; we use the glyph id
   directly (the atlas is laid out by glyph id offline -- catalog C12).
   Positions are in sp; the FFI/shader scales sp->pixels. *)
Record quad : Set := mkQuad {
  q_x  : sp;        (* pen x at the glyph origin, sp *)
  q_y  : sp;        (* baseline y, sp (increasing downward) *)
  q_uv : glyph_id   (* atlas index *)
}.

Definition quad_buffer := list quad.

(* ===================================================================== *)
(* Line geometry                                                          *)
(* ===================================================================== *)

(* Baseline-grid leading (distance between successive baselines), sp.
   1.35 * 10pt = 13.5pt = 884736 sp (the reading-science default 1.3-1.4x
   from the plan sec 2.5). *)
Definition leading : sp := 884736.

(* Top margin / first baseline offset, sp (one leading down). *)
Definition top_baseline : sp := leading.

(* The y baseline for line number [ln] (0-based). *)
Definition baseline_y (ln : nat) : sp := top_baseline + (Z.of_nat ln) * leading.

(* ===================================================================== *)
(* Glue setting (justification)                                           *)
(* ===================================================================== *)

(* For a line with natural width [w], total stretch [y], total shrink [z],
   target [W], the set width of a glue with natural [gw], stretch [gst],
   shrink [gsh] is:
     if w < W (stretch): gw + gst * (W - w) / y          (y > 0)
     if w > W (shrink) : gw - gsh * (w - W) / z           (z > 0)
     else gw.
   Integer division truncates; the small rounding residue (< number of
   glues) is acceptable for an MSDF target and keeps determinism.  When y
   (resp. z) is 0 the glue is rigid and set at natural width. *)
Definition set_glue
    (w y z W : sp) (gw gst gsh : sp) : sp :=
  if Z.ltb w W then
    if Z.leb y 0 then gw else gw + (gst * (W - w)) / y
  else if Z.ltb W w then
    if Z.leb z 0 then gw else gw - (gsh * (w - W)) / z
  else gw.

(* The set width of a single item on a line being justified to fit [W],
   given the line's natural width/stretch/shrink (w,y,z). *)
Definition set_item_width (w y z W : sp) (it : item) : sp :=
  match it with
  | IBox b  => bx_width b
  | IGlue g => set_glue w y z W (gl_width g) (gl_stretch g) (gl_shrink g)
  | IPenalty _ => 0
  end.

(* ===================================================================== *)
(* Laying out one line                                                    *)
(* ===================================================================== *)

(* Place the glyphs of [box b] starting at pen x [x0] on baseline [by],
   advancing by each glyph's share of the box width.  Since a box's glyphs
   were shaped together, we distribute the box width evenly is WRONG; we
   instead need per-glyph advances.  But [box] only stores total width +
   glyph ids.  For correct per-glyph placement we recompute advances from
   the metric table.  To keep GlyphLayout independent of Metrics we accept
   the glyphs already split into per-glyph sub-boxes OR place them with
   equal share.

   The shaper (Metrics.shape) packs a whole word in one box; for layout we
   place each glyph at the running x using its advance recomputed by the
   caller.  To avoid a Metrics dependency cycle we take a [glyph_advance]
   function as a parameter. *)

(* Place the glyph list of a box: emit one quad per glyph at the running x,
   advancing x by [adv g].  Structural recursion on the glyph list; returns
   the quad list (the caller threads the final x separately via
   [glyphs_advance]). *)
(* Tail-recursive variants: use an output accumulator so every recursive call
   is in tail position.  LLVM eliminates frames regardless of optimization level;
   WASM/Asyncify stack stays shallow. *)

Fixpoint place_glyphs_tr (adv : glyph_id -> sp) (gs : list glyph_id) (x by_ : sp)
  (out : quad_buffer) : quad_buffer :=
  match gs with
  | [] => out
  | g :: rest => place_glyphs_tr adv rest (x + adv g) by_ (mkQuad x by_ g :: out)
  end.

Definition place_glyphs (adv : glyph_id -> sp) (gs : list glyph_id) (x by_ : sp)
  : quad_buffer :=
  place_glyphs_tr adv gs x by_ [].

(* Lay out a list of items (one line) starting at pen [x0] on baseline [by],
   justified to fit [W] given the line's natural (w,y,z).  Emits quads for
   box glyphs, advances the pen across set glue.  Structural recursion on
   the item list; pen x threaded by re-deriving each item's set width. *)
Fixpoint layout_line_items_tr
    (adv : glyph_id -> sp) (w y z W : sp)
    (its : list item) (x by_ : sp) (out : quad_buffer) : quad_buffer :=
  match its with
  | [] => out
  | IBox b :: rest =>
      layout_line_items_tr adv w y z W rest (x + bx_width b) by_
        (place_glyphs_tr adv (bx_glyphs b) x by_ out)
  | IGlue g :: rest =>
      let sw := set_glue w y z W (gl_width g) (gl_stretch g) (gl_shrink g) in
      layout_line_items_tr adv w y z W rest (x + sw) by_ out
  | IPenalty _ :: rest =>
      (* a penalty contributes nothing unless it is the chosen break, which
         is handled by line slicing; mid-line penalties are zero-width *)
      layout_line_items_tr adv w y z W rest x by_ out
  end.


(* ===================================================================== *)
(* Slicing the paragraph at break positions                               *)
(* ===================================================================== *)

(* The breaker returns ascending break positions (item-boundary indices)
   ending at [length p].  The line spanning boundaries [i, j) is
   [firstn (j - i) (skipn i p)].  We expose a sublist helper. *)
Definition line_slice (p : paragraph) (i j : nat) : paragraph :=
  firstn (j - i) (skipn i p).

(* Natural width/stretch/shrink of a slice (reuse Boxes totals). *)
Definition slice_w (p : paragraph) (i j : nat) : sp := total_width   (line_slice p i j).
Definition slice_y (p : paragraph) (i j : nat) : sp := total_stretch (line_slice p i j).
Definition slice_z (p : paragraph) (i j : nat) : sp := total_shrink  (line_slice p i j).

(* ===================================================================== *)
(* Whole-paragraph layout                                                 *)
(* ===================================================================== *)

(* Given the advance function, the measure [W], the node list [p], and the
   break positions [bs], lay out every line and concatenate the quad
   buffers.  We walk [bs] carrying the previous boundary [i] and the line
   number [ln].  Structural recursion on [bs]. *)
Fixpoint layout_lines_tr
    (adv : glyph_id -> sp) (W : sp) (p : paragraph)
    (i : nat) (ln : nat) (bs : list nat) (out : quad_buffer) : quad_buffer :=
  match bs with
  | [] => rev_append out []
  | j :: rest =>
      let its := line_slice p i j in
      let w := total_width its in
      let y := total_stretch its in
      let z := total_shrink its in
      let by_ := baseline_y ln in
      layout_lines_tr adv W p j (S ln) rest
        (layout_line_items_tr adv w y z W its 0 by_ out)
  end.

Definition layout_lines
    (adv : glyph_id -> sp) (W : sp) (p : paragraph)
    (i : nat) (ln : nat) (bs : list nat) : quad_buffer :=
  layout_lines_tr adv W p i ln bs [].

(* The public entry: lay out paragraph [p] at measure [W] using the optimal
   Knuth-Plass breaks, with per-glyph advances from [adv].  Returns the
   integer quad buffer ready for [draw_glyph_quads]. *)
Definition layout_paragraph
    (adv : glyph_id -> sp) (W : sp) (p : paragraph) : quad_buffer :=
  let bs := break_at W p in
  layout_lines adv W p 0 0 bs.

(* ===================================================================== *)
(* Totality / structural facts                                            *)
(* ===================================================================== *)

(* Helper: length of rev_append. *)
Lemma rev_append_length {A} (l1 l2 : list A) :
  length (rev_append l1 l2) = (length l1 + length l2)%nat.
Proof.
  rewrite rev_append_rev, app_length, rev_length. reflexivity.
Qed.

(* Helper: In for rev_append. *)
Lemma rev_append_In {A} (l1 l2 : list A) (x : A) :
  In x (rev_append l1 l2) <-> In x l1 \/ In x l2.
Proof.
  rewrite rev_append_rev, in_app_iff, in_rev. reflexivity.
Qed.

(* Laying out the empty paragraph yields the empty buffer. *)
Lemma layout_paragraph_nil :
  forall adv W, layout_lines adv W [] 0 0 (break_at W []) = [].
Proof. reflexivity. Qed.

(* Tail-recursive place_glyphs_tr general length property. *)
Lemma place_glyphs_tr_length :
  forall adv gs x by_ out,
    length (place_glyphs_tr adv gs x by_ out) = (length gs + length out)%nat.
Proof.
  induction gs as [| g gs IH]; intros x by_ out; simpl.
  - reflexivity.
  - rewrite IH. simpl. rewrite Nat.add_succ_r. reflexivity.
Qed.

(* place_glyphs emits exactly one quad per glyph (buffer length = #glyphs)
   -- the buffer is well-sized, so the draw call's vertex count is known. *)
Lemma place_glyphs_length :
  forall adv gs x by_, length (place_glyphs adv gs x by_) = length gs.
Proof.
  intros adv gs x by_. unfold place_glyphs.
  rewrite place_glyphs_tr_length. rewrite Nat.add_0_r. reflexivity.
Qed.

(* Tail-recursive place_glyphs_tr general baseline property. *)
Lemma place_glyphs_tr_baseline :
  forall adv gs x by_ out q,
    In q (place_glyphs_tr adv gs x by_ out) -> q_y q = by_ \/ In q out.
Proof.
  induction gs as [| g gs IH]; intros x by_ out q Hin; simpl in Hin.
  - intuition.
  - apply IH in Hin. intuition.
Qed.

(* Each quad a line produces sits on that line's baseline.  We state the
   per-box placement fact: place_glyphs puts every quad on baseline [by_]. *)
Lemma place_glyphs_baseline :
  forall adv gs x by_ q,
    In q (place_glyphs adv gs x by_) -> q_y q = by_.
Proof.
  unfold place_glyphs. intros * Hin.
  apply place_glyphs_tr_baseline in Hin. intuition.
Qed.

(* ===================================================================== *)
(* MSDF draw FFI seam (C13) -- declared here, realized in the WASM step    *)
(* ===================================================================== *)

(* The single GPU draw call.  This is the ONLY FFI in the whole typesetter
   (plan sec 2.3): a logic-free upload+draw of the integer quad buffer
   against the MSDF atlas.  We DECLARE it as an axiom with the intended
   C++/WASM signature so the seam is explicit; the From-less EM_ASM /
   Embind realization (built -O0 per the gotchas) is added during the WASM
   integration step, NOT here.  Kept as a no-op-returning axiom so this
   pure theory neither depends on nor pulls in any FFI header. *)
Axiom draw_glyph_quads : quad_buffer -> unit.

(* AIDEV-NOTE: draw_glyph_quads is the C13 boundary.  In the WASM build it
   becomes:
     Crane Extract Inlined Constant draw_glyph_quads => "draw_glyph_quads(%a0)".
   uploading (x,y,uv) triples to a VBO and issuing one indexed draw against
   the MSDF atlas texture.  No typesetting logic crosses this seam -- the
   buffer is already final integer geometry.  Do NOT realize it in this
   pure theory (would drag a GL header into the proof build). *)
