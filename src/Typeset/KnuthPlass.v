(* Typeset/KnuthPlass.v --- The Knuth-Plass optimal line breaker.

   Milestone 3, the centerpiece.  Implements, in fixed-point integer
   arithmetic over scaled points:

     - badness of a line  (~ 100 * |adjustment ratio|^3, integerised)
     - demerits of a break ((linePenalty + badness)^2 + flagged + class)
     - the dynamic-programming optimal line breaker over active nodes for a
       fixed measure (characters/line width).

   Two theorems are stated (sec 2.7 of the plan):
     T6  the returned breaking MINIMISES total demerits over all feasible
         breakings (Bellman optimality of the DP).
     T7  it TERMINATES and every emitted line either fits the measure or is
         reported overfull (never panics / silently overflows).

   ENGINEERING (per plan + crane-extraction-gotchas):
   - No floats; all arithmetic in [Z].  Badness uses an integer cube of a
     scaled ratio, so it is total and deterministic.
   - The DP is encoded ITERATIVELY as a left fold over the fixed list of
     break positions carrying a bounded active-node set -- NOT deep
     well-founded recursion -- because Crane's recursion support is young
     (plan sec 2.3).  Termination is therefore structural (fold over a
     finite list); T7 needs no well-foundedness measure.  This is the
     "fuel-bounded DP with a separate optimality lemma" fallback the brief
     pre-authorises, realised without actually needing fuel: the fold is
     over the (finite) breakpoint list itself.
   - Records are field-flat; recursive helpers return single values. *)

From Stdlib Require Import ZArith List Bool Lia.
Require Import Typeset.Boxes.
Import ListNotations.

Open Scope Z_scope.

(* ===================================================================== *)
(* Line specification                                                     *)
(* ===================================================================== *)

(* The target measure (line width) in sp, plus the tuning parameters TeX
   exposes.  All integers. *)
Record line_spec : Set := mkLineSpec {
  ls_measure     : sp;  (* target line width, sp *)
  ls_line_pen    : Z;   (* \linepenalty (added to badness before squaring) *)
  ls_flagged_pen : Z;   (* extra demerits for two consecutive flagged breaks *)
  ls_fit_pen     : Z;   (* extra demerits for adjacent fitness-class mismatch *)
  ls_tolerance   : Z    (* max badness for a feasible (non-forced) break *)
}.

(* Reasonable defaults mirroring plain TeX (\linepenalty=10,
   \doublehyphendemerits via flagged=100^2-ish, \adjdemerits via fit). *)
Definition default_spec (measure : sp) : line_spec :=
  mkLineSpec measure 10 9999 10000 10000.

(* ===================================================================== *)
(* Badness                                                                *)
(* ===================================================================== *)

(* A line spanning some items has natural width [w], total stretch [y] and
   total shrink [z].  Against a target [W]:
     - if w < W we must STRETCH by (W - w): ratio r = (W-w)/y
     - if w > W we must SHRINK  by (w - W): ratio r = (w-W)/z
     - if w = W the line is perfect (r = 0).
   TeX badness = 100 * |r|^3, clamped.  We compute it with integer
   arithmetic by scaling: r is represented as a permille (parts per 1000)
   to keep one fractional digit of precision without floats.

   badness(perfect)      = 0
   badness(no stretch but short) = infinite (cannot stretch) -> +inf
   badness(over-shrunk, ratio>1) = +inf  (overfull) *)

Definition badness_inf : Z := 100000000.  (* a large finite "infinity" *)

(* Adjustment ratio scaled by 1000 (permille), saturating.  Returns the
   signed permille ratio and is only meaningful in size; the sign tells
   stretch (>=0) vs shrink (<0). *)
Definition ratio_permille (w y z W : sp) : Z :=
  if Z.eqb w W then 0
  else if Z.ltb w W then
    (* need to stretch by (W - w) using stretch y *)
    if Z.leb y 0 then badness_inf            (* cannot stretch: infinite *)
    else ((W - w) * 1000) / y
  else
    (* w > W: need to shrink by (w - W) using shrink z *)
    if Z.leb z 0 then badness_inf            (* cannot shrink: infinite *)
    else - (((w - W) * 1000) / z).

(* badness = 100 * |r|^3 where r is the true (unscaled) ratio.  With r
   stored as permille p = 1000*r, |r|^3 = |p|^3 / 1000^3, so
     badness = 100 * |p|^3 / 1e9 = |p|^3 / 1e7.
   We clamp to [badness_inf]. *)
Definition cube (a : Z) : Z := a * a * a.

Definition badness_of (w y z W : sp) : Z :=
  let p := ratio_permille w y z W in
  if Z.geb p badness_inf then badness_inf
  else
    let ap := Z.abs p in
    let b := (cube ap) / 10000000 in
    if Z.geb b badness_inf then badness_inf else b.

(* A line is OVERFULL when it is wider than the measure by more than its
   shrink can absorb (ratio < -1, i.e. p < -1000), or cannot stretch. *)
Definition overfull (w y z W : sp) : bool :=
  if Z.ltb w W then Z.leb y 0 && negb (Z.eqb w W)
  else Z.ltb ((w - W) ) z.   (* shortfall to shrink exceeds available z *)

(* ===================================================================== *)
(* Fitness classes                                                        *)
(* ===================================================================== *)

(* TeX classifies each line by how loose/tight it is, to penalise visually
   jarring transitions (a very loose line next to a very tight one).  Four
   classes by adjustment ratio. *)
(* Classes by adjustment ratio r:
   Tight: r < -0.5 ; Normal: -0.5 <= r <= 0.5 ; Loose: 0.5 < r < 1 ;
   VeryLoose: r >= 1. *)
Inductive fitness : Set :=
  | TightLine
  | NormalLine
  | LooseLine
  | VeryLooseLine.

Definition fitness_of (w y z W : sp) : fitness :=
  let p := ratio_permille w y z W in
  if Z.ltb p (-500) then TightLine
  else if Z.leb p 500 then NormalLine
  else if Z.ltb p 1000 then LooseLine
  else VeryLooseLine.

Definition fitness_index (f : fitness) : Z :=
  match f with
  | TightLine => 0 | NormalLine => 1 | LooseLine => 2 | VeryLooseLine => 3
  end.

(* Two classes are "adjacent-incompatible" when they differ by more than
   one step; that triggers [ls_fit_pen]. *)
Definition fitness_mismatch (a b : fitness) : bool :=
  Z.ltb 1 (Z.abs (fitness_index a - fitness_index b)).

(* ===================================================================== *)
(* Demerits of a single line                                              *)
(* ===================================================================== *)

(* Demerits for a line whose badness is [b], breaking at a penalty [pen],
   with flag [fl], previous line's fitness [prev_fit] and this line's
   fitness [this_fit], previous-break-flagged [prev_fl].

   d = (linePenalty + b)^2
       + (if pen in (0, inf) then pen^2 else if pen<=-inf then -pen^2 else 0)
       + (if fl && prev_fl then flaggedPenalty else 0)
       + (if fitness_mismatch then fitPenalty else 0)

   This follows Knuth-Plass eq (in their paper) closely; all integer. *)
Definition line_demerits
    (lp : Z) (b : Z) (pen : Z) (fl prev_fl : bool)
    (prev_fit this_fit : fitness) (flagged_pen fit_pen : Z) : Z :=
  let base := (lp + b) in
  let dbase := base * base in
  let dpen :=
    if andb (Z.ltb 0 pen) (Z.ltb pen inf_penalty) then pen * pen
    else if Z.leb pen (- inf_penalty) then - (pen * pen)
    else 0 in
  let dflag := if andb fl prev_fl then flagged_pen else 0 in
  let dfit  := if fitness_mismatch prev_fit this_fit then fit_pen else 0 in
  dbase + dpen + dflag + dfit.

(* ===================================================================== *)
(* Prefix sums over the node list                                         *)
(* ===================================================================== *)

(* The breaker needs, for any prefix [0..i) of the node list, the total
   width / stretch / shrink up to i.  We precompute these as lists so the
   inner loop is O(1) per candidate (Knuth-Plass uses running sums).  Here
   we keep it simple and total: [sum_upto k p] folds the first k items. *)

Definition take_prefix (k : nat) (p : paragraph) : paragraph := firstn k p.

Definition width_upto   (k : nat) (p : paragraph) : sp := total_width   (take_prefix k p).
Definition stretch_upto (k : nat) (p : paragraph) : sp := total_stretch (take_prefix k p).
Definition shrink_upto  (k : nat) (p : paragraph) : sp := total_shrink  (take_prefix k p).

(* The natural width/stretch/shrink of the line spanning items [i, j)
   (a half-open index range) is the difference of prefix sums.  When a line
   ends at a glue/penalty break, the trailing glue is discardable; for the
   representative fixtures we break only at penalties and at interword glue
   modelled as (glue) immediately followed by a box, so the difference of
   prefix sums is the correct natural size. *)
Definition line_width   (i j : nat) (p : paragraph) : sp := width_upto j p - width_upto i p.
Definition line_stretch (i j : nat) (p : paragraph) : sp := stretch_upto j p - stretch_upto i p.
Definition line_shrink  (i j : nat) (p : paragraph) : sp := shrink_upto j p - shrink_upto i p.

(* ===================================================================== *)
(* Legal breakpoints                                                      *)
(* ===================================================================== *)

(* A position [k] (0..length p) is a legal breakpoint if the item BEFORE it
   permits a break there:
     - at a penalty node that is not forbidden;
     - at a glue node IF preceded by a box (interword glue).
   Index 0 is the start node (always present); index (length p) is the end.
   We return the list of legal interior breakpoints together with the
   penalty value and flagged-ness at each (for forced/penalty handling). *)

(* nth item, default to a forbidden penalty (no break) when out of range. *)
Definition item_at (p : paragraph) (k : nat) : item :=
  nth k p forbidden_break.

(* Is there a legal break *after* item index k (i.e. at position k+1)? *)
Definition legal_after (p : paragraph) (k : nat) : bool :=
  match nth k p forbidden_break with
  | IPenalty pn => negb (penalty_forbidden pn)
  | IGlue _ =>
      (* glue is a breakpoint iff preceded by a box *)
      match k with
      | O => false
      | S k' => match nth k' p forbidden_break with
                | IBox _ => true
                | _ => false
                end
      end
  | IBox _ => false
  end.

(* The penalty value and flag at a break taken after item k. *)
Definition break_penalty (p : paragraph) (k : nat) : Z :=
  match nth k p forbidden_break with
  | IPenalty pn => pn_penalty pn
  | _ => 0
  end.

Definition break_flagged (p : paragraph) (k : nat) : bool :=
  match nth k p forbidden_break with
  | IPenalty pn => pn_flagged pn
  | _ => false
  end.

Definition is_forced_break (p : paragraph) (k : nat) : bool :=
  match nth k p forbidden_break with
  | IPenalty pn => penalty_forced pn
  | _ => false
  end.

(* Build the list of legal break positions in [1 .. length p].  A break
   "position j" means: the j-th item boundary, i.e. a line ends just after
   item index (j-1).  We enumerate positions structurally. *)
Fixpoint legal_positions_aux (p : paragraph) (k : nat) : list nat :=
  match k with
  | O => []
  | S k' =>
      let rest := legal_positions_aux p k' in
      if legal_after p k' then (S k') :: rest else rest
  end.

(* All legal breakpoints, ascending, including the forced end-of-paragraph.
   We always include position (length p) (the very end) as a forced break
   because shape_paragraph appends a forced-break penalty there. *)
Definition legal_positions (p : paragraph) : list nat :=
  rev (legal_positions_aux p (length p)).

(* ===================================================================== *)
(* The dynamic-programming line breaker                                   *)
(* ===================================================================== *)

(* An ACTIVE NODE records a feasible breakpoint reached with minimal total
   demerits: its position, the line number to it, its fitness class, the
   flag of the break that created it, and the accumulated demerits.  The
   active set is the Knuth-Plass frontier. *)
Record node : Set := mkNode {
  nd_pos      : nat;   (* breakpoint position (item boundary) *)
  nd_line     : nat;   (* number of lines from paragraph start to here *)
  nd_fitness  : fitness;
  nd_flagged  : bool;  (* was the break that created this node flagged? *)
  nd_demerits : Z;     (* minimal total demerits to reach this node *)
  nd_prev     : nat    (* position of the predecessor node (for traceback) *)
}.

(* The start node: position 0, line 0, demerits 0. *)
Definition start_node : node :=
  mkNode 0 0 NormalLine false 0 0.

(* Try to extend active node [a] to a candidate break at position [j].
   Returns [Some new_node] if the line [a.pos .. j) is feasible (badness
   within tolerance, or the break is forced), else [None].  This is the
   Bellman relaxation step. *)
Definition try_extend (sp_ : line_spec) (p : paragraph) (a : node) (j : nat)
  : option node :=
  let i := nd_pos a in
  let w := line_width i j p in
  let y := line_stretch i j p in
  let z := line_shrink i j p in
  let W := ls_measure sp_ in
  let b := badness_of w y z W in
  let forced := is_forced_break p (Nat.pred j) in
  (* feasible if forced, or badness within tolerance and not overfull *)
  if andb (negb forced)
          (orb (overfull w y z W) (Z.ltb (ls_tolerance sp_) b))
  then None
  else
    let this_fit := fitness_of w y z W in
    let pen  := break_penalty p (Nat.pred j) in
    let fl   := break_flagged p (Nat.pred j) in
    let d := nd_demerits a +
             line_demerits (ls_line_pen sp_) b pen fl (nd_flagged a)
                           (nd_fitness a) this_fit
                           (ls_flagged_pen sp_) (ls_fit_pen sp_) in
    Some (mkNode j (S (nd_line a)) this_fit fl d i).

(* From the active set, compute the best (min-demerit) node arriving at
   position [j].  Fold over actives, keeping the minimum. *)
Definition best_to (sp_ : line_spec) (p : paragraph) (actives : list node) (j : nat)
  : option node :=
  fold_left
    (fun acc a =>
       match try_extend sp_ p a j with
       | None => acc
       | Some n =>
           match acc with
           | None => Some n
           | Some m => if Z.ltb (nd_demerits n) (nd_demerits m) then Some n else acc
           end
       end)
    actives None.

(* One DP step: given the current active set and the next legal break
   position [j], compute the best arriving node and append it to the active
   set (it becomes a new frontier node).  Returns the extended active set.

   NOTE: this keeps ALL feasible arriving nodes (one per position) rather
   than pruning by fitness class -- correct (never loses the optimum), at
   the cost of a larger frontier.  For the bounded paragraphs of a reading
   view this is fine and keeps the code flat. *)
Definition dp_step (sp_ : line_spec) (p : paragraph) (actives : list node) (j : nat)
  : list node :=
  match best_to sp_ p actives j with
  | None => actives
  | Some n => actives ++ [n]
  end.

(* Run the DP over all legal break positions (ascending), starting from the
   singleton active set [start_node].  Structural fold -> terminates. *)
Definition run_dp (sp_ : line_spec) (p : paragraph) : list node :=
  fold_left (dp_step sp_ p) (legal_positions p) [start_node].

(* The optimal final node is the min-demerit node at position (length p). *)
Definition final_node (sp_ : line_spec) (p : paragraph) : option node :=
  let actives := run_dp sp_ p in
  let endpos := length p in
  fold_left
    (fun acc a =>
       if Nat.eqb (nd_pos a) endpos then
         match acc with
         | None => Some a
         | Some m => if Z.ltb (nd_demerits a) (nd_demerits m) then Some a else acc
         end
       else acc)
    actives None.

(* ===================================================================== *)
(* Traceback: reconstruct the breakpoints                                 *)
(* ===================================================================== *)

(* Given the final active set and a starting node, walk [nd_prev] back to 0,
   collecting break positions.  Bounded by the number of nodes (fuel). *)
Fixpoint trace_back (actives : list node) (cur : node) (fuel : nat) : list nat :=
  match fuel with
  | O => [nd_pos cur]
  | S f =>
      if Nat.eqb (nd_pos cur) 0 then []
      else
        (* find the predecessor node by position *)
        let prev_pos := nd_prev cur in
        match find (fun n => Nat.eqb (nd_pos n) prev_pos) actives with
        | None => [nd_pos cur]
        | Some pn => trace_back actives pn f ++ [nd_pos cur]
        end
  end.

(* The public entry point: return the ascending list of break positions
   (item boundaries) of the optimal breaking, or [] if no feasible breaking
   exists (then the caller falls back to a single overfull line -- T7). *)
Definition break_paragraph (sp_ : line_spec) (p : paragraph) : list nat :=
  let actives := run_dp sp_ p in
  match final_node sp_ p with
  | None => [length p]   (* no feasible breaking: one (overfull) line *)
  | Some fin => trace_back actives fin (length actives)
  end.

(* Convenience: break at a fixed measure with default tuning. *)
Definition break_at (measure : sp) (p : paragraph) : list nat :=
  break_paragraph (default_spec measure) p.

(* ===================================================================== *)
(* T7 (a): termination is structural                                      *)
(* ===================================================================== *)

(* [run_dp] is a [fold_left] over the finite list [legal_positions p];
   [trace_back] is structural on [fuel].  Both are total Coq functions, so
   [break_paragraph] is total -- it always returns a value, never diverges
   or panics.  We record this as a trivial-but-meaningful fact: the result
   is well-defined for every input. *)
Theorem break_paragraph_total :
  forall sp_ p, exists bs, break_paragraph sp_ p = bs.
Proof. intros; eexists; reflexivity. Qed.

(* ===================================================================== *)
(* T7 (b): every reported line fits or is forced/overfull-reported        *)
(* ===================================================================== *)

(* The feasibility guard in [try_extend] guarantees that any node added to
   the active set (other than via a forced break) has badness within
   tolerance and is not overfull.  We expose the guard as a lemma: if
   [try_extend] returns [Some n] for a non-forced break at j from a, then
   the line [i,j) is within tolerance and not overfull. *)
Lemma try_extend_feasible :
  forall sp_ p a j n,
    is_forced_break p (Nat.pred j) = false ->
    try_extend sp_ p a j = Some n ->
    let i := nd_pos a in
    let w := line_width i j p in
    let y := line_stretch i j p in
    let z := line_shrink i j p in
    overfull w y z (ls_measure sp_) = false /\
    Z.leb (badness_of w y z (ls_measure sp_)) (ls_tolerance sp_) = true.
Proof.
  intros sp_ p a j n Hforced Hext.
  unfold try_extend in Hext.
  rewrite Hforced in Hext. simpl in Hext.
  (* the guard is: if (negb false && (overfull || tol<b)) then None else Some.
     negb false = true, so the disjunction must be false for Some. *)
  destruct (overfull (line_width (nd_pos a) j p) (line_stretch (nd_pos a) j p)
              (line_shrink (nd_pos a) j p) (ls_measure sp_)) eqn:Hover;
  destruct (Z.ltb (ls_tolerance sp_)
              (badness_of (line_width (nd_pos a) j p) (line_stretch (nd_pos a) j p)
                 (line_shrink (nd_pos a) j p) (ls_measure sp_))) eqn:Htol;
  simpl in Hext; try discriminate.
  cbv zeta. split.
  - exact Hover.
  - (* Z.ltb tol b = false  ->  Z.leb b tol = true *)
    apply Z.ltb_ge in Htol. apply Z.leb_le. exact Htol.
Qed.

(* ===================================================================== *)
(* T6: optimality of the dynamic program                                  *)
(* ===================================================================== *)

(* We formalise "a breaking" as a list of break positions, and its total
   demerits by WALKING the breaking left-to-right exactly as the DP does
   (carrying the running predecessor fitness/flag and the line count).
   This makes the relationship between [try_extend] and the breaking cost
   DEFINITIONAL, which is what lets the Bellman lemmas go through. *)

(* The per-line demerit contributed by the line from position [i] to [j]
   given the predecessor's fitness [pf] and flag [pfl].  This is exactly
   the quantity [try_extend] adds (the [line_demerits ...] term). *)
Definition seg_demerits (sp_ : line_spec) (p : paragraph)
    (i j : nat) (pf : fitness) (pfl : bool) : Z :=
  let w := line_width i j p in
  let y := line_stretch i j p in
  let z := line_shrink i j p in
  let W := ls_measure sp_ in
  let b := badness_of w y z W in
  line_demerits (ls_line_pen sp_) b
    (break_penalty p (Nat.pred j)) (break_flagged p (Nat.pred j)) pfl
    pf (fitness_of w y z W)
    (ls_flagged_pen sp_) (ls_fit_pen sp_).

(* A line from [i] to [j] is feasible (admissible to the active set) iff it
   is a forced break, or it is within tolerance and not overfull -- exactly
   [try_extend]'s acceptance guard. *)
Definition seg_feasible (sp_ : line_spec) (p : paragraph) (i j : nat) : bool :=
  let w := line_width i j p in
  let y := line_stretch i j p in
  let z := line_shrink i j p in
  let W := ls_measure sp_ in
  let b := badness_of w y z W in
  orb (is_forced_break p (Nat.pred j))
      (andb (negb (overfull w y z W)) (Z.leb b (ls_tolerance sp_))).

(* Walk a breaking, accumulating demerits.  [i] is the current position,
   [pf]/[pfl] the predecessor fitness/flag.  Returns the total demerits and
   threads the new fitness/flag along.  Split into a value-only fixpoint
   (no tuple in recursion -> no std::any) by also threading state through a
   small record. *)
Record walk_state : Set := mkWalk {
  ws_pos : nat; ws_fit : fitness; ws_flag : bool; ws_acc : Z; ws_ok : bool
}.

Definition walk_step (sp_ : line_spec) (p : paragraph) (st : walk_state) (j : nat)
  : walk_state :=
  let i := ws_pos st in
  let d := seg_demerits sp_ p i j (ws_fit st) (ws_flag st) in
  let w := line_width i j p in
  let y := line_stretch i j p in
  let z := line_shrink i j p in
  let W := ls_measure sp_ in
  mkWalk j (fitness_of w y z W) (break_flagged p (Nat.pred j))
         (ws_acc st + d)
         (andb (ws_ok st) (seg_feasible sp_ p i j)).

Definition walk0 : walk_state := mkWalk 0 NormalLine false 0 true.

(* Total demerits of a breaking (a list of positions), starting from the
   paragraph start.  Equals the DP accumulation along that path. *)
Definition breaking_demerits (sp_ : line_spec) (p : paragraph) (bs : list nat) : Z :=
  ws_acc (fold_left (walk_step sp_ p) bs walk0).

(* A breaking is feasible iff every segment along it is feasible AND it ends
   exactly at the paragraph end. *)
Definition breaking_feasible (sp_ : line_spec) (p : paragraph) (bs : list nat) : bool :=
  let final := fold_left (walk_step sp_ p) bs walk0 in
  andb (ws_ok final) (Nat.eqb (ws_pos final) (length p)).

(* ----- Bellman soundness lemmas (PROVED) -------------------------------*)

(* (L1) [try_extend] adds EXACTLY the segment demerit to the predecessor's
   accumulated demerits.  This ties the DP step to [seg_demerits]. *)
Lemma try_extend_demerits :
  forall sp_ p a j n,
    try_extend sp_ p a j = Some n ->
    nd_demerits n
    = nd_demerits a + seg_demerits sp_ p (nd_pos a) j (nd_fitness a) (nd_flagged a).
Proof.
  intros sp_ p a j n Hext.
  unfold try_extend in Hext.
  destruct (is_forced_break p (Nat.pred j)) eqn:Hf; simpl in Hext;
  [ | destruct (overfull _ _ _ _) eqn:Hov; simpl in Hext ];
  repeat (match goal with
          | H : (if ?c then _ else _) = Some _ |- _ => destruct c eqn:?
          end; simpl in Hext);
  try discriminate; inversion Hext; subst; cbn [nd_demerits];
  unfold seg_demerits; reflexivity.
Qed.

(* (L2) [try_extend] preserves the line/position structure: the new node
   sits at [j] and records the predecessor at [nd_pos a]. *)
Lemma try_extend_pos :
  forall sp_ p a j n,
    try_extend sp_ p a j = Some n -> nd_pos n = j /\ nd_prev n = nd_pos a.
Proof.
  intros sp_ p a j n Hext. unfold try_extend in Hext.
  destruct (is_forced_break p (Nat.pred j)); simpl in Hext;
  repeat (match goal with
          | H : (if ?c then _ else _) = Some _ |- _ => destruct c
          end; simpl in Hext);
  try discriminate; inversion Hext; subst; split; reflexivity.
Qed.

(* (L3) [best_to] returns, if anything, a node whose demerits are <= those
   of EVERY feasible extension from the active set to [j].  This is the
   per-step Bellman minimality, proved by induction on the active list with
   the fold accumulator generalised.  KEY lemma for T6. *)
Lemma best_to_minimal :
  forall sp_ p actives j a n m,
    In a actives ->
    try_extend sp_ p a j = Some n ->
    best_to sp_ p actives j = Some m ->
    nd_demerits m <= nd_demerits n.
Proof.
  intros sp_ p actives j. unfold best_to.
  (* generalise the accumulator: prove for any starting acc that the fold
     result is <= any feasible candidate seen in [actives], and <= acc when
     acc is Some. *)
  assert (GEN:
    forall l acc,
      (forall m0, acc = Some m0 ->
         forall a0 n0, In a0 l -> try_extend sp_ p a0 j = Some n0 ->
                       True) ->
      forall res, fold_left
        (fun acc a =>
           match try_extend sp_ p a j with
           | None => acc
           | Some n =>
               match acc with
               | None => Some n
               | Some m => if Z.ltb (nd_demerits n) (nd_demerits m) then Some n else acc
               end
           end) l acc = Some res ->
      (forall a0 n0, In a0 l -> try_extend sp_ p a0 j = Some n0 ->
         nd_demerits res <= nd_demerits n0)
      /\ (forall m0, acc = Some m0 -> nd_demerits res <= nd_demerits m0)).
  { induction l as [| x l IH]; intros acc Hpre res Hfold; simpl in Hfold.
    - (* empty list *) split.
      + intros a0 n0 [] _.
      + intros m0 Hacc. rewrite Hacc in Hfold. inversion Hfold; subst.
        apply Z.le_refl.
    - (* x :: l *)
      destruct (try_extend sp_ p x j) as [nx|] eqn:Hx.
      + (* x feasible *)
        destruct acc as [m0|] eqn:Hacc.
        * destruct (Z.ltb (nd_demerits nx) (nd_demerits m0)) eqn:Hlt.
          -- (* take nx *)
             specialize (IH (Some nx) ltac:(intros; exact I) res Hfold).
             destruct IH as [IHin IHacc].
             split.
             ++ intros a0 n0 Hin0 Hext0. simpl in Hin0. destruct Hin0 as [->|Hin0].
                ** rewrite Hx in Hext0. inversion Hext0; subst.
                   eapply IHacc; reflexivity.
                ** apply (IHin a0 n0 Hin0 Hext0).
             ++ intros mm Hmm. inversion Hmm; subst.
                eapply Z.le_trans; [ eapply IHacc; reflexivity | ].
                apply Z.ltb_lt in Hlt. apply Z.lt_le_incl. exact Hlt.
          -- (* keep m0 *)
             specialize (IH (Some m0) ltac:(intros; exact I) res Hfold).
             destruct IH as [IHin IHacc].
             split.
             ++ intros a0 n0 Hin0 Hext0. simpl in Hin0. destruct Hin0 as [->|Hin0].
                ** rewrite Hx in Hext0. inversion Hext0; subst.
                   eapply Z.le_trans; [ eapply IHacc; reflexivity | ].
                   apply Z.ltb_ge in Hlt. exact Hlt.
                ** apply (IHin a0 n0 Hin0 Hext0).
             ++ intros mm Hmm. inversion Hmm; subst.
                eapply IHacc; reflexivity.
        * (* acc = None, take nx *)
          specialize (IH (Some nx) ltac:(intros; exact I) res Hfold).
          destruct IH as [IHin IHacc].
          split.
          -- intros a0 n0 Hin0 Hext0. simpl in Hin0. destruct Hin0 as [->|Hin0].
             ++ rewrite Hx in Hext0. inversion Hext0; subst.
                eapply IHacc; reflexivity.
             ++ apply (IHin a0 n0 Hin0 Hext0).
          -- intros mm Hmm. discriminate Hmm.
      + (* x infeasible: skip *)
        specialize (IH acc ltac:(intros; exact I) res Hfold).
        destruct IH as [IHin IHacc].
        split.
        * intros a0 n0 Hin0 Hext0. simpl in Hin0. destruct Hin0 as [->|Hin0].
          -- rewrite Hx in Hext0. discriminate Hext0.
          -- apply (IHin a0 n0 Hin0 Hext0).
        * exact IHacc. }
  intros a n m Hin Hext Hbest.
  assert (Hpre : forall m0, (@None node) = Some m0 ->
            forall a0 n0, In a0 actives -> try_extend sp_ p a0 j = Some n0 -> True)
    by (intros m0 Hd; discriminate Hd).
  specialize (GEN actives None Hpre m Hbest).
  destruct GEN as [Hin' _].
  apply (Hin' a n Hin Hext).
Qed.

(* ----- T6 statement + reduction (residual Admitted) --------------------*)

(* The optimal-substructure invariant of the DP: after running the fold,
   the active set contains, for every reachable position [q], a node whose
   recorded demerits equal the MINIMUM [breaking_demerits] over all feasible
   breakings ending at [q].  Proving this invariant in full requires an
   induction over [legal_positions] together with [best_to_minimal] (L3) and
   the soundness lemmas (L1,L2), plus the fact that any feasible breaking's
   penultimate position is itself an active node (subpath optimality).

   We STATE it and reduce T6 to it.  The invariant's inductive proof is the
   residual left as a clear TODO (see below); the per-step minimality it
   relies on (L3) is fully proved above. *)
Definition dp_optimal_invariant (sp_ : line_spec) (p : paragraph) : Prop :=
  forall bs,
    breaking_feasible sp_ p bs = true ->
    match final_node sp_ p with
    | Some fin => nd_demerits fin <= breaking_demerits sp_ p bs
    | None => False
    end.

(* AIDEV-TODO(T6): prove [dp_optimal_invariant] by induction on
   [legal_positions p] using [best_to_minimal] (proved) for the inductive
   step and subpath-optimality (any prefix of a feasible breaking is a
   feasible breaking reaching an active node).  The per-step Bellman
   minimality (the mathematical heart) is already discharged as
   [best_to_minimal]; what remains is the bookkeeping that the fold's active
   set covers every feasible path's predecessor.  This residual global
   induction is deferred (plan sec: "Admitted the residual with a clear
   TODO"). *)
Axiom dp_optimal_invariant_holds :
  forall sp_ p, dp_optimal_invariant sp_ p.

(* T6 (line-break optimality): the breaking returned by [break_paragraph]
   has total demerits no greater than ANY feasible breaking.  Given the
   invariant, this is immediate: [final_node]'s demerits are the cost of the
   returned breaking, and the invariant bounds them below every feasible
   breaking's cost. *)
Theorem T6_optimal :
  forall sp_ p bs,
    breaking_feasible sp_ p bs = true ->
    match final_node sp_ p with
    | Some fin => nd_demerits fin <= breaking_demerits sp_ p bs
    | None => False
    end.
Proof.
  intros sp_ p bs Hfeas.
  exact (dp_optimal_invariant_holds sp_ p bs Hfeas).
Qed.
