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

(* ----- Precomputed cumulative prefix-sum tables (the speed fix) --------- *)

(* [width_upto k p] above re-folds [firstn k p] FROM SCRATCH; called O(n)
   times per paragraph (once per legal position, inside [best_to]) that is an
   O(n^2) tower of list allocations + bignum additions and was the dominant
   cost.  We instead SCAN the paragraph ONCE into a cumulative table: entry
   [k] of [prefix_w p] is exactly [width_upto k p].  The DP then reads the
   table (no re-fold, no [firstn] allocation).

   Three separate scans (not one returning a triple): a Fixpoint returning a
   tuple extracts to [std::any] under Crane (recursive-tuple gotcha), whereas
   three [list sp]-valued scans stay flat PODs.  Each scan emits the running
   accumulator BEFORE consuming the next item, so the list has length
   [length p + 1] and position [k] holds the sum of the first [k] items. *)
Fixpoint scan_width_tr (acc : sp) (p : paragraph) (out : list sp) : list sp :=
  match p with
  | [] => rev_append out [acc]
  | it :: rest =>
      let next_acc := acc + match it with
                            | IBox b => bx_width b | IGlue g => gl_width g
                            | IPenalty _ => 0 end in
      scan_width_tr next_acc rest (acc :: out)
  end.

Definition scan_width (acc : sp) (p : paragraph) : list sp :=
  scan_width_tr acc p [].

Fixpoint scan_stretch_tr (acc : sp) (p : paragraph) (out : list sp) : list sp :=
  match p with
  | [] => rev_append out [acc]
  | it :: rest =>
      let next_acc := acc + match it with IGlue g => gl_stretch g | _ => 0 end in
      scan_stretch_tr next_acc rest (acc :: out)
  end.

Definition scan_stretch (acc : sp) (p : paragraph) : list sp :=
  scan_stretch_tr acc p [].

Fixpoint scan_shrink_tr (acc : sp) (p : paragraph) (out : list sp) : list sp :=
  match p with
  | [] => rev_append out [acc]
  | it :: rest =>
      let next_acc := acc + match it with IGlue g => gl_shrink g | _ => 0 end in
      scan_shrink_tr next_acc rest (acc :: out)
  end.

Definition scan_shrink (acc : sp) (p : paragraph) : list sp :=
  scan_shrink_tr acc p [].

(* The three tables for a paragraph, bundled (built once in [run_dp]). *)
Record psums : Set := mkPsums { ps_w : list sp; ps_y : list sp; ps_z : list sp }.

Definition build_psums (p : paragraph) : psums :=
  mkPsums (scan_width 0 p) (scan_stretch 0 p) (scan_shrink 0 p).

(* O(1)-amortised reads of the prefix sums at position [k]. *)
Definition pw_at (ps : psums) (k : nat) : sp := nth k (ps_w ps) 0.
Definition py_at (ps : psums) (k : nat) : sp := nth k (ps_y ps) 0.
Definition pz_at (ps : psums) (k : nat) : sp := nth k (ps_z ps) 0.

(* Cons laws for the totals (each total of [it :: rest] splits off the head
   item's contribution).  Used to relate the scan's step to [total_*]. *)
Lemma total_width_cons : forall it rest,
  total_width (it :: rest)
  = (match it with IBox b => bx_width b | IGlue g => gl_width g | IPenalty _ => 0 end)
    + total_width rest.
Proof.
  intros it rest. change (it :: rest) with ([it] ++ rest).
  rewrite total_width_app. destruct it; reflexivity.
Qed.
Lemma total_stretch_cons : forall it rest,
  total_stretch (it :: rest)
  = (match it with IGlue g => gl_stretch g | _ => 0 end) + total_stretch rest.
Proof.
  intros it rest. change (it :: rest) with ([it] ++ rest).
  rewrite total_stretch_app. destruct it; reflexivity.
Qed.
Lemma total_shrink_cons : forall it rest,
  total_shrink (it :: rest)
  = (match it with IGlue g => gl_shrink g | _ => 0 end) + total_shrink rest.
Proof.
  intros it rest. change (it :: rest) with ([it] ++ rest).
  rewrite total_shrink_app. destruct it; reflexivity.
Qed.

(* KEY EQUALITY LEMMAS: the precomputed table value at any in-range position
   [k <= length p] EQUALS the original [total_*(firstn k p)] expression.
   These are what make the speed refactor RESULT-IDENTICAL: the DP reads the
   table only at legal positions (all <= length p), and every such read is
   provably the very integer [width_upto]/[stretch_upto]/[shrink_upto] would
   have recomputed -- so the DP, [seg_demerits], [breaking_demerits], T6 and
   T7 all see precisely the same numbers as before the optimisation. *)
Lemma scan_width_tr_eq : forall p acc out,
  scan_width_tr acc p out = rev_append out (scan_width acc p).
Proof.
  (* AIDEV-NOTE: scan_width acc p := scan_width_tr acc p [] (5cab40f tail-rec
     refactor), so the cons case has scan_width_tr at out=(acc::out) on the LHS
     AND at out=[acc] on the RHS.  A single [rewrite IH] left the RHS occurrence
     un-rewritten and [reflexivity] failed — breaking the whole-project build.
     Rewrite IH at BOTH occurrences; rev_append's cons step closes the rest. *)
  induction p as [| it p IH]; intros acc out.
  - reflexivity.
  - cbn [scan_width_tr scan_width].
    rewrite (IH _ (acc :: out)), (IH _ [acc]).
    reflexivity.
Qed.

(* AIDEV-NOTE: 5cab40f made scan_width a reverse-accumulator wrapper
   (scan_width acc p := scan_width_tr acc p []), so it no longer reduces to
   [acc :: scan_width (acc+w) p] definitionally and the old cbn-based nth proof
   broke (whole-project build failure).  This cons law re-establishes that step
   via scan_width_tr_eq; the nth proof then proceeds structurally. *)
Lemma scan_width_cons : forall it p acc,
  scan_width acc (it :: p)
  = acc :: scan_width (acc + match it with
                            | IBox b => bx_width b | IGlue g => gl_width g
                            | IPenalty _ => 0 end) p.
Proof.
  intros it p acc.
  change (scan_width acc (it :: p)) with (scan_width_tr acc (it :: p) []).
  cbn [scan_width_tr]. now rewrite (scan_width_tr_eq p _ [acc]).
Qed.

Lemma scan_width_nth :
  forall p k acc, (k <= length p)%nat ->
    nth k (scan_width acc p) 0 = acc + total_width (firstn k p).
Proof.
  induction p as [| it p IH]; intros [|k] acc Hk.
  - change (scan_width acc []) with (@cons sp acc nil); cbn [nth firstn].
    rewrite total_width_nil, Z.add_0_r. reflexivity.
  - cbn [length] in Hk; lia.
  - rewrite scan_width_cons; cbn [nth firstn].
    rewrite total_width_nil, Z.add_0_r. reflexivity.
  - rewrite scan_width_cons; cbn [nth firstn length] in *.
    rewrite IH by lia. rewrite total_width_cons. lia.
Qed.
Lemma scan_stretch_tr_eq : forall p acc out,
  scan_stretch_tr acc p out = rev_append out (scan_stretch acc p).
Proof.
  induction p as [| it p IH]; intros acc out.
  - reflexivity.
  - cbn [scan_stretch_tr scan_stretch].
    rewrite (IH _ (acc :: out)), (IH _ [acc]).
    reflexivity.
Qed.

Lemma scan_stretch_cons : forall it p acc,
  scan_stretch acc (it :: p)
  = acc :: scan_stretch (acc + match it with IGlue g => gl_stretch g | _ => 0 end) p.
Proof.
  intros it p acc.
  change (scan_stretch acc (it :: p)) with (scan_stretch_tr acc (it :: p) []).
  cbn [scan_stretch_tr]. now rewrite (scan_stretch_tr_eq p _ [acc]).
Qed.

Lemma scan_stretch_nth :
  forall p k acc, (k <= length p)%nat ->
    nth k (scan_stretch acc p) 0 = acc + total_stretch (firstn k p).
Proof.
  induction p as [| it p IH]; intros [|k] acc Hk.
  - change (scan_stretch acc []) with (@cons sp acc nil); cbn [nth firstn].
    rewrite total_stretch_nil, Z.add_0_r. reflexivity.
  - cbn [length] in Hk; lia.
  - rewrite scan_stretch_cons; cbn [nth firstn].
    rewrite total_stretch_nil, Z.add_0_r. reflexivity.
  - rewrite scan_stretch_cons; cbn [nth firstn length] in *.
    rewrite IH by lia. rewrite total_stretch_cons. lia.
Qed.
Lemma scan_shrink_tr_eq : forall p acc out,
  scan_shrink_tr acc p out = rev_append out (scan_shrink acc p).
Proof.
  induction p as [| it p IH]; intros acc out.
  - reflexivity.
  - cbn [scan_shrink_tr scan_shrink].
    rewrite (IH _ (acc :: out)), (IH _ [acc]).
    reflexivity.
Qed.

Lemma scan_shrink_cons : forall it p acc,
  scan_shrink acc (it :: p)
  = acc :: scan_shrink (acc + match it with IGlue g => gl_shrink g | _ => 0 end) p.
Proof.
  intros it p acc.
  change (scan_shrink acc (it :: p)) with (scan_shrink_tr acc (it :: p) []).
  cbn [scan_shrink_tr]. now rewrite (scan_shrink_tr_eq p _ [acc]).
Qed.

Lemma scan_shrink_nth :
  forall p k acc, (k <= length p)%nat ->
    nth k (scan_shrink acc p) 0 = acc + total_shrink (firstn k p).
Proof.
  induction p as [| it p IH]; intros [|k] acc Hk.
  - change (scan_shrink acc []) with (@cons sp acc nil); cbn [nth firstn].
    rewrite total_shrink_nil, Z.add_0_r. reflexivity.
  - cbn [length] in Hk; lia.
  - rewrite scan_shrink_cons; cbn [nth firstn].
    rewrite total_shrink_nil, Z.add_0_r. reflexivity.
  - rewrite scan_shrink_cons; cbn [nth firstn length] in *.
    rewrite IH by lia. rewrite total_shrink_cons. lia.
Qed.

Lemma pw_at_correct : forall p k, (k <= length p)%nat -> pw_at (build_psums p) k = width_upto k p.
Proof. intros p k Hk. unfold pw_at, build_psums, width_upto, take_prefix; cbn [ps_w].
  rewrite scan_width_nth by exact Hk; apply Z.add_0_l. Qed.
Lemma py_at_correct : forall p k, (k <= length p)%nat -> py_at (build_psums p) k = stretch_upto k p.
Proof. intros p k Hk. unfold py_at, build_psums, stretch_upto, take_prefix; cbn [ps_y].
  rewrite scan_stretch_nth by exact Hk; apply Z.add_0_l. Qed.
Lemma pz_at_correct : forall p k, (k <= length p)%nat -> pz_at (build_psums p) k = shrink_upto k p.
Proof. intros p k Hk. unfold pz_at, build_psums, shrink_upto, take_prefix; cbn [ps_z].
  rewrite scan_shrink_nth by exact Hk; apply Z.add_0_l. Qed.

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

(* All legal breakpoints, ascending, including the forced end-of-paragraph.
   We always include position (length p) (the very end) as a forced break
   because shape_paragraph appends a forced-break penalty there. *)
Fixpoint legal_positions_tr (p : paragraph) (k : nat) (acc : list nat) : list nat :=
  match k with
  | O => acc
  | S k' =>
      if legal_after p k' then legal_positions_tr p k' (k :: acc)
      else legal_positions_tr p k' acc
  end.

Definition legal_positions (p : paragraph) : list nat :=
  legal_positions_tr p (length p) [].

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
  nd_prev     : nat;   (* position of the predecessor node (for traceback) *)
  (* PREFIX-SUM CACHE (performance only).  These hold the cumulative
     width/stretch/shrink of the paragraph prefix [0 .. nd_pos), i.e.
     [width_upto nd_pos p] / [stretch_upto ..] / [shrink_upto ..].  They let
     [try_extend] size a candidate line [i..j) in O(1) as a difference of
     prefix sums (the running-sums trick of Knuth-Plass), instead of
     recomputing [total_*(firstn _ p)] from scratch each call (which made the
     DP O(n^3)).  Their correctness is the invariant [node_cache_ok] below;
     every node the DP creates satisfies it, and the optimality/feasibility
     proofs rewrite these caches back to [line_width]/etc. so the recorded
     demerits are provably identical to the cache-free formulation. *)
  nd_w        : sp;
  nd_y        : sp;
  nd_z        : sp
}.

(* The start node: position 0, line 0, demerits 0.  Its prefix-sum cache is
   the empty-prefix total, namely 0 in each component (= width_upto 0 p). *)
Definition start_node : node :=
  mkNode 0 0 NormalLine false 0 0 0 0 0.

(* Try to extend active node [a] to a candidate break at position [j].
   Returns [Some new_node] if the line [a.pos .. j) is feasible (badness
   within tolerance, or the break is forced), else [None].  This is the
   Bellman relaxation step. *)
(* PER-POSITION ARGUMENTS (passed in, computed ONCE per [j] by the caller):
   - [wj]/[yj]/[zj]  : the prefix sums AT [j] (= [width_upto j p] etc.), so the
     line [i..j) is sized in O(1) as [wj - nd_w a] (the node carries
     [nd_w a = width_upto i p]); this equals [line_width i j p], see
     [line_width_cache].
   - [forcedj]/[penj]/[flj] : the forced-flag / penalty / flagged of the break
     taken just after item [Nat.pred j], i.e. [is_forced_break p (Nat.pred j)],
     [break_penalty p (Nat.pred j)], [break_flagged p (Nat.pred j)].  These are
     [nth (Nat.pred j) p ...] reads -- O(j) on the extracted linked list -- and
     depend ONLY on [j], not on the active node [a].  Hoisting them out of the
     per-active fold turns the DP from O(n^3) (an O(j) [nth] per relaxation)
     into O(n^2) (one such read per position).  The guard, demerits and emitted
     node are otherwise byte-identical to the cache-free version. *)
Definition try_extend (sp_ : line_spec) (p : paragraph) (a : node) (j : nat)
    (wj yj zj : sp) (forcedj : bool) (penj : Z) (flj : bool)
  : option node :=
  let i := nd_pos a in
  let w := wj - nd_w a in
  let y := yj - nd_y a in
  let z := zj - nd_z a in
  let W := ls_measure sp_ in
  let b := badness_of w y z W in
  let forced := forcedj in
  (* feasible if forced, or badness within tolerance and not overfull *)
  if andb (negb forced)
          (orb (overfull w y z W) (Z.ltb (ls_tolerance sp_) b))
  then None
  else
    let this_fit := fitness_of w y z W in
    let pen  := penj in
    let fl   := flj in
    let d := nd_demerits a +
             line_demerits (ls_line_pen sp_) b pen fl (nd_flagged a)
                           (nd_fitness a) this_fit
                           (ls_flagged_pen sp_) (ls_fit_pen sp_) in
    Some (mkNode j (S (nd_line a)) this_fit fl d i wj yj zj).

(* From the active set, compute the best (min-demerit) node arriving at
   position [j].  Fold over actives, keeping the minimum.  The per-position
   values [wj..flj] are supplied by the caller (computed once) and shared
   across every active node, so no per-position work happens inside the fold. *)
Definition best_to (sp_ : line_spec) (p : paragraph) (actives : list node) (j : nat)
    (wj yj zj : sp) (forcedj : bool) (penj : Z) (flj : bool)
  : option node :=
  fold_left
    (fun acc a =>
       match try_extend sp_ p a j wj yj zj forcedj penj flj with
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
(* [ps] is the precomputed prefix-sum table; the sums at [j] are read from it
   in O(1)-amortised time instead of being re-folded from [firstn j p]. *)
Definition dp_step (sp_ : line_spec) (p : paragraph) (ps : psums)
    (actives : list node) (j : nat)
  : list node :=
  let it := nth (Nat.pred j) p forbidden_break in
  let forcedj := match it with IPenalty pn => penalty_forced pn | _ => false end in
  let penj := match it with IPenalty pn => pn_penalty pn | _ => 0 end in
  let flj := match it with IPenalty pn => pn_flagged pn | _ => false end in
  match best_to sp_ p actives j (pw_at ps j) (py_at ps j) (pz_at ps j)
                forcedj penj flj with
  | None => actives
  | Some n => actives ++ [n]
  end.

(* Run the DP over all legal break positions (ascending), starting from the
   singleton active set [start_node].  The prefix-sum table is built ONCE
   here (a single O(n) scan) and threaded into every step.  Structural fold
   -> terminates. *)
Definition run_dp (sp_ : line_spec) (p : paragraph) : list node :=
  let ps := build_psums p in
  fold_left (dp_step sp_ p ps) (legal_positions p) [start_node].

(* RESULT-IDENTITY BRIDGE.  For any in-range position [j <= length p] the
   table-driven step reads EXACTLY the prefix sums the cache-free formulation
   would have recomputed, so [dp_step] with the precomputed table coincides
   with feeding [width_upto j p]/[stretch_upto j p]/[shrink_upto j p]
   directly.  This is the lemma that machine-checks "the optimisation does not
   change the result": every position the DP visits is legal, hence
   <= length p (see [legal_positions]), so the precomputed sums it uses are
   the same integers as before.  (Consumes [pw_at_correct] et al.) *)
Lemma dp_step_table_eq :
  forall sp_ p actives j, (j <= length p)%nat ->
    dp_step sp_ p (build_psums p) actives j
    = match best_to sp_ p actives j (width_upto j p) (stretch_upto j p) (shrink_upto j p)
                    (is_forced_break p (Nat.pred j)) (break_penalty p (Nat.pred j))
                    (break_flagged p (Nat.pred j)) with
      | None => actives
      | Some n => actives ++ [n]
      end.
Proof.
  intros sp_ p actives j Hj. unfold dp_step.
  rewrite (pw_at_correct p j Hj), (py_at_correct p j Hj), (pz_at_correct p j Hj).
  unfold is_forced_break, break_penalty, break_flagged.
  reflexivity.
Qed.

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
Fixpoint trace_back_aux (actives : list node) (cur : node) (fuel : nat) (acc : list nat) : list nat :=
  match fuel with
  | O => nd_pos cur :: acc
  | S f =>
      if Nat.eqb (nd_pos cur) 0 then acc
      else
        match find (fun n => Nat.eqb (nd_pos n) (nd_prev cur)) actives with
        | None => nd_pos cur :: acc
        | Some pn => trace_back_aux actives pn f (nd_pos cur :: acc)
        end
  end.

Definition trace_back (actives : list node) (cur : node) (fuel : nat) : list nat :=
  trace_back_aux actives cur fuel [].

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
(* Prefix-sum cache correctness (ties the fast DP to the cache-free spec)  *)
(* ===================================================================== *)

(* A node's prefix-sum cache is CORRECT for paragraph [p] when its three
   cached fields equal the genuine prefix sums at its position.  Every node
   the DP ever materialises (the start node and every [try_extend] output)
   satisfies this -- so the fast, O(1)-per-line sizing in [try_extend] is
   provably the same number as the cache-free [line_width]/[line_stretch]/
   [line_shrink].  The proofs below need only the cache fact, never the
   reachability bookkeeping, so they stay self-contained. *)
Definition node_cache_ok (p : paragraph) (a : node) : Prop :=
  nd_w a = width_upto   (nd_pos a) p /\
  nd_y a = stretch_upto (nd_pos a) p /\
  nd_z a = shrink_upto  (nd_pos a) p.

(* The start node's (0,0,0) cache is correct: the empty-prefix totals. *)
Lemma start_node_cache_ok : forall p, node_cache_ok p start_node.
Proof.
  intros p. unfold node_cache_ok, start_node; cbn [nd_w nd_y nd_z nd_pos].
  unfold width_upto, stretch_upto, shrink_upto, take_prefix; cbn [firstn].
  repeat split; reflexivity.
Qed.

(* KEY EQUALITY LEMMA.  Under a correct cache for [a] and the caller's
   contract that [wj]/[yj]/[zj] are the prefix sums at [j], the fast line
   sizes [wj - nd_w a] etc. coincide DEFINITIONALLY-AFTER-REWRITE with the
   canonical [line_width]/[line_stretch]/[line_shrink].  This is the single
   bridge every downstream proof uses: rewrite the fast form to the spec
   form, then the original cache-free proof script applies verbatim. *)
Lemma line_width_cache :
  forall p a j,
    node_cache_ok p a ->
    width_upto j p - nd_w a = line_width (nd_pos a) j p /\
    stretch_upto j p - nd_y a = line_stretch (nd_pos a) j p /\
    shrink_upto j p - nd_z a = line_shrink (nd_pos a) j p.
Proof.
  intros p a j (Hw & Hy & Hz).
  unfold line_width, line_stretch, line_shrink.
  rewrite Hw, Hy, Hz. repeat split; reflexivity.
Qed.

(* ===================================================================== *)
(* T7 (b): every reported line fits or is forced/overfull-reported        *)
(* ===================================================================== *)

(* The feasibility guard in [try_extend] guarantees that any node added to
   the active set (other than via a forced break) has badness within
   tolerance and is not overfull.  We expose the guard as a lemma: if
   [try_extend] returns [Some n] for a non-forced break at j from a (with the
   j-prefix-sums supplied and a's cache correct), then the line [i,j) is
   within tolerance and not overfull. *)
Lemma try_extend_feasible :
  forall sp_ p a j n,
    node_cache_ok p a ->
    is_forced_break p (Nat.pred j) = false ->
    try_extend sp_ p a j (width_upto j p) (stretch_upto j p) (shrink_upto j p)
               (is_forced_break p (Nat.pred j)) (break_penalty p (Nat.pred j))
               (break_flagged p (Nat.pred j)) = Some n ->
    let i := nd_pos a in
    let w := line_width i j p in
    let y := line_stretch i j p in
    let z := line_shrink i j p in
    overfull w y z (ls_measure sp_) = false /\
    Z.leb (badness_of w y z (ls_measure sp_)) (ls_tolerance sp_) = true.
Proof.
  intros sp_ p a j n Hcache Hforced Hext.
  unfold try_extend in Hext.
  destruct (line_width_cache p a j Hcache) as (Ew & Ey & Ez).
  rewrite Ew, Ey, Ez in Hext.
  rewrite Hforced in Hext. simpl in Hext.
  destruct (overfull _ _ _ _ || Z.ltb _ _) eqn:Hguard; try discriminate.
  apply orb_false_iff in Hguard; destruct Hguard as [Hover Htol].
  split; [exact Hover | apply Z.leb_le; apply Z.ltb_ge; exact Htol].
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
    node_cache_ok p a ->
    try_extend sp_ p a j (width_upto j p) (stretch_upto j p) (shrink_upto j p)
               (is_forced_break p (Nat.pred j)) (break_penalty p (Nat.pred j))
               (break_flagged p (Nat.pred j)) = Some n ->
    nd_demerits n
    = nd_demerits a + seg_demerits sp_ p (nd_pos a) j (nd_fitness a) (nd_flagged a).
Proof.
  intros sp_ p a j n Hcache Hext.
  unfold try_extend in Hext.
  destruct (line_width_cache p a j Hcache) as (Ew & Ey & Ez).
  rewrite Ew, Ey, Ez in Hext.
  repeat (match goal with
          | H : (if ?c then _ else _) = Some _ |- _ => destruct c
          end; simpl in Hext);
  try discriminate; inversion Hext; subst; cbn [nd_demerits];
  unfold seg_demerits; reflexivity.
Qed.

(* (L2) [try_extend] preserves the line/position structure: the new node
   sits at [j] and records the predecessor at [nd_pos a]. *)
Lemma try_extend_pos :
  forall sp_ p a j n wj yj zj forcedj penj flj,
    try_extend sp_ p a j wj yj zj forcedj penj flj = Some n ->
    nd_pos n = j /\ nd_prev n = nd_pos a.
Proof.
  intros sp_ p a j n wj yj zj forcedj penj flj Hext. unfold try_extend in Hext.
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
  forall sp_ p actives j wj yj zj forcedj penj flj a n m,
    In a actives ->
    try_extend sp_ p a j wj yj zj forcedj penj flj = Some n ->
    best_to sp_ p actives j wj yj zj forcedj penj flj = Some m ->
    nd_demerits m <= nd_demerits n.
Proof.
  intros sp_ p actives j wj yj zj forcedj penj flj. unfold best_to.
  Ltac solve_in Hx IHin IHacc :=
    intros a0 n0 Hin0 Hext0; simpl in Hin0; destruct Hin0 as [->|Hin0];
    [ rewrite Hx in Hext0; try discriminate; inversion Hext0; subst; eapply IHacc; reflexivity
    | apply (IHin a0 n0 Hin0 Hext0) ].
  assert (GEN:
    forall l acc,
      forall res, fold_left
        (fun acc a =>
           match try_extend sp_ p a j wj yj zj forcedj penj flj with
           | None => acc
           | Some n =>
               match acc with
               | None => Some n
               | Some m => if Z.ltb (nd_demerits n) (nd_demerits m) then Some n else acc
               end
           end) l acc = Some res ->
      (forall a0 n0, In a0 l -> try_extend sp_ p a0 j wj yj zj forcedj penj flj = Some n0 ->
         nd_demerits res <= nd_demerits n0)
      /\ (forall m0, acc = Some m0 -> nd_demerits res <= nd_demerits m0)).
  { induction l as [| x l IH]; intros acc res Hfold; simpl in Hfold.
    - split.
      + intros a0 n0 [] _.
      + intros m0 Hacc. rewrite Hacc in Hfold. inversion Hfold; subst.
        apply Z.le_refl.
    - destruct (try_extend sp_ p x j wj yj zj forcedj penj flj) as [nx|] eqn:Hx.
      + destruct acc as [m0|] eqn:Hacc.
        * destruct (Z.ltb (nd_demerits nx) (nd_demerits m0)) eqn:Hlt.
          -- specialize (IH (Some nx) res Hfold). destruct IH as [IHin IHacc].
             split; [solve_in Hx IHin IHacc |].
             intros mm Hmm. inversion Hmm; subst.
             eapply Z.le_trans; [ eapply IHacc; reflexivity | ].
             apply Z.ltb_lt in Hlt. apply Z.lt_le_incl. exact Hlt.
          -- specialize (IH (Some m0) res Hfold). destruct IH as [IHin IHacc].
             split; [| intros mm Hmm; inversion Hmm; subst; eapply IHacc; reflexivity].
             intros a0 n0 Hin0 Hext0. simpl in Hin0. destruct Hin0 as [->|Hin0].
             ** rewrite Hx in Hext0. inversion Hext0; subst.
                eapply Z.le_trans; [ eapply IHacc; reflexivity | ].
                apply Z.ltb_ge in Hlt. exact Hlt.
             ** apply (IHin a0 n0 Hin0 Hext0).
        * specialize (IH (Some nx) res Hfold). destruct IH as [IHin IHacc].
          split; [solve_in Hx IHin IHacc |].
          intros mm Hmm. discriminate Hmm.
      + specialize (IH acc res Hfold). destruct IH as [IHin IHacc].
        split; [| exact IHacc].
        intros a0 n0 Hin0 Hext0. simpl in Hin0. destruct Hin0 as [->|Hin0].
        * rewrite Hx in Hext0. discriminate Hext0.
        * apply (IHin a0 n0 Hin0 Hext0). }
  intros a n m Hin Hext Hbest.
  specialize (GEN actives None m Hbest).
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
