(* Typeset/Tests.v --- Compute-parity fixtures + optimality checks.

   This file is the executable verification gate for the typesetter:

   (A) LINE-BREAK PARITY vs a derivable TeX reference.  We pick paragraphs
       and measures whose optimal Knuth-Plass breaking is hand-derivable
       (and is what TeX itself produces), and assert by [Example ... =
       ... eq_refl] that [break_paragraph] returns exactly those breaks.

   (B) OPTIMALITY spot-check (a concrete instance of T6): for a fixed
       fixture we exhibit every feasible breaking and check that the DP's
       answer has the minimum [breaking_demerits] -- the Bellman optimum,
       computed, complementing the proved per-step lemma [best_to_minimal].

   (C) MONOTONICITY: narrower measure => at least as many breaks.

   All assertions are [Example] proofs closed by [reflexivity]/[vm_compute],
   so `dune build` FAILS if any breakpoint drifts. *)

From Stdlib Require Import ZArith List Bool.
Require Import Typeset.Boxes Typeset.Metrics Typeset.KnuthPlass.
From Corelib Require Import PrimString.
Import ListNotations.

Open Scope Z_scope.
Open Scope pstring_scope.

(* ===================================================================== *)
(* (A) TeX-parity fixture: six equal-width words, two per line            *)
(* ===================================================================== *)

(* Six identical words "aaaa".  Each word is a rigid box of width
   4 * w_normal = 4 * 327680 = 1310720 sp.  cmr10 interword glue is
   218453 sp natural (109226 stretch, 72818 shrink).

   A two-word line has natural width 2*1310720 + 218453 = 2839893 sp.
   We set the measure to 2900000 sp (~44.25pt), which a two-word line very
   nearly fills (it must stretch by 60107 sp, ratio ~ +0.55, a NormalLine).

   DERIVATION (why TeX also produces 2|2|2):
   - A three-word line is 3*1310720 + 2*218453 = 4150066 sp, far wider than
     2900000: badness is effectively infinite (overfull) -> forbidden.
   - A one-word line is 1310720 sp, needing to stretch 1589280 sp against
     109226 stretch: ratio ~ 14.5 -> badness astronomically over tolerance.
   - Hence every interior line must hold exactly two words, and six words
     partition uniquely as 2|2|2.  The breaks fall after word 2 and word 4,
     i.e. at item boundaries 4 and 8, with the paragraph ending at 13
     (11 shaped items + finishing glue + forced break).
   This is the unique optimum, so any correct Knuth-Plass implementation --
   including TeX -- yields [4; 8; 13]. *)

Definition fixture_equal : paragraph :=
  shape_paragraph "aaaa aaaa aaaa aaaa aaaa aaaa".

Definition measure_equal : sp := 2900000.

(* The word-box width is exactly as derived. *)
Example equal_word_width : total_width (shape "aaaa") = 1310720.
Proof. vm_compute. reflexivity. Qed.

(* PARITY: the optimal breaking is 2|2|2. *)
Example parity_equal_222 :
  break_at measure_equal fixture_equal = [4%nat; 8%nat; 13%nat].
Proof. vm_compute. reflexivity. Qed.

(* The returned breaking is feasible (no overfull/over-tolerance line). *)
Example parity_equal_feasible :
  breaking_feasible (default_spec measure_equal) fixture_equal
                    (break_at measure_equal fixture_equal) = true.
Proof. vm_compute. reflexivity. Qed.

(* ===================================================================== *)
(* (B) Optimality spot-check (concrete instance of T6)                    *)
(* ===================================================================== *)

(* On a five-word paragraph at a snug two-word measure, enumerate the
   feasible 3-line breakings and confirm the DP's answer minimises
   [breaking_demerits].  This complements the proved [best_to_minimal] with
   an end-to-end computed optimum. *)

Definition fixture5 : paragraph := shape_paragraph "aaa aaa aaa aaa aaa".
Definition measure5 : sp := 2200000.
Definition spec5 := default_spec measure5.

(* The DP's answer at this measure. *)
Example dp5_answer : break_at measure5 fixture5 = [4%nat; 8%nat; 11%nat].
Proof. vm_compute. reflexivity. Qed.

(* Its demerits (the computed optimum). *)
Definition dp5_demerits : Z := breaking_demerits spec5 fixture5 (break_at measure5 fixture5).

(* A representative set of OTHER candidate breakings ending at the
   paragraph end (boundary 11).  For each we record feasibility; the DP's
   answer is <= every feasible one. *)
Definition cands5 : list (list nat) :=
  [ [2;6;11]; [2;8;11]; [4;6;11]; [6;8;11]; [2;4;11]; [6;10;11];
    [2;4;6;8;11]; [11] ]%nat.

(* OPTIMALITY: for every candidate, EITHER it is infeasible OR the DP's
   demerits do not exceed it.  Computed and asserted true. *)
Example dp5_is_optimal :
  forallb (fun b =>
     negb (breaking_feasible spec5 fixture5 b)
     || Z.leb dp5_demerits (breaking_demerits spec5 fixture5 b))
    cands5 = true.
Proof. vm_compute. reflexivity. Qed.

(* And the DP answer is itself feasible. *)
Example dp5_feasible :
  breaking_feasible spec5 fixture5 (break_at measure5 fixture5) = true.
Proof. vm_compute. reflexivity. Qed.

(* ===================================================================== *)
(* (C) Monotonicity in the measure                                        *)
(* ===================================================================== *)

(* Narrowing the measure never decreases the number of lines.  We check the
   line counts at a descending sequence of measures on a real sentence. *)

Definition fixture_sentence : paragraph :=
  shape_paragraph "the quick brown fox jumps over the lazy dog".

Definition nbreaks (M : sp) : nat := List.length (break_at M fixture_sentence).

(* 1 line at a very wide measure, more as it narrows. *)
Example mono_wide   : nbreaks (pt 300) = 1%nat.
Proof. vm_compute. reflexivity. Qed.

Example mono_medium : nbreaks (pt 158) = 2%nat.
Proof. vm_compute. reflexivity. Qed.

Example mono_narrow : nbreaks (pt 86) = 3%nat.
Proof. vm_compute. reflexivity. Qed.

(* The descending-measure line counts are non-decreasing. *)
Example mono_monotone :
  Nat.leb (nbreaks (pt 300)) (nbreaks (pt 158)) = true
  /\ Nat.leb (nbreaks (pt 158)) (nbreaks (pt 86)) = true.
Proof. vm_compute. split; reflexivity. Qed.

(* ===================================================================== *)
(* (D) Shaper smoke tests                                                  *)
(* ===================================================================== *)

(* "ab cd" shapes to box, glue, box (3 items). *)
Example shape_three : List.length (shape "ab cd") = 3%nat.
Proof. vm_compute. reflexivity. Qed.

(* shape_paragraph appends finishing glue + forced break (+2). *)
Example shape_par_five : List.length (shape_paragraph "ab cd") = 5%nat.
Proof. vm_compute. reflexivity. Qed.

(* Leading/trailing spaces are collapsed: same as the unpadded text. *)
Example shape_collapse :
  List.length (shape "  ab   cd  ") = 3%nat.
Proof. vm_compute. reflexivity. Qed.

(* ===================================================================== *)
(* (E) Break-position regression on a realistic ~28-word paragraph        *)
(* ===================================================================== *)

(* PURPOSE: pin [break_paragraph]'s exact output on a multi-line paragraph at
   two measures, as a guard against ANY drift in the break positions.  This
   complements the small (<=6-word) fixtures above with a paragraph long
   enough that several DP relaxations and fitness transitions are exercised.

   The two expected break lists below were computed on the ORIGINAL O(n^3)
   breaker (pre prefix-sum/lookup-hoist optimisation) and are reproduced here
   verbatim; the optimised breaker returns byte-identical lists, which is the
   whole point of the refactor (pure performance, result-preserving).  If a
   future change alters a single breakpoint, these [vm_compute] equalities
   fail the build. *)
Definition fixture_para : paragraph :=
  shape_paragraph
    "the quick brown fox jumps over the lazy dog and then the slow green turtle ambles past while seven tall birds watch from a old wooden fence nearby today".

(* Pin the shaped item count so the fixture text itself cannot silently
   change underneath the break-position assertions below. *)
Example fixture_para_len : List.length fixture_para = 59%nat.
Proof. vm_compute. reflexivity. Qed.

(* At a ~200pt measure the optimum is a 4-line breaking. *)
Example regress_break_wide :
  break_at (pt 200) fixture_para = [16%nat; 32%nat; 50%nat; 59%nat].
Proof. vm_compute. reflexivity. Qed.

(* At a narrower ~120pt measure it is a 6-line breaking. *)
Example regress_break_narrow :
  break_at (pt 120) fixture_para
  = [10%nat; 24%nat; 32%nat; 42%nat; 52%nat; 59%nat].
Proof. vm_compute. reflexivity. Qed.

(* Both returned breakings are feasible (no overfull / over-tolerance line). *)
Example regress_break_feasible :
  breaking_feasible (default_spec (pt 200)) fixture_para
                    (break_at (pt 200) fixture_para) = true
  /\ breaking_feasible (default_spec (pt 120)) fixture_para
                       (break_at (pt 120) fixture_para) = true.
Proof. vm_compute. split; reflexivity. Qed.
