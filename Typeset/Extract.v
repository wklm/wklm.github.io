(* Typeset/Extract.v --- Crane extraction sanity driver.

   NOT part of the proof theory's logic: this file exists only to drive
   Crane (ROCQ->C++23) over the typesetter and confirm the extracted C++
   compiles natively under clang++ (catching std::any leaks and young-Crane
   recursion issues early, per the plan's verification gate).

   It extracts a single representative entry point [typeset_demo] that
   exercises the whole pipeline: shape a paragraph, run the Knuth-Plass
   breaker, and lay it out into the integer quad buffer.  The MSDF draw FFI
   (draw_glyph_quads) is the only boundary; we extract it as a no-op so no
   GL header is needed for this compile check. *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
(* Mapping.Std realizes [string]->std::string and [int]->native int;
   Mapping.NatIntStd maps [nat] to a native machine int (not unary Nat).
   Without these the primitives extract as [std::any] -- this is exactly
   what Logic.v imports for its working native extraction. *)
From Crane Require Import Mapping.Std Mapping.NatIntStd.
From Stdlib Require Import ZArith List.
Require Import Typeset.Boxes Typeset.Metrics Typeset.KnuthPlass
        Typeset.GlyphLayout.
Import ListNotations.

Open Scope Z_scope.

(* A self-contained entry: lay out a fixed demo paragraph at a measure
   given in WHOLE POINTS (converted to sp here) and return the number of
   glyph quads produced.  Taking the measure as [nat] points lets a C++
   driver call it with a plain integer (Z.of_nat extracts cleanly). *)
Definition typeset_demo (measure_pt : nat) : nat :=
  let measure : sp := pt (Z.of_nat measure_pt) in
  let p := shape_paragraph "the quick brown fox" in
  let buf := layout_paragraph advance_of measure p in
  List.length buf.

(* Extract the breaker entry too (the centerpiece), returning the number of
   lines for a measure in whole points. *)
Definition break_demo (measure_pt : nat) : nat :=
  let measure : sp := pt (Z.of_nat measure_pt) in
  List.length (break_at measure (shape_paragraph "the quick brown fox")).

(* draw_glyph_quads: realize as a no-op for the compile check (the real
   WASM build supplies the EM_ASM/Embind GL upload). *)
Crane Extract Inlined Constant draw_glyph_quads => "((void)%a0, std::monostate{})".

Crane Extraction "typeset_demo" typeset_demo break_demo.
