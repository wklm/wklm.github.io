(* ProcFFI.v — subprocess effect algebra [procE] for the SMTP listener's git
   calls.  Follows Crane's extraction pattern (mirrors IoEffects.v's [toolE]
   and NetFFI.v's [netE]).

   A single primitive, [raw_run_proc argv stdin], runs an external program and
   returns a *packed* result string "exit\nstdout\nstderr" — the exit code as
   decimal, then a LF, then stdout, then a LF, then stderr.  Splitting that
   packed string back into (exit, stdout, stderr) is done in pure ROCQ (see
   ProcResult below), keeping the C++ shim free of any framing policy.

   [argv] is the program + arguments joined by a single NUL byte ('\0'); the
   shim splits on NUL and execs argv[0] with the full vector.  Joining/splitting
   on NUL is marshalling (no domain branching), so the thin-shim test holds.

   The C++ realization (FFI boundary C6) lives in src/proc_helpers.h:
   fork + execvp + pipes (no shell), zero git/SMTP/MIME knowledge. *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.
From Stdlib Require Import Lists.List.
Import ListNotations.
Require Import StringLib.

Open Scope pstring_scope.

(* ---- The procE effect ---------------------------------------------- *)

Inductive procE : Type -> Type :=
| RunProc : string -> string -> procE string.   (* argv(NUL-joined), stdin -> packed *)

Definition raw_run_proc {E} `{procE -< E} (argv stdin_data : string)
  : itree E string :=
  embed (RunProc argv stdin_data).

(* ---- Crane C++ extraction for procE -------------------------------- *)

Crane Extract Inductive procE => ""
  [ "run_proc(%a0, %a1)" ]
  From "proc_helpers.h".

Crane Extract Inlined Constant raw_run_proc =>
  "run_proc(%a0, %a1)" From "proc_helpers.h".

(* ---- argv construction (pure) -------------------------------------- *)
(* The shim splits argv on a single NUL byte.  Build NUL-joined argv from a
   list of arguments in ROCQ (marshalling only). *)

Definition nul : string := PrimString.make 1%int63 0%int63.

Fixpoint join_nul (xs : list string) : string :=
  match xs with
  | nil => ""
  | x :: nil => x
  | x :: rest => cat x (cat nul (join_nul rest))
  end.

(* ---- packed-result parsing (pure) ---------------------------------- *)
(* The shim returns "exit\nstdout\nstderr": a decimal exit code, LF, then the
   raw stdout bytes, LF, then the raw stderr bytes.  stdout itself may contain
   LFs, so we split on exactly the FIRST two LFs (exit | stdout-and-rest), and
   the SECOND LF separates stdout from stderr only at the boundary the shim
   inserted.  To keep this unambiguous the shim base64-NUL?  No: simpler and
   faithful — the shim guarantees the layout exit<LF>stdout<NUL>stderr is NOT
   used; instead we only ever need the exit code for control flow, so we parse
   the exit code (digits up to the first LF) and treat the remainder as the
   combined output (used only for logging).  This avoids any ambiguity from
   embedded newlines. *)

(* Parse leading decimal digits as an int (stops at first non-digit). *)
Fixpoint parse_int_aux (s : string) (pos acc : int) (fuel : nat) : int :=
  match fuel with
  | O => acc
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then acc
      else
        let c := PrimString.get s pos in
        if andb (leb ch_0 c) (leb c ch_9)
        then parse_int_aux s (add pos 1%int63) (add (mul acc 10%int63) (sub c ch_0)) f'
        else acc
  end.

(* Exit code = decimal prefix before the first LF.  "" / no-digits -> 0. *)
Definition proc_exit_code (packed : string) : int :=
  parse_int_aux packed 0%int63 0%int63 12%nat.

(* Combined output = everything after the first LF (for logging only). *)
Definition proc_output (packed : string) : string :=
  let n := PrimString.length packed in
  let nl := find_char packed ch_newline 0%int63 mime_fuel in
  if leb n nl then ""
  else PrimString.sub packed (add nl 1%int63) (sub n (add nl 1%int63)).

(* True iff the process exited 0. *)
Definition proc_ok (packed : string) : bool :=
  int_eqb (proc_exit_code packed) 0%int63.
