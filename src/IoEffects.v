(* IoEffects.v — process-IO effect algebra for the CLI tools.

   Crane's [Monads.IO]/[Monads.Dir] cover stdout/stdin, file read/write, and
   directory ops, but NOT command-line arguments, environment variables,
   stderr, or process exit.  This module adds a [toolE] effect for exactly
   those, following Crane's own pattern ([Crane Extract Inductive consoleE]
   + per-op [Crane Extract Inlined Constant]), and defines the combined
   [IO := itree (dirE +' ioE +' toolE)] used by EncryptPost.v / DecryptPost.v.

   The C++ realization lives in src/crypto_helpers.h (process-IO shim,
   FFI boundary C-catalog): argv globals, std::getenv, std::cerr, std::exit.
   The dune-generated main.cpp captures argc/argv via [tool_set_args]. *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree Monads.IO Monads.Dir.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.

Open Scope pstring_scope.

(* ---- The toolE effect --------------------------------------------- *)

Inductive toolE : Type -> Type :=
| ArgCount : toolE int
| ArgGet   : int -> toolE string
| GetEnv   : string -> toolE string
| EPrint   : string -> toolE unit
| ExitWith : int -> toolE unit.

(* Smart constructors (mirror IODefs.v's [print]/[read] style). *)
Definition arg_count {E} `{toolE -< E} : itree E int :=
  embed ArgCount.
Definition arg_get {E} `{toolE -< E} (i : int) : itree E string :=
  embed (ArgGet i).
Definition getenv {E} `{toolE -< E} (name : string) : itree E string :=
  embed (GetEnv name).
Definition eprint {E} `{toolE -< E} (s : string) : itree E unit :=
  embed (EPrint s).
Definition exit_with {E} `{toolE -< E} (code : int) : itree E unit :=
  embed (ExitWith code).

(* ---- The combined tool IO monad ----------------------------------- *)

(* As in Logic.v, [IO] is a [Notation] (not a [Definition]) so it unfolds at
   extraction time, preserving Crane's monad-table dispatch.  A 3-way [+']
   sum is fine — extraction is per-operation, not per-sum-shape. *)
Notation IO := (itree (dirE +' ioE +' toolE)).

(* ---- Crane C++ extraction for toolE ------------------------------- *)

(* Positional mapping of the five constructors, in declaration order.
   [tool_exit] never returns; the ROCQ side binds it then [Ret tt], so the
   trailing expression is dead. *)
Crane Extract Inductive toolE => ""
  [ "tool_arg_count()"
    "tool_arg_get(%a0)"
    "tool_getenv(%a0)"
    "tool_eprint(%a0)"
    "tool_exit(%a0)" ]
  From "crypto_helpers.h".

Crane Extract Inlined Constant arg_count =>
  "tool_arg_count()" From "crypto_helpers.h".
Crane Extract Inlined Constant arg_get =>
  "tool_arg_get(%a0)" From "crypto_helpers.h".
Crane Extract Inlined Constant getenv =>
  "tool_getenv(%a0)" From "crypto_helpers.h".
Crane Extract Inlined Constant eprint =>
  "tool_eprint(%a0)" From "crypto_helpers.h".
Crane Extract Inlined Constant exit_with =>
  "tool_exit(%a0)" From "crypto_helpers.h".
