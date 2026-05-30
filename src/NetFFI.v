(* NetFFI.v — POSIX socket effect algebra [netE] for the SMTP listener.

   Crane's [Monads.IO]/[Monads.Dir] cover stdout/file/dir IO but not network
   sockets.  This module adds a [netE] effect (listen/accept/recv-line/
   recv-bytes/send/close) following Crane's own extraction pattern
   ([Crane Extract Inductive] + per-op [Crane Extract Inlined Constant]),
   mirroring IoEffects.v's [toolE].

   Sockets and connections are plain int file descriptors (Crane int63 ->
   int64_t).  The C++ realization (FFI boundary C5) lives in src/net_helpers.h:
   socket/bind/listen/accept/recv/send/close — pure syscall plumbing with ZERO
   SMTP/MIME/git knowledge.  The sequential accept-loop model (one connection
   at a time) is sufficient for the low-volume Tailscale-bound listener.

   De-risked by an echo-server spike (Crane realizes a blocking accept-loop
   cleanly — no callback shim needed). *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.

Open Scope pstring_scope.

(* ---- The netE effect ----------------------------------------------- *)

Inductive netE : Type -> Type :=
| Listen    : string -> int -> netE int      (* host, port -> listen fd (-1 err) *)
| Accept    : int -> netE int                 (* listen fd -> conn fd (-1 err) *)
| RecvLine  : int -> netE string              (* conn fd -> one line incl '\n', "" EOF *)
| RecvBytes : int -> int -> netE string        (* conn fd, n -> up to n bytes *)
| Send      : int -> string -> netE int        (* conn fd, data -> 0 ok / -1 err *)
| Close     : int -> netE unit.                (* fd -> unit *)

(* Smart constructors (mirror IODefs.v's [read]/[write_file] style). *)
Definition net_listen {E} `{netE -< E} (host : string) (port : int) : itree E int :=
  embed (Listen host port).
Definition net_accept {E} `{netE -< E} (lfd : int) : itree E int :=
  embed (Accept lfd).
Definition net_recv_line {E} `{netE -< E} (cfd : int) : itree E string :=
  embed (RecvLine cfd).
Definition net_recv_bytes {E} `{netE -< E} (cfd : int) (n : int) : itree E string :=
  embed (RecvBytes cfd n).
Definition net_send {E} `{netE -< E} (cfd : int) (data : string) : itree E int :=
  embed (Send cfd data).
Definition net_close {E} `{netE -< E} (fd : int) : itree E unit :=
  embed (Close fd).

(* ---- Crane C++ extraction for netE --------------------------------- *)

(* Positional mapping of the six constructors, in declaration order.  Realized
   by src/net_helpers.h (POSIX sockets). *)
Crane Extract Inductive netE => ""
  [ "net_listen(%a0, %a1)"
    "net_accept(%a0)"
    "net_recv_line(%a0)"
    "net_recv_bytes(%a0, %a1)"
    "net_send(%a0, %a1)"
    "net_close(%a0)" ]
  From "net_helpers.h".

Crane Extract Inlined Constant net_listen =>
  "net_listen(%a0, %a1)" From "net_helpers.h".
Crane Extract Inlined Constant net_accept =>
  "net_accept(%a0)" From "net_helpers.h".
Crane Extract Inlined Constant net_recv_line =>
  "net_recv_line(%a0)" From "net_helpers.h".
Crane Extract Inlined Constant net_recv_bytes =>
  "net_recv_bytes(%a0, %a1)" From "net_helpers.h".
Crane Extract Inlined Constant net_send =>
  "net_send(%a0, %a1)" From "net_helpers.h".
Crane Extract Inlined Constant net_close =>
  "net_close(%a0)" From "net_helpers.h".
