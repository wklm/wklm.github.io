(* Smtp.v — pure SMTP command state machine + reply strings.

   A faithful, side-effect-free model of the verbs the listener handles:
   HELO / EHLO / MAIL FROM / RCPT TO / DATA / RSET / NOOP / QUIT, plus the
   in-DATA terminator line ".".  [step] maps (state, command line) to a new
   state and a reply string; the SmtpServer.v driver performs the socket IO
   and, on a completed DATA, the publish pipeline.

   This is the provable basis for T5 (SMTP state-machine safety: no 250 OK for
   a message without a prior successful MAIL FROM and the allowlist + parse
   checks).  The reply codes mirror smtp/listener.py:
     550 sender not allowed / 550 cannot parse / 550 no body / 451 processing
     failed / 250 OK, with 220/221/250/354/500/503 for protocol framing. *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* ---- Session state ------------------------------------------------- *)

(* Phase of the SMTP conversation. *)
Inductive phase : Type :=
| PInit            (* connected, banner sent, awaiting HELO/EHLO *)
| PReady           (* greeted; awaiting MAIL FROM *)
| PMail            (* MAIL FROM seen; awaiting RCPT / DATA *)
| PData            (* inside DATA; accumulating message lines *)
| PQuit.           (* client asked to QUIT; connection should close *)

Record sstate : Type := MkState {
  ph       : phase;
  sender   : string;       (* lowercased MAIL FROM address *)
  data_acc : string;       (* accumulated DATA bytes (with CRLFs) *)
}.

Definition init_state : sstate := MkState PInit "" "".

(* ---- Reply-code constants (the leading 3-digit + space) ------------ *)

Definition r220 : string := "220 ".
Definition r221 : string := "221 ".
Definition r250 : string := "250 ".
Definition r354 : string := "354 ".
Definition r451 : string := "451 ".
Definition r500 : string := "500 ".
Definition r503 : string := "503 ".
Definition r550 : string := "550 ".

(* CRLF for line-terminated replies (a pstring "\r\n" literal is 4 bytes). *)
Definition smtp_crlf : string := cat (PrimString.make 1%int63 13%int63)
                                     (PrimString.make 1%int63 10%int63).

Definition reply (code rest : string) : string := cat code (cat rest smtp_crlf).

(* ---- Command parsing ----------------------------------------------- *)
(* [upcase]/[downcase] (ASCII case folding) live in StringLib.v. *)

(* Strip a trailing line ending: a final LF (delivered by RecvLine), then a
   final CR.  RecvLine yields lines terminated by "\r\n" (CRLF) or bare "\n";
   [trim_trailing_cr] alone only removes a final CR, so a no-argument command
   line like "DATA\r\n" would keep its CRLF and never match a verb.  [chomp]
   removes the LF first, then the CR. *)
Definition chomp (line : string) : string :=
  let n := PrimString.length line in
  let no_lf :=
    if andb (leb 1%int63 n) (int_eqb (PrimString.get line (sub n 1%int63)) ch_newline)
    then PrimString.sub line 0%int63 (sub n 1%int63)
    else line in
  trim_trailing_cr no_lf.

(* The verb = the uppercased text up to the first space (or whole line). *)
Definition command_verb (line : string) : string :=
  let stripped := chomp line in
  let sp := find_char stripped ch_space 0%int63 mime_fuel in
  upcase (PrimString.sub stripped 0%int63 sp).

(* The argument = everything after the first space, trimmed. *)
Definition command_arg (line : string) : string :=
  let stripped := chomp line in
  let n := PrimString.length stripped in
  let sp := find_char stripped ch_space 0%int63 mime_fuel in
  if leb n sp then ""
  else trim (PrimString.sub stripped (add sp 1%int63) (sub n (add sp 1%int63))).

(* Extract the address from "FROM:<addr>" / "TO:<addr>" (after the verb).
   We take the substring between '<' and '>' if present, else the text after
   the first ':'.  Lowercased to match the allowlist convention. *)
Definition extract_addr (arg : string) : string :=
  let n := PrimString.length arg in
  let lt := find_char arg ch_lt 0%int63 mime_fuel in
  if ltb lt n then
    let gt := find_char arg ch_gt (add lt 1%int63) mime_fuel in
    if leb n gt then downcase (trim (PrimString.sub arg (add lt 1%int63) (sub n (add lt 1%int63))))
    else downcase (trim (PrimString.sub arg (add lt 1%int63) (sub gt (add lt 1%int63))))
  else
    let cl := find_char arg ch_colon 0%int63 mime_fuel in
    if leb n cl then downcase (trim arg)
    else downcase (trim (PrimString.sub arg (add cl 1%int63) (sub n (add cl 1%int63)))).

(* A line consisting solely of "." (after stripping the line ending)
   terminates DATA. *)
Definition is_data_terminator (line : string) : bool :=
  string_eqb (chomp line) ".".

(* ---- The step relation --------------------------------------------- *)
(* [step st line] returns (st', reply, data_complete?).  When the third
   component is true, the driver should run the publish pipeline on
   [st'.(data_acc)] (the message that was accumulated) and emit the final
   250/451/550 reply itself — so [step] returns the *neutral* placeholder
   "" reply in that one case (the driver overrides it). *)

(* Outside DATA: dispatch on the verb. *)
Definition step_command (st : sstate) (line : string) : sstate * string * bool :=
  let verb := command_verb line in
  let arg := command_arg line in
  if orb (string_eqb verb "HELO") (string_eqb verb "EHLO") then
    (MkState PReady "" "", reply r250 "OK", false)
  else if string_eqb verb "MAIL" then
    match st.(ph) with
    | PInit => (st, reply r503 "bad sequence: HELO first", false)
    | _ => (MkState PMail (extract_addr arg) "", reply r250 "OK", false)
    end
  else if string_eqb verb "RCPT" then
    match st.(ph) with
    | PMail => (st, reply r250 "OK", false)
    | _ => (st, reply r503 "bad sequence: MAIL first", false)
    end
  else if string_eqb verb "DATA" then
    match st.(ph) with
    | PMail => (MkState PData st.(sender) "",
                reply r354 "end data with <CR><LF>.<CR><LF>", false)
    | _ => (st, reply r503 "bad sequence: need MAIL/RCPT first", false)
    end
  else if string_eqb verb "RSET" then
    (MkState PReady "" "", reply r250 "OK", false)
  else if string_eqb verb "NOOP" then
    (st, reply r250 "OK", false)
  else if string_eqb verb "QUIT" then
    (MkState PQuit st.(sender) "", reply r221 "Bye", false)
  else
    (st, reply r500 "command not recognized", false).

(* Inside DATA: accumulate until the "." terminator. *)
Definition step_data (st : sstate) (line : string) : sstate * string * bool :=
  if is_data_terminator line then
    (* Hand the accumulated body to the driver; reply is driver-decided. *)
    (MkState PReady "" st.(data_acc), "", true)
  else
    (* Append the raw line verbatim (it already carries its CRLF from RecvLine).
       SMTP transparency (leading-dot un-stuffing) is not needed for the
       Mail.app senders in scope; bodies never begin a line with "..". *)
    (MkState PData st.(sender) (cat st.(data_acc) line), "", false).

Definition step (st : sstate) (line : string) : sstate * string * bool :=
  match st.(ph) with
  | PData => step_data st line
  | _ => step_command st line
  end.

(* ---- Greeting ------------------------------------------------------ *)

Definition greeting (banner : string) : string :=
  reply r220 (cat banner " Crane Blog SMTP").

(* ---- Allowlist check (pure) ---------------------------------------- *)
(* Empty allowlist accepts any sender; otherwise the lowercased sender must
   be a member.  [allow] is the parsed list of lowercased allowed addresses. *)
Fixpoint addr_in (a : string) (allow : list string) : bool :=
  match allow with
  | [] => false
  | x :: rest => if string_eqb x a then true else addr_in a rest
  end.

Definition sender_allowed (sender : string) (allow : list string) : bool :=
  match allow with
  | [] => true
  | _ => addr_in (downcase sender) allow
  end.

(* ===================================================================== *)
(*  T5 — SMTP state-machine safety                                       *)
(* ===================================================================== *)
(* The pure state machine never fabricates message acceptance: the only step
   that signals DATA completion ([data_done = true]) returns the *neutral*
   empty reply, deferring the final 250/451/550 to the driver (SmtpServer.v),
   which gates acceptance on [sender_allowed] + a non-empty parsed body.  So
   "no 250 without allowlist+parse pass" holds by construction. *)

(* Projections of the step triple. *)
Definition step_reply (st : sstate) (line : string) : string :=
  let '(_, rep, _) := step st line in rep.
Definition step_done (st : sstate) (line : string) : bool :=
  let '(_, _, d) := step st line in d.

(* Helpers extracting the components of a raw step triple. *)
Definition done_of (t : sstate * string * bool) : bool := let '(_, _, d) := t in d.
Definition reply_of (t : sstate * string * bool) : string := let '(_, r, _) := t in r.

Lemma step_command_done_false : forall st line,
  done_of (step_command st line) = false.
Proof.
  (* AIDEV-NOTE: the old [match ?p with _ => _ end => destruct p] matched the
     OUTER [let '(_,_,d) := ...] of done_of and destructed the result triple
     abstractly, leaving an opaque [b = false].  Case-split only on the dispatch
     CONDITIONS (verb if's + [ph st]); every leaf triple carries a literal
     [false], so done_of reduces and reflexivity closes each branch. *)
  intros st line. unfold step_command, done_of.
  repeat (match goal with
          | |- context[if ?c then _ else _] => destruct c
          | |- context[match ph st with _ => _ end] => destruct (ph st)
          end); reflexivity.
Qed.

(* (b)+(c) DATA completion happens only in the PData phase on the terminator
   line, and in that case the reply is exactly the neutral empty string. *)
Lemma data_done_in_data_phase : forall st line,
  step_done st line = true ->
  ph st = PData /\ is_data_terminator line = true.
Proof.
  intros st line. unfold step_done, step.
  destruct (ph st).
  1,2,3,5: pose proof (step_command_done_false st line) as H; unfold done_of in H; destruct (step_command st line) as [[? ?] d]; congruence.
  (* AIDEV-NOTE: PData branch — [congruence] cannot prove the conjunction goal in
     the terminator=true case (no contradiction there, unlike the command phases).
     Intro the [done = true] hyp, then split/discriminate per terminator value. *)
  unfold step_data, done_of. destruct (is_data_terminator line); intros Hd.
  - split; reflexivity.
  - discriminate Hd.
Qed.

Lemma data_done_reply_neutral : forall st line,
  step_done st line = true -> step_reply st line = "".
Proof.
  intros st line H.
  pose proof (data_done_in_data_phase st line H) as [Hph Ht].
  unfold step_reply, step. rewrite Hph. unfold step_data. rewrite Ht. reflexivity.
Qed.

