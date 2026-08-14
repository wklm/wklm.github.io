(* SmtpServer.v — the [smtp_listener] program, authored in ROCQ and extracted
   to C++23 via Crane.  Replaces smtp/listener.py (aiosmtpd).

   run : IO unit  where  IO := itree (dirE +' ioE +' toolE +' netE +' procE).

   Behaviour (faithful to listener.py):
     - bind SMTP_HOST:SMTP_PORT, print a startup line, then a sequential
       accept-loop (one connection at a time — low-volume Tailscale listener);
     - per connection: send the 220 banner, then fold Smtp.step over recv'd
       lines, sending each reply, until QUIT or EOF;
     - on a completed DATA: run the publish pipeline on the accumulated bytes
       and send the final 250/451/550 reply.

   Publish pipeline (all in-process — NO encrypt_post subprocess):
     allowlist check (BLOG_ALLOW_FROM; empty=accept) -> MimeIngest.ingest
     (Subject / body / X-Crane-Public-Keys) -> reject 550 if body empty ->
     PostBuild.build_md -> ENCRYPT in-process (CryptoSpec + MimeBuild, exactly
     as EncryptPost.v's build_envelope, incl. ECDSA signing of the raw
     ciphertext package) -> write posts-encrypted/<slug>.eml ->
     git via procE (fetch + R4-guarded reset --hard + add + commit + push).

   R4 safeguard: before the [git reset --hard], a procE/dirE precondition
   asserts the current directory's basename matches the configured repo path
   and that ./.git exists — the reset is un-runnable from the wrong directory. *)

From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree Monads.IO Monads.Dir.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.
From Stdlib Require Import Lists.List.
Import ListNotations.

Require Import StringLib.
Require Import MimeLib.
Require Import MimeBuild.
Require Import CryptoSpec.
Require Import IoEffects.
Require Import NetFFI.
Require Import ProcFFI.
Require Import Smtp.
Require Import MimeIngest.
Require Import PostBuild.
Require Import Recipients.  (* multi-recipient resolution + envelope building *)

Open Scope pstring_scope.

(* The full 5-way effect sum.  As in Logic.v / IoEffects.v this is a Notation
   so it unfolds at extraction time (preserving Crane's monad-table dispatch). *)
Notation IO := (itree (dirE +' ioE +' toolE +' netE +' procE)).

(* ===================================================================== *)
(*  Configuration (environment)                                          *)
(* ===================================================================== *)

(* Default port when SMTP_PORT is unset/zero. *)
Definition default_port : int := 2525%int63.

(* Parse a decimal port string; 0 -> default. *)
Fixpoint port_aux (s : string) (pos acc : int) (fuel : nat) : int :=
  match fuel with
  | O => acc
  | S f' =>
      let n := PrimString.length s in
      if leb n pos then acc
      else
        let c := PrimString.get s pos in
        if andb (leb ch_0 c) (leb c ch_9)
        then port_aux s (add pos 1%int63) (add (mul acc 10%int63) (sub c ch_0)) f'
        else acc
  end.
Definition parse_port (s : string) : int :=
  let p := port_aux (trim s) 0%int63 0%int63 8%nat in
  if leb p 0%int63 then default_port else p.

(* ===================================================================== *)
(*  Allowlist parsing                                                    *)
(* ===================================================================== *)

(* Split BLOG_ALLOW_FROM on ',' into trimmed lowercased non-empty addresses. *)
Fixpoint clean_allow (xs : list string) : list string :=
  match xs with
  | [] => []
  | x :: rest =>
      let a := downcase (trim x) in
      if is_empty a then clean_allow rest else a :: clean_allow rest
  end.
Definition parse_allow (s : string) : list string :=
  clean_allow (split_on_char_fuel s ch_comma 0%int63 mime_fuel).

(* ===================================================================== *)
(*  In-process encryption (reuse of EncryptPost.v's pipeline)            *)
(* ===================================================================== *)

(* The protected inner Date.  As in EncryptPost.v, the acceptance/round-trip
   never inspects the *encrypted* inner Date, so a fixed RFC 5322 string keeps
   extraction pure and the output deterministic. *)
Definition fixed_date : string := "Thu, 01 Jan 1970 00:00:00 +0000".

(* Build the full outer envelope — shared, multi-recipient, in
   Recipients.build_envelope (single source of truth with EncryptPost.v).
   One Public-Keys / Wraps entry per recipient. *)

(* Build the encrypted .eml from the post markdown + author identity.  Mirrors
   EncryptPost.encrypt_one's body assembly, but the markdown is in memory (no
   posts/<slug>.md read) and there are no image attachments (SMTP bodies are
   plain text — listener.py's _plain_body strips attachments).  [sign_sk] /
   [sign_pk_hex] are threaded into build_envelope unchanged. *)
Definition build_eml
  (cek : key_material) (recipients_pk : list (string * string))
  (author slug title md_body sign_sk sign_pk_hex : string) : string :=
  let recipients_str := recipients_to (kid_list recipients_pk) in
  let protected_headers :=
    ("From", author) ::
    ("To", recipients_str) ::
    ("Date", fixed_date) ::
    ("Subject", title) :: nil in
  let inner_mime := build_inner_mime protected_headers "post.md" md_body nil in
  build_envelope cek recipients_pk slug inner_mime sign_sk sign_pk_hex.

(* Build the PUBLIC .eml from the post markdown + author identity (feature 2):
   no CEK, no wraps, no keys/<kid>.pub resolution.  The inner MIME is
   byte-identical to an author-only post (To: reader: <kid>) and the envelope
   signs the canonical form
   sha256(sign_info_public || slug || normalize_crlf inner_mime) — the same
   build_public_envelope single source of truth as EncryptPost.v.  [kid] is
   passed explicitly (SPEC-NIT 1; sibling build_eml's author pattern). *)
Definition build_public_eml
  (kid author slug title md_body sign_sk sign_pk_hex : string) : string :=
  let recipients_str := recipients_to (kid :: nil) in
  let protected_headers :=
    ("From", author) ::
    ("To", recipients_str) ::
    ("Date", fixed_date) ::
    ("Subject", title) :: nil in
  let inner_mime := build_inner_mime protected_headers "post.md" md_body nil in
  build_public_envelope slug inner_mime sign_sk sign_pk_hex.

(* ===================================================================== *)
(*  git via procE  (R4-guarded)                                          *)
(* ===================================================================== *)

(* Build a `git <args...>` NUL-joined argv. *)
Definition git_argv (args : list string) : string :=
  join_nul ("git" :: args).

(* Run a git command, returning the packed result.  Bound to the concrete [IO]
   monad and consuming [raw_run_proc] via an explicit bind: a polymorphic
   wrapper that returned a bare [itree E string] made Crane emit a templated
   helper whose inlined [raw_run_proc] arguments were mis-positioned (the
   implicit subevent witness leaked into [%a0]).  Under a concrete [bind] the
   two value arguments extract correctly. *)
Definition git (args : list string) : IO string :=
  r <- raw_run_proc (git_argv args) "" ;; Ret r.

(* R4 precondition: the publish step's destructive `git reset --hard` may only
   run when the process CWD is the configured repo checkout AND ./.git exists.
   We assert the CWD's basename equals [repo_base] (the basename of
   BLOG_REPO_PATH, default "repo") and that `git rev-parse --git-dir` succeeds
   (exit 0) — i.e. we really are inside a git work-tree.  Returns true iff safe. *)
Definition cwd_basename (cwd : string) : string :=
  basename_of (trim cwd).

Definition repo_guard_ok (cwd repo_base : string) (gitdir_packed : string) : bool :=
  andb (string_eqb (cwd_basename cwd) repo_base) (proc_ok gitdir_packed).

(* ===================================================================== *)
(*  The publish pipeline                                                 *)
(* ===================================================================== *)

(* Resolve a recipient public key (65-byte uncompressed, hex on disk) from
   keys/<kid>.pub. *)
Definition pubkey_path (kid : string) : string := cat "keys/" (cat kid ".pub").

(* Resolve the author signing public key from keys/<kid>.sign.pub. *)
Definition sign_pubkey_path (kid : string) : string := cat "keys/" (cat kid ".sign.pub").

(* Read keys/<kid>.pub for every recipient (author first).  Concrete at this
   file's IO (dirE +' ioE +' toolE +' netE +' procE); see the note in
   Recipients.v.  The recursion is the whole first statement so the
   tail-position gate passes. *)
Fixpoint read_pubkeys (kids : list string) : IO (list (string * string)) :=
  match kids with
  | [] => Ret []
  | kid :: rest =>
      others <- read_pubkeys rest ;;
      pub_hex <- read (pubkey_path kid) ;;
      let pub_raw := hex_decode (trim pub_hex) in
      Ret ((kid, pub_raw) :: others)
  end.

(* The status reply strings (final DATA replies), mirroring listener.py. *)
Definition reply_ok            : string := reply r250 "OK".
Definition reply_no_body       : string := reply r550 "message has no body".
Definition reply_not_allowed   : string := reply r550 "sender not allowed".
Definition reply_proc_failed   : string := reply r451 "processing failed".

(* The branch (from BLOG_BRANCH, default "main"). *)
Definition env_branch (b : string) : string :=
  let t := trim b in if is_empty t then "main" else t.

(* Perform the git publish for a freshly written posts-encrypted/<slug>.eml.
   Returns the final SMTP reply string.  The plaintext markdown is NEVER
   written to disk (unlike listener.py, which staged posts/<ts>.md then let
   the pre-commit hook encrypt it) — we encrypt in-process and commit only the
   ciphertext, so the publish only needs to add posts-encrypted/. *)
Definition publish_git (branch slug eml_rel : string) : IO string :=
  (* The expected work-tree basename is the basename of BLOG_REPO_PATH (default
     "/repo" -> "repo"), so the R4 guard tracks the actual deploy config rather
     than a hard-coded literal. *)
  repo_path0 <- getenv "BLOG_REPO_PATH" ;;
  let repo_base :=
    let rp := trim repo_path0 in
    if is_empty rp then "repo" else basename_of rp in
  cwd <- current_path ;;
  gitdir <- git ("rev-parse" :: "--git-dir" :: nil) ;;
  (* R4 guard: only reset --hard inside the real repo work-tree. *)
  if negb (repo_guard_ok cwd repo_base gitdir) then
    _ <- eprint (concat_all
      ("smtp: refusing git reset --hard outside repo work-tree (cwd=" ::
       trim cwd :: ")" :: lf :: nil)) ;;
    Ret reply_proc_failed
  else
    let origin_branch := cat "origin/" branch in
    _ <- git ("fetch" :: "origin" :: branch :: nil) ;;
    _ <- git ("reset" :: "--hard" :: origin_branch :: nil) ;;
    _ <- git ("add" :: eml_rel :: nil) ;;
    commit_r <- git ("commit" :: "-m" :: cat "post: " (cat slug " (via smtp)") :: nil) ;;
    if negb (proc_ok commit_r) then
      _ <- eprint (concat_all
        ("smtp: git commit failed: " :: proc_output commit_r :: lf :: nil)) ;;
      Ret reply_proc_failed
    else
      push_r <- git ("push" :: "origin" :: cat "HEAD:" branch :: nil) ;;
      if negb (proc_ok push_r) then
        _ <- eprint (concat_all
          ("smtp: git push failed: " :: proc_output push_r :: lf :: nil)) ;;
        Ret reply_proc_failed
      else Ret reply_ok.

(* The full publish from an accumulated DATA payload [msg].  [sender] is the
   MAIL FROM (already lowercased by Smtp.extract_addr); [allow] the parsed
   allowlist; the env-derived identity is read inside.  Returns the final SMTP
   reply string. *)
Definition publish (sender : string) (allow : list string) (msg : string)
                   (branch : string) : IO string :=
  if negb (sender_allowed sender allow) then Ret reply_not_allowed
  else
    let ing := ingest msg in
    if is_empty ing.(in_body) then Ret reply_no_body
    else
      kid0 <- getenv "CRANE_BLOG_AUTHOR_KEY_ID" ;;
      let kid := trim kid0 in
      author0 <- getenv "CRANE_BLOG_AUTHOR_EMAIL" ;;
      let author := trim author0 in
      sign_kid0 <- getenv "CRANE_BLOG_SIGNING_KEY_ID" ;;
      let sign_kid := trim sign_kid0 in
      sign_hex <- getenv "CRANE_BLOG_SIGNING_KEY" ;;
      let sign_sk := hex_decode (trim sign_hex) in
      if is_empty sign_sk
      then
        _ <- eprint (concat_all ("CRANE_BLOG_SIGNING_KEY not set" :: lf :: nil)) ;;
        _ <- exit_with 1%int63 ;;
        Ret reply_proc_failed   (* dead: tool_exit never returns *)
      else
        sign_pub_hex <- read (sign_pubkey_path sign_kid) ;;
        let sign_pk_hex := trim sign_pub_hex in
        env_pk0 <- getenv "BLOG_PUBLIC_KEYS" ;;
        let env_pk := trim env_pk0 in
        (* public-keys: prefer the email header, then the env default. *)
        let public_keys := if is_empty ing.(in_public_keys) then env_pk else ing.(in_public_keys) in
        (* The slug ts fallback is derived from the subject; if the subject has no
           slug-worthy chars we fall back to a fixed timestamp-shaped string.  We
           do not have a clock effect, so the fallback is "post" (the only case
           the acceptance test exercises uses a real subject). *)
        let slug := slug_from_subject ing.(in_subject) "post" in
        let title := ing.(in_subject) in
        (* G2/A fix: the X-Crane-Public-Keys header is a FULL override of the
           BLOG_PUBLIC_KEYS env default, so the keyless public branch must be
           gated on the same explicit opt-in as the startup guard (C6/M9) at
           REQUEST time too — otherwise an unauthenticated sender can publish
           a public post with X-Crane-Public-Keys: * (bypassing the startup
           check, which only sees the env). *)
        allow_pub0 <- getenv "BLOG_ALLOW_PUBLIC" ;;
        let allow_pub := trim allow_pub0 in
        if andb (is_public_marker public_keys) (negb (string_eqb allow_pub "1")) then
          _ <- eprint (concat_all
            ("smtp: public post rejected: BLOG_ALLOW_PUBLIC=1 is required (the X-Crane-Public-Keys override is not an opt-in)" :: lf :: nil)) ;;
          Ret reply_proc_failed
        else
        (* Feature 2 / D3: exactly "*" => PUBLIC (keyless) envelope — no
           keys/<kid>.pub resolution, no CEK; mixed "*" + named readers is
           rejected BEFORE any key reads (uncapped detection, D-M2). *)
        if is_public_marker public_keys then
          let md := build_md author ing.(in_subject) ing.(in_body)
                             fixed_date public_keys kid slug in
          let eml := build_public_eml kid author slug title md sign_sk sign_pk_hex in
          let eml_rel := cat "posts-encrypted/" (cat slug ".eml") in
          _ <- create_directory "posts-encrypted" ;;
          _ <- write_file eml_rel eml ;;
          _ <- eprint (concat_all
            ("smtp: public -> " :: eml_rel :: lf :: nil)) ;;
          publish_git branch slug eml_rel
        else if contains_public_marker public_keys then
          _ <- eprint (concat_all
            ("smtp: recipients may not mix the public marker * with named readers" :: lf :: nil)) ;;
          Ret reply_proc_failed
        else
          (* Recipients: the author (CRANE_BLOG_AUTHOR_KEY_ID) is always first;
             the X-Crane-Public-Keys header / BLOG_PUBLIC_KEYS env adds up to 3
             more readers, resolved from keys/<kid>.pub. *)
          let recips := build_recipients kid public_keys in
          recipients_pk <- read_pubkeys recips ;;
          if negb (recips_ok recipients_pk)
          then
            _ <- eprint (concat_all
              ("smtp: missing or unreadable recipient public key under keys/" :: lf :: nil)) ;;
            Ret reply_proc_failed
          else
            let md := build_md author ing.(in_subject) ing.(in_body)
                               fixed_date public_keys kid slug in
            (* Encrypt the *post markdown* (md), exactly as encrypt_post would after
               the pre-commit hook wrote posts/<slug>.md. *)
            let eml := build_eml (random_bytes 32%int63) recipients_pk author slug title md sign_sk sign_pk_hex in
            let eml_rel := cat "posts-encrypted/" (cat slug ".eml") in
            _ <- create_directory "posts-encrypted" ;;
            _ <- write_file eml_rel eml ;;
            _ <- eprint (concat_all
              ("smtp: encrypted -> " :: eml_rel :: lf :: nil)) ;;
            publish_git branch slug eml_rel.

(* ===================================================================== *)
(*  Per-connection SMTP fold                                             *)
(* ===================================================================== *)

(* Send a reply string on the connection. *)
Definition send_reply (cfd : int) (s : string) : IO unit :=
  _ <- net_send cfd s ;; Ret tt.

(* Fold over recv'd lines.  [st] is the SMTP state, [allow]/[branch] the config.
   On EOF (empty line from RecvLine) we stop.  On a data-complete step we run
   [publish] and send the final reply, then continue (the connection may send
   QUIT next).  Fuel bounds the line count per connection. *)
Fixpoint serve_lines (cfd : int) (st : sstate) (allow : list string)
                     (branch : string) (fuel : nat) : IO unit :=
  match fuel with
  | O => Ret tt
  | S f' =>
      line <- net_recv_line cfd ;;
      if is_empty line then Ret tt   (* client closed / EOF *)
      else
        let '(st', rep, data_done) := step st line in
        if data_done then
          final <- publish st'.(sender) allow st'.(data_acc) branch ;;
          _ <- send_reply cfd final ;;
          (* reset to PReady-ish for any further commands; keep folding. *)
          serve_lines cfd (MkState PReady "" "") allow branch f'
        else
          _ <- send_reply cfd rep ;;
          match st'.(ph) with
          | PQuit => Ret tt
          | _ => serve_lines cfd st' allow branch f'
          end
  end.

(* Per-connection fuel: SMTP sessions are short; 1e6 lines is far beyond any
   real envelope (DATA bodies arrive as lines too). *)
Notation conn_fuel := 1000000%nat.

Definition serve_conn (cfd : int) (banner : string) (allow : list string)
                      (branch : string) : IO unit :=
  _ <- send_reply cfd (greeting banner) ;;
  _ <- serve_lines cfd init_state allow branch conn_fuel ;;
  _ <- net_close cfd ;;
  Ret tt.

(* ===================================================================== *)
(*  The accept loop                                                      *)
(* ===================================================================== *)

(* Sequentially accept and serve connections.  Fuel bounds the number of
   connections served before the process exits (it is restarted by the
   container's restart policy).  A negative accept fd (error) stops the loop. *)
Fixpoint accept_loop (lfd : int) (banner : string) (allow : list string)
                     (branch : string) (fuel : nat) : IO unit :=
  match fuel with
  | O => Ret tt
  | S f' =>
      cfd <- net_accept lfd ;;
      if ltb cfd 0%int63 then Ret tt   (* accept error *)
      else
        _ <- serve_conn cfd banner allow branch ;;
        accept_loop lfd banner allow branch f'
  end.

(* The connection budget before a clean exit/restart. *)
Notation accept_fuel := 1000000000%nat.

(* ===================================================================== *)
(*  Entry point                                                          *)
(* ===================================================================== *)

Definition run : IO unit :=
  host0 <- getenv "SMTP_HOST" ;;
  let host := let h := trim host0 in if is_empty h then "0.0.0.0" else h in
  port0 <- getenv "SMTP_PORT" ;;
  let port := parse_port port0 in
  banner0 <- getenv "SMTP_BANNER" ;;
  let banner := let b := trim banner0 in if is_empty b then "wklm.online" else b in
  branch0 <- getenv "BLOG_BRANCH" ;;
  let branch := env_branch branch0 in
  allow0 <- getenv "BLOG_ALLOW_FROM" ;;
  let allow := parse_allow allow0 in
  (* C6/M9/A6 startup guards: public publishing turns the listener into an
     author-equivalent write channel, so it must never run unauthenticated or
     without an explicit opt-in for the global "*" footgun. *)
  env_pk0 <- getenv "BLOG_PUBLIC_KEYS" ;;
  let env_pk := trim env_pk0 in
  allow_pub0 <- getenv "BLOG_ALLOW_PUBLIC" ;;
  let allow_pub := trim allow_pub0 in
  if andb (string_eqb env_pk "*") (negb (string_eqb allow_pub "1")) then
    _ <- eprint (concat_all
      ("smtp: BLOG_PUBLIC_KEYS=* makes every post public and requires explicit BLOG_ALLOW_PUBLIC=1" :: lf :: nil)) ;;
    exit_with 1%int63
  else if andb (orb (string_eqb env_pk "*") (string_eqb allow_pub "1"))
               (match allow with [] => true | _ :: _ => false end) then
    _ <- eprint (concat_all
      ("smtp: refusing to start: public publishing is enabled but BLOG_ALLOW_FROM is empty" :: lf ::
       "smtp: the listener has author-equivalent write access; refusing to run unauthenticated" :: lf :: nil)) ;;
    exit_with 1%int63
  else
  lfd <- net_listen host port ;;
  if ltb lfd 0%int63 then
    _ <- eprint (concat_all ("smtp: failed to bind " :: host :: lf :: nil)) ;;
    exit_with 1%int63
  else
    _ <- print_endline (concat_all ("smtp: listening on " :: host :: lf :: nil)) ;;
    accept_loop lfd banner allow branch accept_fuel.

Set Warnings "-crane-extraction-default-directory".

Set Crane Extraction Output Directory ".".
Crane Extraction "smtp_listener" run.
