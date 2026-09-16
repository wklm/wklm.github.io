From Corelib Require Import PrimString PrimInt63.
Require Crane.Extraction.
From Crane Require Import Mapping.Std Mapping.NatIntStd Monads.ITree Monads.IO Monads.Dir.
From ExtLib Require Import Structures.Monad.
Import MonadNotation.
From Stdlib Require Import Lists.List.
Import ListNotations.

Require Import PageModel.

Open Scope pstring_scope.

(* [IO] is a [Notation], not a [Definition], so it unfolds at extraction
   time to [itree (dirE +' ioE)].  See the pre-encryption revision for the
   full rationale; keeping it a [Notation] preserves Crane's monad-table
   dispatch. *)
Notation IO := (itree (dirE +' ioE)).

Notation ch_tab := 9%int63.
Notation ch_newline := 10%int63.
Notation ch_cr := 13%int63.
Notation ch_space := 32%int63.
Notation ch_quote := 34%int63.
Notation ch_amp := 38%int63.
Notation ch_apos := 39%int63.
Notation ch_dot := 46%int63.
Notation ch_slash := 47%int63.
Notation ch_colon := 58%int63.
Notation ch_lt := 60%int63.
Notation ch_gt := 62%int63.
Notation ch_0 := 48%int63.
Notation ch_9 := 57%int63.

(* Upper bound on recursion depth for string scanners.  An encrypted post
   is an OpenPGP ASCII-armored MIME message; the body is largely base64
   and is typically a few kilobytes per image.  [fuel] is a scanner
   step count, one char per step. *)
Notation fuel := 2000000.

(* A 1-character primitive string containing LF.  Kept because the page
   shell composes newline-separated header rows. *)
Definition newline_str : string := "
".
Crane Extract Inlined Constant newline_str => "std::string(""\n"")".

(* ---- Low-level string primitives ---------------------------------- *)

Definition int_eqb (a b : int) : bool := eqb a b.

Definition is_empty (s : string) : bool :=
  leb (PrimString.length s) 0%int63.

Definition html_escape_char (s : string) (pos : int) : string :=
  let ch := PrimString.get s pos in
  if int_eqb ch ch_amp then "&amp;"
  else if int_eqb ch ch_lt then "&lt;"
  else if int_eqb ch ch_gt then "&gt;"
  else if int_eqb ch ch_quote then "&quot;"
  else if int_eqb ch ch_apos then "&#39;"
  else PrimString.sub s pos 1%int63.

(* Accumulator-passing so the self-call is in TAIL position: the naive
   [cat (escape_char) (html_escape_aux ...)] form nests the recursive call
   inside [cat], which under em++ -O2 + Asyncify grows one native WASM frame
   per input byte and overflows the stack on a large body.  check-tail-position.sh
   enforces this.  [acc] is built left-to-right (append), so the result is
   byte-identical to the naive form. *)
Fixpoint html_escape_aux (s : string) (pos : int) (remaining : nat) (acc : string) : string :=
  match remaining with
  | O => acc
  | S remaining' =>
      if leb (PrimString.length s) pos then acc
      else html_escape_aux s (add pos 1%int63) remaining' (cat acc (html_escape_char s pos))
  end.

Definition html_escape (s : string) : string :=
  html_escape_aux s 0%int63 fuel "".

Fixpoint concat_all (parts : list string) : string :=
  match parts with
  | nil => ""
  | x :: rest => cat x (concat_all rest)
  end.

Fixpoint nat_of_int_fuel (i : int) (remaining : nat) : nat :=
  match remaining with
  | O => O
  | S remaining' =>
      if leb i 0%int63 then O
      else S (nat_of_int_fuel (sub i 1%int63) remaining')
  end.

Definition nat_of_len (s : string) : nat :=
  nat_of_int_fuel (PrimString.length s) fuel.

Fixpoint starts_with_aux (s pref : string) (pos : int) (remaining : nat) : bool :=
  match remaining with
  | O => true
  | S remaining' =>
      if leb (PrimString.length pref) pos then true
      else if leb (PrimString.length s) pos then false
      else if int_eqb (PrimString.get s pos) (PrimString.get pref pos)
           then starts_with_aux s pref (add pos 1%int63) remaining'
           else false
  end.

Definition starts_with (s pref : string) : bool :=
  starts_with_aux s pref 0%int63 (nat_of_len pref).

Fixpoint find_char (s : string) (ch : int) (pos : int) (remaining : nat) : int :=
  match remaining with
  | O => PrimString.length s
  | S remaining' =>
      if leb (PrimString.length s) pos then PrimString.length s
      else if int_eqb (PrimString.get s pos) ch then pos
      else find_char s ch (add pos 1%int63) remaining'
  end.

Fixpoint string_eqb_aux (a b : string) (pos : int) (remaining : nat) : bool :=
  match remaining with
  | O => true
  | S remaining' =>
      if leb (PrimString.length a) pos then true
      else if int_eqb (PrimString.get a pos) (PrimString.get b pos)
           then string_eqb_aux a b (add pos 1%int63) remaining'
           else false
  end.

Definition string_eqb (a b : string) : bool :=
  if int_eqb (PrimString.length a) (PrimString.length b)
  then string_eqb_aux a b 0%int63 (nat_of_len a)
  else false.

Fixpoint string_ge_aux (a b : string) (pos : int) (remaining : nat) : bool :=
  match remaining with
  | O => true
  | S remaining' =>
      let la := PrimString.length a in
      let lb := PrimString.length b in
      if andb (leb la pos) (leb lb pos) then true
      else if leb la pos then false
      else if leb lb pos then true
      else
        let ca := PrimString.get a pos in
        let cb := PrimString.get b pos in
        if int_eqb ca cb then string_ge_aux a b (add pos 1%int63) remaining'
        else leb cb ca
  end.

Definition string_ge (a b : string) : bool :=
  string_ge_aux a b 0%int63 fuel.

Definition substring_from (s : string) (start : int) : string :=
  PrimString.sub s start (sub (PrimString.length s) start).

Fixpoint reverse_string_acc (s acc : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => acc
  | S remaining' =>
      if leb (PrimString.length s) pos then acc
      else
        let ch := PrimString.sub s pos 1%int63 in
        reverse_string_acc s (cat ch acc) (add pos 1%int63) remaining'
  end.

Definition reverse_string (s : string) : string :=
  reverse_string_acc s "" 0%int63 fuel.

Fixpoint trim_left_from (s : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => substring_from s pos
  | S remaining' =>
      if leb (PrimString.length s) pos then ""
      else
        let ch := PrimString.get s pos in
        if orb (int_eqb ch ch_space)
           (orb (int_eqb ch ch_tab)
           (orb (int_eqb ch ch_newline)
                (int_eqb ch ch_cr)))
        then trim_left_from s (add pos 1%int63) remaining'
        else substring_from s pos
  end.

Definition trim_left (s : string) : string :=
  trim_left_from s 0%int63 fuel.

Definition trim_right (s : string) : string :=
  reverse_string (trim_left (reverse_string s)).

Definition trim (s : string) : string :=
  trim_right (trim_left s).

Definition has_suffix (s suffix : string) : bool :=
  let len_s := PrimString.length s in
  let len_suffix := PrimString.length suffix in
  if ltb len_s len_suffix then false
  else string_eqb (PrimString.sub s (sub len_s len_suffix) len_suffix) suffix.

Fixpoint last_segment_aux (s : string) (pos last : int) (remaining : nat) : string :=
  match remaining with
  | O => substring_from s last
  | S remaining' =>
      if leb (PrimString.length s) pos then substring_from s last
      else if int_eqb (PrimString.get s pos) ch_slash
           then last_segment_aux s (add pos 1%int63) (add pos 1%int63) remaining'
           else last_segment_aux s (add pos 1%int63) last remaining'
  end.

Definition last_segment (s : string) : string :=
  last_segment_aux s 0%int63 0%int63 fuel.

(* Strip a trailing [".eml"] from the last path segment; whatever remains is
   used verbatim as the URL slug. *)
Definition file_stem_eml (path : string) : string :=
  let name := last_segment path in
  let len_name := PrimString.length name in
  if has_suffix name ".eml"
  then PrimString.sub name 0%int63 (sub len_name 4%int63)
  else name.

(* ---- Output-path helpers ----------------------------------------- *)

Definition file_output_path (output_dir slug : string) : string :=
  cat output_dir (cat "/" (cat slug "/index.html")).

Definition styles_output_path (output_dir : string) : string :=
  cat output_dir "/styles/site.css".

Definition index_output_path (output_dir : string) : string :=
  cat output_dir "/index.html".

Definition dirname_output_path (output_dir slug : string) : string :=
  cat output_dir (cat "/" slug).

(* ---- Encrypted post model ---------------------------------------- *)

(* An [EncryptedPost] is the opaque view the generator has of a
   [posts-encrypted/<slug>.eml] file.  The public renderer uses the
   slug, a non-rendered sort key, and the raw envelope.

   [ep_body] is the FULL outer envelope byte-for-byte: the public
   header block (Subject: ..., MIME-Version, Public-Keys, Signature,
   Signing-Key, Content-Type) followed by the multipart/hpke+wrapped
   body ([application/wrapped-keys] part with per-reader CEK wraps +
   [application/aes-gcm] ciphertext).  The generator never parses MIME
   semantics and never touches cryptographic bytes.

   The envelope is rendered into the page's [<pre id='ciphertext'>]
   (HTML-escaped by [serialize_post_page]; the browser's textContent
   read-back entity-decodes it, so the bytes the decrypt app parses are
   byte-identical to what native [decrypt_post] parses).  Its
   [parse_envelope] reads the Signature / Signing-Key headers and the
   Content-Type boundary from this same header block.  The envelope
   charset is hex/base64/ASCII literals by construction (escaped for
   XSS safety, not for correctness).  Sender/recipient/date and the real
   subject live only in the *inner* protected MIME headers, which are
   encrypted. *)
Record EncryptedPost : Type := mkEncryptedPost {
  ep_slug : string;
  ep_sort_key : string;
  ep_body : string
}.

Definition public_subject : string := "Subject: ...".

(* Truncated SHA-256 fingerprint of the full envelope ([ep_body] — public
   headers + multipart body), used as the inbox link label.  The Rocq
   definition is identity; the C++ helper [sha256_trunc_std] in
   [blog_helpers.h] provides the real hash. *)
Definition sha256_trunc (s : string) : string := s.

Definition month_key (m : string) : string :=
  if string_eqb m "Jan" then "01"
  else if string_eqb m "Feb" then "02"
  else if string_eqb m "Mar" then "03"
  else if string_eqb m "Apr" then "04"
  else if string_eqb m "May" then "05"
  else if string_eqb m "Jun" then "06"
  else if string_eqb m "Jul" then "07"
  else if string_eqb m "Aug" then "08"
  else if string_eqb m "Sep" then "09"
  else if string_eqb m "Oct" then "10"
  else if string_eqb m "Nov" then "11"
  else if string_eqb m "Dec" then "12"
  else "00".

(* Normalize the RFC 5322 date shape emitted by the tools,
   e.g. [Fri, 01 May 2026 13:24:03 +0000], into a lexicographic UTC-ish
   key.  If a hand-written message uses another shape, sorting falls
   back to the original date string. *)
Definition date_sort_key (date : string) : string :=
  let len := PrimString.length date in
  if leb 25%int63 len then
    let day := PrimString.sub date 5%int63 2%int63 in
    let mon := PrimString.sub date 8%int63 3%int63 in
    let year := PrimString.sub date 12%int63 4%int63 in
    let time := PrimString.sub date 17%int63 8%int63 in
    concat_all (year :: month_key mon :: day :: "T" :: time :: nil)
  else date.

Definition sort_key (slug date : string) : string :=
  if int_eqb (PrimString.length slug) 16%int63
  then slug
  else if is_empty date then slug
  else date_sort_key date.

(* ---- .eml header parsing ----------------------------------------- *)

(* Split a raw [.eml] byte string at the first blank line.  Returns the
   header block (without the blank line) and the body (everything after
   the blank line).  [\r] is tolerated: a line consisting solely of
   [\r] counts as blank.  The hook emits LF-only output, so this is
   defensive. *)
Definition is_blank_line (line : string) : bool :=
  let t := trim line in
  is_empty t.

Fixpoint split_headers_body (s : string) (pos : int) (remaining : nat) : string * string :=
  match remaining with
  | O => (s, "")
  | S remaining' =>
      let len := PrimString.length s in
      if leb len pos then (s, "")
      else
        let eol := find_char s ch_newline pos fuel in
        let line := PrimString.sub s pos (sub eol pos) in
        if is_blank_line line
        then
          let header := PrimString.sub s 0%int63 pos in
          let body_start := if ltb eol len then add eol 1%int63 else len in
          let body := PrimString.sub s body_start (sub (PrimString.length s) body_start) in
          (header, body)
        else
          let next := if ltb eol len then add eol 1%int63 else len in
          split_headers_body s next remaining'
  end.

(* [Header] lines are [Key: Value]; the header block is already free of
   RFC 5322 line folding because the hook emits each header on a single
   line.  A line that does not contain [':'] is ignored. *)
Definition parse_header_line (line : string) : string * string :=
  let len := PrimString.length line in
  let colon := find_char line ch_colon 0%int63 fuel in
  if leb len colon then ("", "")
  else
    let key := PrimString.sub line 0%int63 colon in
    let value_start := add colon 1%int63 in
    let value :=
      if leb len value_start then ""
      else PrimString.sub line value_start (sub len value_start) in
    (trim key, trim value).

Fixpoint lookup_header_aux (s : string) (needle : string) (pos : int) (remaining : nat) : string :=
  match remaining with
  | O => ""
  | S remaining' =>
      let len := PrimString.length s in
      if leb len pos then ""
      else
        let eol := find_char s ch_newline pos fuel in
        let line := PrimString.sub s pos (sub eol pos) in
        let '(key, value) := parse_header_line line in
        if string_eqb key needle
        then value
        else
          let next := if ltb eol len then add eol 1%int63 else len in
          lookup_header_aux s needle next remaining'
  end.

Definition lookup_header (headers needle : string) : string :=
  lookup_header_aux headers needle 0%int63 fuel.

Definition parse_eml (slug raw : string) : EncryptedPost :=
  let '(headers, _body) := split_headers_body raw 0%int63 fuel in
  let date := lookup_header headers "Date" in
  mkEncryptedPost
    slug
    (sort_key slug date)
    raw.

(* The build-time-pinned author signing key (D-C5/A5), read by [run] from the
   committed keys/author-signing.pub and threaded through [render_eml_page] as
   the <meta name='crane-author-signing-key'> content.  It is NOT derived from
   the envelope's own Signing-Key header (that would be TOFU: an attacker
   minting their own keypair would sign with a key that "matches" itself).
   The browser's [do_public] therefore compares the pinned meta against the
   envelope's Signing-Key and fails closed on mismatch — authenticity rests on
   the committed pin, not on the envelope. *)

(* ---- Rendering --------------------------------------------------- *)

(* Page-shell + render functions are now thin wrappers around PageModel.v
   serializers.  The page shell in PageModel's [serialize_page_shell] uses
   content-hashed asset URLs (site.<sha>.css?v=<hash>) computed at runtime
   by [run] below. *)

(* The outer envelope carries no private metadata: encrypt_post emits
   only the placeholder [Subject: ...], MIME-Version, Public-Keys,
   Signature, Signing-Key and Content-Type — no From/To/Date, no
   plaintext.  The deploy pipeline enforces this on every
   [posts-encrypted/*.eml] (placeholder outer Subject, no
   ^(From|To|Date):).  The full envelope is rendered (HTML-escaped)
   into #ciphertext; the browser's textContent read-back restores the
   exact bytes.

   Browser-side decryption runs in the crane_decrypt WASM module (ROCQ ->
   Crane -> em++, from src/DecryptApp.v): WebAuthn + Web Crypto API authenticate
   the reader, retrieve their ECDH key from IndexedDB, HPKE-unwrap the CEK, and
   AES-GCM decrypt the body. *)
Definition render_eml_page (ep : EncryptedPost) (version : string) (pinned : string) : string :=
  let prefix := "../" in
  serialize_post_page (mk_post_page ep.(ep_body) prefix version pinned).

Definition render_inbox_page (eps : list EncryptedPost) (version : string) : string :=
  let rows := map (fun ep => 
    concat_all (
      "<li>" ::
      "<a class='inbox-subject' href='" :: html_escape (cat ep.(ep_slug) "/") :: "'>" ::
      html_escape (sha256_trunc ep.(ep_body)) ::
      "</a>" ::
      "<span class='inbox-status' data-slug='" :: html_escape ep.(ep_slug) :: "'></span>" ::
      "</li>" :: nil
    )) eps in
  serialize_inbox_page (mk_inbox_page rows version).

(* ---- Enrollment page ----------------------------------------------- *)

Definition render_enroll_page (version : string) : string :=
  let prefix := "../" in
  serialize_enroll_page (mk_enroll_page prefix version).

Definition enroll_output_path (output_dir : string) : string :=
  cat output_dir "/enroll/index.html".

Definition enroll_dir_output_path (output_dir : string) : string :=
  cat output_dir "/enroll".

(* ---- Stylesheet --------------------------------------------------
   Restores the pre-email visual language: a small literary page, Georgia
   body text, neutral paper, and a restrained index.  The encrypted envelope
   remains visible, but as a quiet source artifact inside the old essay shell
   instead of a mail-client imitation. *)
Definition stylesheet_core : string :=
  concat_all (
    "@import url('https://cdn.jsdelivr.net/npm/katex@0.16.8/dist/katex.min.css');" ::
    ":root{--paper:#faf8f5;--paper-card:#ffffff;--paper-subtle:#f5f0e6;--ink:#1b1917;--ink-light:#3f3b36;--muted:#57534b;--rule:#d0c5b5;--rule-subtle:#e0d8ca;--serene-blue:#52a3eb;--serene-lilac:#f2c4e2;--serene-coral:#fa6e43;--serene-peach:#f7c196;--serene-yellow:#fbc52d;--serene-charcoal:#1b1917;--accent:var(--serene-blue);--accent-hover:#3b8cd2;--btn-bg:var(--serene-coral);--btn-hover:#e55a2f;--btn-text:#ffffff;--focus-ring:0 0 0 3px rgba(82,163,235,0.45);color-scheme:light dark}" ::
    "@media (prefers-color-scheme: dark){:root{--paper:#141312;--paper-card:#1e1c1a;--paper-subtle:#201e1c;--ink:#f7f4ef;--ink-light:#ded8cc;--muted:#b5aea3;--rule:#3d3934;--rule-subtle:#2e2b28;--serene-blue:#64b0f3;--serene-lilac:#f5cde6;--serene-coral:#fb7c53;--serene-peach:#f9cca6;--serene-yellow:#fcd048;--serene-charcoal:#141312;--accent:var(--serene-blue);--accent-hover:#82c0f7;--btn-bg:var(--serene-coral);--btn-hover:#fa6e43;--btn-text:#141312;--focus-ring:0 0 0 3px rgba(100,176,243,0.45)}}" ::
    "*,*::before,*::after{box-sizing:border-box}" ::
    "html{-webkit-text-size-adjust:100%;hanging-punctuation:first last}" ::
    "body{margin:0;background:var(--paper);color:var(--ink);font:18px/1.68 Georgia,'Times New Roman',serif;font-feature-settings:'kern' 1,'liga' 1,'onum' 1;font-variant-numeric:oldstyle-nums proportional-nums;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}" ::
    "p{margin:0 0 1.4em;text-wrap:pretty;orphans:2;widows:2}" ::
    "h1,h2,h3{font-weight:normal;line-height:1.24;text-wrap:balance;color:var(--ink)}" ::
    "h1{font-size:2.15rem;margin:0 0 1.2rem;letter-spacing:-.02em}" ::
    "h2{font-size:1.45rem;margin:2.2em 0 .6em;letter-spacing:-.01em}" ::
    "h3{font-size:1.15rem;font-style:italic;color:var(--muted);margin:1.8em 0 .5em}" ::
    "a{color:var(--ink);text-decoration:underline;text-decoration-color:var(--rule);text-decoration-thickness:1px;text-underline-offset:.22em;transition:color .15s ease,text-decoration-color .15s ease}" ::
    "a:hover{color:var(--serene-coral);text-decoration-color:var(--serene-coral)}" ::
    "a:focus-visible{outline:none;box-shadow:var(--focus-ring);border-radius:2px}" ::
    "::selection{background:color-mix(in oklab,var(--serene-peach) 30%,transparent)}" ::
    "time{font-variant-numeric:tabular-nums oldstyle-nums}" ::
    ".skip-link{position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden}" ::
    ".skip-link:focus{position:static;width:auto;height:auto;padding:.35rem .75rem;background:var(--ink);color:var(--paper);border-radius:2px;box-shadow:var(--focus-ring)}" ::
    ".page-shell{max-width:42rem;margin:0 auto;padding:0 1.5rem 6rem;position:relative}" ::
    ".site-header{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;margin-bottom:3.6rem;padding:1.4rem 0 1.1rem;border-top:3px solid var(--ink);border-bottom:1px solid var(--rule);font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif}" ::
    ".site-mark{text-decoration:none;font-weight:600;font-size:.95rem;letter-spacing:.06em;color:var(--ink);transition:color .15s ease}" ::
    ".site-mark:hover{color:var(--serene-coral);text-decoration:none}" ::
    ".site-nav a{color:var(--muted);font-size:.78rem;font-weight:500;letter-spacing:.08em;text-transform:uppercase;text-decoration:none;padding-bottom:2px;border-bottom:1.5px solid transparent;transition:color .15s ease,border-bottom-color .15s ease}" ::
    ".site-nav a:hover{color:var(--serene-blue);border-bottom-color:var(--serene-blue);text-decoration:none}" ::
    ".post-header{margin-bottom:2.4rem}" ::
    ".post-header h1{margin:.2em 0 0;font-size:2rem}" ::
    ".post-meta{margin:0;color:var(--muted);font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:.78rem;font-weight:500;letter-spacing:.06em;text-transform:uppercase}" ::
    ".eml-body{margin:1.6em 0 0;padding:1.25rem 1.5rem;background:var(--paper-subtle);color:var(--ink);border:1px solid var(--rule);border-radius:4px;white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.74rem;line-height:1.58}" ::
    ".index::before{content:'DISPATCHES';display:block;font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:.72rem;font-weight:600;letter-spacing:.12em;color:var(--muted);margin-bottom:1.2rem}" ::
    ".index .posts{list-style:none;padding:0;margin:0;border-top:1px solid var(--rule)}" ::
    ".index .posts li{margin:0;padding:.85rem 0;border-bottom:1px solid var(--rule-subtle);display:flex;align-items:center;justify-content:space-between;gap:1rem}" ::
    ".index .posts a{color:var(--ink);text-decoration:none;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.84rem;letter-spacing:.03em;font-weight:500;transition:color .15s ease}" ::
    ".index .posts a:hover{color:var(--serene-coral);text-decoration:none}" ::
    ".inbox-subject{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.84rem;letter-spacing:.03em}" ::
    "@media (max-width:34rem){.page-shell{padding:0 1rem 3.5rem}.site-header{margin-bottom:2.2rem}.index .posts li{padding:.75rem 0}}" ::
    "body{font-size:clamp(1.0625rem,0.98rem + 0.45vw,1.125rem)}" ::
    "figure{margin:0}" ::
    "hr{border:none;border-top:1px dotted var(--rule);margin:2.5rem 0}" ::
    ".index .posts li{min-height:44px}" ::
    ".index .posts a{display:inline-block;padding:.35rem 0;overflow-wrap:anywhere;word-break:break-word}" ::
    "code,.eml-body,.pubkey-display,.inbox-subject{overflow-wrap:anywhere;word-break:break-word}" ::
    "@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}" ::
    "@media print{.site-nav{display:none}body{background:#fff;color:#000}a{text-decoration:none;color:#000}}" :: nil).

Definition stylesheet_decrypt : string :=
  concat_all (
    ".inbox-status{font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:.72rem;font-weight:500;letter-spacing:.04em;color:var(--muted);white-space:nowrap}" ::
    ".inbox-status::after{content:'encrypted'}" ::
    ".inbox-status.unlocked{color:var(--ink-light)}" ::
    ".inbox-status.unlocked::after{content:'unlocked';font-weight:600}" ::
    ".inbox-status-msg{color:var(--muted);font-size:.82rem;font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif}" ::
    "#decrypt-ui{margin:2.8rem 0;padding:1.4rem 1.6rem;background:var(--paper-subtle);border:1px solid var(--rule);border-radius:4px;font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:.86rem}" ::
    ".decrypt-hint{color:var(--muted);margin:0 0 1rem;line-height:1.55}" ::
    "#decrypt-button{padding:.5rem 1.4rem;font-family:inherit;font-size:.84rem;font-weight:600;letter-spacing:.03em;border:none;border-radius:3px;background:var(--btn-bg);color:var(--btn-text);cursor:pointer;transition:background-color .15s ease,opacity .15s ease}" ::
    "#decrypt-button:hover{background:var(--btn-hover)}" ::
    "#decrypt-button:focus-visible{outline:none;box-shadow:var(--focus-ring)}" ::
    "#decrypt-status{margin-top:.75rem;color:var(--muted);font-size:.82rem;line-height:1.4}" ::
    "#clear-key-button{display:none;margin-top:.6rem;margin-left:.6rem;padding:.45rem .9rem;font-family:inherit;font-size:.82rem;border:1px solid var(--rule);background:var(--paper);color:var(--muted);border-radius:3px;cursor:pointer;transition:color .15s ease,border-color .15s ease}" ::
    "#clear-key-button:hover{color:var(--ink);border-color:var(--muted)}" ::
    (* :empty so the error auto-shows the moment ROCQ sets its textContent and
       stays hidden while empty (the success path leaves it empty). *)
    ".decrypt-error{margin-top:.75rem;color:#c83220;font-size:.84rem;font-weight:500}" ::
    ".decrypt-error:empty{display:none}" ::
    ".decrypt-fallback{color:var(--muted);font-size:.84rem}" ::
    "#decrypted-content{display:none;margin-top:2.8rem;animation:reader-fade .4s ease-out both}" ::
    "#real-body{font-family:Georgia,'Times New Roman',serif;font-size:1.125rem;line-height:1.68;color:var(--ink)}" ::
    "#real-body h1,#real-body h2,#real-body h3{font-family:Georgia,'Times New Roman',serif;font-weight:normal;color:var(--ink)}" ::
    "#real-body blockquote{margin:1.8em 0;padding:.6em 1.2em;border-left:2px solid var(--rule);color:var(--ink-light);font-style:italic;font-size:1.05em;line-height:1.6}" ::
    "#real-body code{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.88em;background:var(--paper-subtle);border:1px solid var(--rule-subtle);padding:.15em .35em;border-radius:3px}" ::
    "#real-body pre code{display:block;padding:1.1rem;overflow-x:auto;border:1px solid var(--rule);border-radius:4px}" ::
    "#real-body ul,#real-body ol{padding-left:1.5rem;margin:1.2em 0}" ::
    "#real-body li{margin:.45em 0}" ::
    "#real-body img{display:block;margin:0 auto;max-width:100%;max-height:min(52vh,460px);width:auto;height:auto;object-fit:contain;border-radius:3px}" ::
    "#real-body p:has(> img){display:flex;justify-content:center;align-items:center;gap:1rem;margin:1.2rem auto;max-width:100%}" ::
    "#real-body p:has(> img) img{max-height:min(52vh,460px);max-width:100%;width:auto;height:auto;object-fit:contain}" ::
    "body:has(#real-body img) .page-shell{padding-bottom:2rem}" ::
    "body:has(#real-body img) .site-header{margin-bottom:2rem;padding:1rem 0 .8rem}" ::
    "#decrypted-content:has(#real-body img){margin-top:1.8rem}" ::
    "#decrypted-content:has(#real-body img) header{margin-bottom:1rem}" ::
    "#decrypted-content:has(#real-body img) #real-title{font-size:1.75rem;margin:0 0 .3rem}" ::
    "#decrypted-content:has(#real-body img) #real-meta{margin:0 0 .8rem}" ::
    "#decrypted-content:has(#real-body img) .post-colophon{margin-top:2rem;padding-top:1rem}" ::
    "#decrypted-content:has(#real-body img) #reader-canvas{display:none}" ::
    "#decrypted-content:has(#real-body img) #real-body{position:static;width:auto;height:auto;margin:0 0 1rem;clip:auto;overflow:visible;white-space:normal}" ::
    "#reader-canvas{display:block;width:100%;max-width:37.5rem;height:auto;margin:0 auto 1.8rem;color:var(--ink);background:var(--paper);border-radius:2px;animation:reader-resolve .4s ease-out both}" ::
    ".sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}" ::
    "@keyframes reader-fade{from{opacity:0}to{opacity:1}}" ::
    "@keyframes reader-resolve{from{opacity:0}to{opacity:1}}" ::
    ".post-colophon{margin-top:4.5rem;padding-top:1.5rem;border-top:1px dotted var(--rule);font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:.74rem;color:var(--muted);white-space:pre-wrap;line-height:1.6;letter-spacing:.02em}" ::
    ".post-colophon::after{content:'❧  serene  ·  sleepless 2018';display:block;font-family:Georgia,serif;font-style:italic;font-size:.82rem;color:var(--serene-peach);margin-top:.75rem;letter-spacing:.08em}" ::
    "#real-body a[href^='http']::after{content:'↗';font-size:.78em;margin-left:.15em;color:var(--muted);text-decoration:none}" ::
    "#real-body a[href^='http']:hover::after{color:var(--serene-coral)}" ::
    "#decrypt-button,#clear-key-button{min-height:44px}" :: nil).

Definition stylesheet_enroll : string :=
  concat_all (
    ".enroll-cta{margin:3.5rem 0 1rem;font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:.84rem;color:var(--muted)}" ::
    ".enroll-link{color:var(--serene-blue);text-decoration:underline;text-decoration-color:rgba(82,163,235,0.4);text-underline-offset:.22em;transition:color .15s ease,text-decoration-color .15s ease}" ::
    ".enroll-link:hover{color:var(--serene-coral);text-decoration-color:var(--serene-coral)}" ::
    ".enroll-link::after{content:' →'}" ::
    "#enroll-ui{margin:2.2rem 0;padding:1.5rem 1.8rem;background:var(--paper-subtle);border:1px solid var(--rule);border-radius:4px}" ::
    "#enroll-button{padding:.55rem 1.5rem;font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:.86rem;font-weight:600;letter-spacing:.03em;border:none;background:var(--btn-bg);color:var(--btn-text);cursor:pointer;border-radius:3px;transition:background-color .15s ease,opacity .15s ease}" ::
    "#enroll-button:hover{background:var(--btn-hover)}" ::
    "#enroll-button:focus-visible{outline:none;box-shadow:var(--focus-ring)}" ::
    "#enroll-status{margin-top:.75rem;font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:.84rem;color:var(--muted)}" ::
    "#enroll-result{margin:2.2rem 0;padding:1.5rem 1.8rem;background:var(--paper-subtle);border:1px solid var(--rule);border-radius:4px}" ::
    "#enroll-result code{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.88rem;background:var(--paper);border:1px solid var(--rule);padding:.2rem .45rem;border-radius:3px;color:var(--serene-coral);font-weight:500}" ::
    ".pubkey-display{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.74rem;line-height:1.55;background:var(--paper);padding:1.1rem 1.25rem;overflow-x:auto;word-break:break-all;border:1px solid var(--rule);border-radius:3px;color:var(--ink)}" ::
    ".enroll-note{color:var(--muted);font-size:.82rem;font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;margin-top:1.5rem;line-height:1.55}" ::
    "#enroll-existing{margin:2.2rem 0;padding:1.5rem 1.8rem;background:var(--paper-subtle);border:1px solid var(--rule);border-radius:4px;font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:.84rem}" ::
    "#enroll-existing-info{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.74rem;background:var(--paper);padding:.95rem;overflow-x:auto;overflow-wrap:anywhere;word-break:break-all;border:1px solid var(--rule);border-radius:3px;color:var(--ink)}" ::
    "#enroll-button{min-height:44px}" ::
    "#enroll-result code{overflow-wrap:anywhere}" :: nil).

Definition stylesheet : string :=
  cat stylesheet_core (cat stylesheet_decrypt stylesheet_enroll).

(* ---- IO pipeline ------------------------------------------------- *)

Fixpoint read_eml_list (paths : list string) : IO (list EncryptedPost) :=
  match paths with
  | nil => Ret nil
  | path :: rest =>
      raw <- read path ;;
      parsed_rest <- read_eml_list rest ;;
      Ret (parse_eml (file_stem_eml path) raw :: parsed_rest)
  end.

(* Descending sort by a hidden key. Timestamp slugs sort directly; otherwise
   the key falls back to the Date header when present. *)
Fixpoint insert_ep (ep : EncryptedPost) (eps : list EncryptedPost) : list EncryptedPost :=
  match eps with
  | nil => ep :: nil
  | q :: rest =>
      if string_ge ep.(ep_sort_key) q.(ep_sort_key)
      then ep :: q :: rest
      else q :: insert_ep ep rest
  end.

Fixpoint sort_eps (eps : list EncryptedPost) : list EncryptedPost :=
  match eps with
  | nil => nil
  | ep :: rest => insert_ep ep (sort_eps rest)
  end.

Fixpoint write_eml_pages (output_dir : string) (eps : list EncryptedPost) (version : string) (pinned : string) : IO unit :=
  match eps with
  | nil => Ret tt
  | ep :: rest =>
      _ <- create_directory (dirname_output_path output_dir ep.(ep_slug)) ;;
      _ <- write_file (file_output_path output_dir ep.(ep_slug)) (render_eml_page ep version pinned) ;;
      write_eml_pages output_dir rest version pinned
  end.

(* [run] is the extracted entry point.  It reads the ciphertext tree
   from [./posts-encrypted/], emits one page per [.eml] under
   [_site/<slug>/], plus the inbox index and stylesheet.  Static
   assets under [./static/] are copied to [_site/static/] verbatim
   so that the browser-side decryption JS is served.

   Phase 0a (robust): content-hash the stylesheet at runtime.  After
   writing [styles/site.css], read it back, compute its truncated
   SHA-256 hash, and rename the file to [styles/site.<sha8>.css].
   The hash becomes the cache-busting version tag on all page asset
   URLs (stylesheet link + WASM module imports), making them
   immutable-cacheable — any CSS change produces a new URL, bypassing
   the 4h max-age completely. *)

Fixpoint copy_static_files (files : list string) : IO unit :=
  match files with
  | nil => Ret tt
  | name :: rest =>
      content <- read (cat "./static/" name) ;;
      _ <- write_file (cat "./_site/static/" name) content ;;
      copy_static_files rest
  end.

Definition run : IO unit :=
  files <- list_directory "./posts-encrypted" ;;
  let eml_paths := map (fun name => cat "./posts-encrypted/" name)
                       (filter (fun name => has_suffix name ".eml") files) in
  parsed <- read_eml_list eml_paths ;;
  let eps := sort_eps parsed in
  (* D-C5/A5 trust anchor: the build-time-pinned author signing key.  Read from
     the committed keys/author-signing.pub (the CI deploy gates assert every
     envelope's Signing-Key equals this pin).  Empty when absent — the browser
     then fails closed on any public post. *)
  pinned0 <- read "./keys/author-signing.pub" ;;
  let pinned := trim pinned0 in
  _ <- create_directory "./_site" ;;
  _ <- create_directory "./_site/styles" ;;
  _ <- write_file (styles_output_path "./_site") stylesheet ;;
  (* Content-hash both CSS and WASM for cache-busting.  If EITHER changes,
     the version tag changes → all asset URLs get a fresh URL → stale
     max-age=14400 caches are bypassed. *)
  css <- read (styles_output_path "./_site") ;;
  wasm <- read "./static/crane_decrypt.mjs" ;;
  let hash := sha256_trunc (cat css wasm) in
  let hashed_css := cat "./_site/styles/site." (cat hash ".css") in
  _ <- write_file hashed_css css ;;
  (* Use the combined hash as the cache-busting version on all pages *)
  _ <- write_file (index_output_path "./_site") (render_inbox_page eps hash) ;;
  _ <- write_eml_pages "./_site" eps hash pinned ;;
  _ <- create_directory (enroll_dir_output_path "./_site") ;;
  _ <- write_file (enroll_output_path "./_site") (render_enroll_page hash) ;;
  _ <- create_directory "./_site/static" ;;
  static_files <- list_directory "./static" ;;
  copy_static_files (filter (fun name => negb (is_empty name)) static_files).

Set Warnings "-crane-extraction-default-directory".
Set Crane Extraction Output Directory ".".

(* Linear-time [concat_all] override — same rationale as the pre-encryption
   revision.  The Coq definition is kept for proof-level reasoning; only
   the C++ call site is redirected to the helper in [blog_helpers.h]. *)
Crane Extract Inlined Constant concat_all => "concat_all_std(%a0)" From "blog_helpers.h".

(* Truncated SHA-256 fingerprint of the full envelope for inbox labels. *)
Crane Extract Inlined Constant sha256_trunc => "sha256_trunc_std(%a0)" From "blog_helpers.h".

Crane Extraction "blog" run.
