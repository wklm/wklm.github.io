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
      "<a class='inbox-subject' href='" :: html_escape (cat ep.(ep_slug) "/index.html") :: "'>" ::
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
    ":root{--paper:#fff;--ink:#111;--muted:#555;--accent:#005cc5}" ::
    "@media (prefers-color-scheme: dark){:root{--paper:#141414;--ink:#e8e8e8;--muted:#9a9a9a;--rule:#2e2e2e;--accent:#e8e8e8}}" ::
    "*,*::before,*::after{box-sizing:border-box}" ::
    "html{-webkit-text-size-adjust:100%;hanging-punctuation:first last}" ::
    "body{margin:0;background:var(--paper);color:var(--ink);font:18px/1.55 Georgia,'Times New Roman',serif;font-variant-numeric:oldstyle-nums proportional-nums;text-rendering:optimizeLegibility;-webkit-font-smoothing:antialiased}" ::
    "p{margin:0 0 1em;text-wrap:pretty;orphans:2;widows:2}" ::
    "h1,h2,h3{font-weight:normal;line-height:1.2;text-wrap:balance;margin:1.6em 0 .4em}" ::
    "h1{font-size:1.75rem;margin-top:0}h2{font-size:1.25rem}h3{font-size:1.05rem;font-style:italic}" ::
    "a{color:inherit;text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:.18em}" ::
    "a:hover{text-decoration-thickness:2px}" ::
    "a:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}" ::
    "time{font-variant-numeric:tabular-nums oldstyle-nums}" ::
    ".skip-link{position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden}" ::
    ".skip-link:focus{position:static;width:auto;height:auto;padding:.25rem .5rem;background:var(--ink);color:var(--paper)}" ::
    ".page-shell{max-width:36rem;margin:0 auto;padding:2rem 1.25rem 4rem}" ::
    ".site-header{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;margin-bottom:3rem;font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:.82rem}" ::
    ".site-mark{text-decoration:none;font-weight:600;letter-spacing:.02em}" ::
    ".site-nav a{color:var(--muted);text-decoration:none}" ::
    ".site-nav a:hover{color:var(--ink);text-decoration:underline}" ::
    ".post-header{margin-bottom:2rem}" ::
    ".post-header h1{margin:.2em 0 0}" ::
    ".post-meta{margin:0;color:var(--muted);font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:.82rem;letter-spacing:.02em}" ::
    ".eml-body{margin:1.2em 0 0;padding:0;background:transparent;color:var(--ink);white-space:pre-wrap;word-break:break-all;overflow-wrap:anywhere;font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.72rem;line-height:1.45}" ::
    ".index .posts{list-style:none;padding:0;margin:0}" ::
    ".index .posts li{margin:.35em 0}" ::
    ".index .posts a{text-decoration:none}" ::
    ".index .posts a:hover{text-decoration:underline}" ::
    ".inbox-subject{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.72rem}" ::
    "@media (max-width:32rem){.page-shell{padding:1.25rem 1rem 3rem}.site-header{margin-bottom:2rem}.index .posts li{margin:.8em 0}}" ::
    "@media print{.site-nav{display:none}body{background:#fff;color:#000}a{text-decoration:none;color:#000}}" :: nil).

Definition stylesheet_decrypt : string :=
  concat_all (
    "#decrypt-ui{margin:2rem 0;font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:.82rem}" ::
    ".decrypt-hint{color:var(--muted);margin-bottom:.75rem}" ::
    "#decrypt-button{margin-top:.25rem;padding:.35rem 1rem;font-family:inherit;font-size:.82rem;border:1px solid var(--ink);background:var(--ink);color:var(--paper);cursor:pointer}" ::
    "#decrypt-button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}" ::
    "#decrypt-status{margin-top:.4rem;color:var(--muted)}" ::
    "#clear-key-button{display:none;margin-top:.5rem;margin-left:.5rem;padding:.35rem 1rem;font-family:inherit;font-size:.82rem;border:1px solid var(--rule);background:var(--paper);color:var(--muted);cursor:pointer}" ::
    (* :empty so the error auto-shows the moment ROCQ sets its textContent and
       stays hidden while empty (the success path leaves it empty).  The decrypt
       app only ever sets #decrypt-error's TEXT (dom_set_text), never its
       display — so visibility MUST be driven by content here, not by a
       dom_show.  Was `.decrypt-error{display:none}`, which hid it
       unconditionally => every decrypt failure was silent. *)
    ".decrypt-error{margin-top:.5rem;color:#c0392b}" ::
    ".decrypt-error:empty{display:none}" ::
    ".decrypt-fallback{color:var(--muted);font-size:.82rem}" ::
    "#decrypted-content{display:none;margin-top:2rem;animation:reader-fade .5s ease-out both}" ::
    "#real-body{font-family:Georgia,'Times New Roman',serif;font-size:1.125rem;line-height:1.55}" ::
    "#real-body img{max-width:100%;height:auto}" ::
    "#real-body p:has(> img){display:flex;gap:1rem;align-items:flex-start}" ::
    "#real-body p:has(> img) img{flex:1;min-width:0;max-width:50%;height:auto}" ::
    "#decrypted-content:has(#real-body img) #reader-canvas{display:none}" ::
    "#decrypted-content:has(#real-body img) #real-body{position:static;width:auto;height:auto;margin:0 0 1rem;clip:auto;overflow:visible;white-space:normal}" ::
    (* Verified-Reader canvas is the visible reading surface; sized to its CSS
       box (reader_begin reads clientWidth/Height * devicePixelRatio). *)
    "#reader-canvas{display:block;width:100%;max-width:38rem;height:32rem;margin:0 0 1rem;animation:reader-resolve .7s ease-out both}" ::
    (* #real-body kept in the DOM for accessibility but visually hidden (the
       canvas is the visual surface).  Standard clip-rect sr-only — textContent
       stays readable to assistive tech AND to the e2e text assertion. *)
    ".sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}" ::
    (* decrypt-resolve: the content + canvas fade/blur in when revealed (the
       ciphertext->set-prose moment).  Pure presentation; the canvas backing
       store is painted synchronously, so getImageData (e2e) is unaffected. *)
    "@keyframes reader-fade{from{opacity:0}to{opacity:1}}" ::
    "@keyframes reader-resolve{from{opacity:0;filter:blur(6px)}to{opacity:1;filter:blur(0)}}" ::
    (* a11y comfortable-spacing toggle (pure CSS).  Hide the raw checkbox; style
       the label as a button; when checked, hide the canvas and reveal #real-body
       as full-flow text with Zorzi-style increased letter/word spacing. *)
    ".reader-a11y-toggle{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}" ::
    ".reader-a11y-label{display:inline-block;margin:0 0 1rem;padding:.3rem .8rem;font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:.8rem;color:var(--muted);border:1px solid var(--rule);border-radius:2px;cursor:pointer}" ::
    ".reader-a11y-toggle:focus-visible ~ .reader-a11y-label{outline:2px solid var(--accent);outline-offset:2px}" ::
    "#reader-a11y:checked ~ .reader-a11y-label{background:var(--ink);color:var(--paper)}" ::
    "#reader-a11y:checked ~ #reader-canvas{display:none}" ::
    "#reader-a11y:checked ~ #real-body{position:static;width:auto;height:auto;margin:0 0 1rem;clip:auto;overflow:visible;white-space:normal;letter-spacing:.12em;word-spacing:.18em;line-height:1.8}" ::
    ".post-colophon{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--rule);font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.65rem;color:var(--muted);white-space:pre-wrap}" ::
    ".inbox-status::after{content:' ✉';color:var(--muted)}" ::
    ".inbox-status.unlocked::after{content:' 📜';color:var(--muted)}" ::
    ".inbox-status-msg{color:var(--muted);font-size:.82rem;font-family:-apple-system,Helvetica,Arial,sans-serif}" :: nil).

Definition stylesheet_enroll : string :=
  concat_all (
    (* Inbox enrollment call-to-action: a quiet link to /enroll/ (the inbox no
       longer runs crane_enroll; see render_inbox_page). *)
    ".enroll-cta{margin:2rem 0;font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:.82rem}" ::
    ".enroll-link{color:var(--muted)}" ::
    ".enroll-link:hover{color:var(--ink)}" ::
    "#enroll-ui{margin:2rem 0}" ::
    "#enroll-button{padding:.5rem 1.25rem;font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:.88rem;border:1px solid var(--ink);background:var(--ink);color:var(--paper);cursor:pointer;border-radius:4px}" ::
    "#enroll-button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}" ::
    "#enroll-status{margin-top:.5rem;font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:.82rem}" ::
    "#enroll-result{margin:2rem 0}" ::
    "#enroll-result code{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.88rem;background:var(--rule);padding:.15rem .35rem;border-radius:2px}" ::
    ".pubkey-display{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.7rem;background:var(--rule);padding:1rem;overflow-x:auto;word-break:break-all;border:1px solid var(--rule)}" ::
    ".enroll-note{color:var(--muted);font-size:.82rem;font-family:-apple-system,Helvetica,Arial,sans-serif;margin-top:1.5rem}" ::
    "#enroll-existing{margin:2rem 0;font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:.82rem}" ::
    "#enroll-existing-info{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:.72rem;background:var(--rule);padding:.75rem;overflow-x:auto}" :: nil).

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
