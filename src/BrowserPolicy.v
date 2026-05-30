(* BrowserPolicy.v — the WebAuthn ceremony POLICY, lifted out of the EM_ASM
   shim and into ROCQ where it belongs.

   THE BUG THIS FIXES.  The shipped browser_helpers.h hard-coded the WebAuthn
   create options *inside* the EM_ASM body: pubKeyCredParams, residentKey,
   userVerification, timeouts were all JS literals.  That is a thin-shim
   CONTRACT VIOLATION (TRUSTED.md C2: shims do platform delegation + byte
   marshalling ONLY — never policy).  The concrete fallout was the
   residentKey:'required' enroll bug: an authenticator without a resident-key
   slot fails create() and enrollment silently dies, with the policy decision
   unreviewable because it lived in a string literal no proof or guard could
   see.  Lifting the policy here makes it (a) a single source of truth shared by
   every ceremony, (b) reviewable ROCQ data, and (c) guardable — see the
   [rs256_offered] compile-time regression Example below, which is exactly the
   check that would have caught the algorithm-list half of the class of bug.

   CRANE-SAFETY (crane-extraction-gotchas, strictly observed):
     - ints (int63) + primitive strings ONLY; no list/record crosses the FFI
       (the policy is marshalled as a comma-joined CSV string + scalar ints,
       split back into a JS array in the thin shim);
     - no chained if-in-let (would leak std::any);
     - no std::any-producing constructs anywhere.
   The membership helper + Example below are pure ROCQ proof obligations; they
   are erased at extraction (no runtime cost, no FFI surface). *)

From Corelib Require Import PrimString PrimInt63.
From Stdlib Require Import Lists.List.
Import ListNotations.
Require Import StringLib.

Open Scope pstring_scope.

(* ---- COSE algorithm identifiers (RFC 8152 / WebAuthn) --------------- *)
(* Negative ints, written via PrimInt63.sub of the magnitude from 0 (int63 has
   no unary-minus literal; each numeral must carry its own [%int63] suffix or it
   defaults to [nat]).  [PrimInt63.sub 0 n] is the wrapped two's complement,
   exactly the bit pattern the shim would cast back with [+a] in JS — but the
   values only ever travel as the decimal STRINGS in [wa_alg_csv], so this int
   form is the documented spec value, not the marshalled one. *)
Definition cose_es256 : int := PrimInt63.sub 0%int63 7%int63.    (* ECDSA  w/ SHA-256  (-7)   *)
Definition cose_rs256 : int := PrimInt63.sub 0%int63 257%int63.  (* RSASSA w/ SHA-256  (-257) *)
Definition cose_eddsa : int := PrimInt63.sub 0%int63 8%int63.    (* EdDSA              (-8)   *)

(* ---- The offered algorithm list, as a comma-joined CSV --------------- *)
(* This CSV is THE source of truth for pubKeyCredParams.  The thin shim splits
   it on ',' and maps each token [a] to { type:'public-key', alg:+a } — so the
   set of offered algorithms is decided here, in reviewable ROCQ, never in JS.
   Order = preference order (ES256 first, then RS256, then EdDSA): widening the
   set to include RS256 is what makes platform authenticators that lack ES256
   (rare, but real — and the kind of mismatch the original hard-coded
   [-7,-8]-only list silently excluded) able to enroll. *)
Definition wa_alg_csv : string := "-7,-257,-8".

(* ---- Resident-key / user-verification policy ------------------------- *)
(* THE residentKey:'required' FIX.  'discouraged' (not 'required') so a
   non-resident / non-discoverable authenticator still enrolls: the reader key
   that actually protects the content lives in IndexedDB (EnrollApp.v), the
   passkey is only a best-effort presence gate (DecryptApp.passkey_gate), so a
   discoverable credential is NOT a requirement and demanding one needlessly
   fails enrollment on common authenticators. *)
Definition rk_discouraged : string := "discouraged".

(* userVerification 'preferred' (not 'required'): take a UV gesture when the
   authenticator offers one, but never hard-fail enroll/assert on a
   UV-incapable authenticator. *)
Definition uv_preferred : string := "preferred".

(* ---- Ceremony timeouts (ms) ----------------------------------------- *)
Definition wa_create_timeout : int := 120000%int63.  (* registration: 2 min *)
Definition wa_get_timeout     : int := 60000%int63.   (* assertion:     1 min *)

(* ===================================================================== *)
(* COMPILE-TIME regression guard.                                         *)
(*                                                                        *)
(* Membership of a decimal token in [wa_alg_csv], decided purely over the    *)
(* CSV string (split on ',' then string-compare) — no int parsing, so it     *)
(* checks the EXACT bytes the shim will receive and map.  This is the check  *)
(* that would have caught the algorithm half of the ceremony-policy bug: if  *)
(* RS256 were ever dropped from the offered set, [rs256_offered] below stops  *)
(* compiling, failing the builder stage (which builds the .vo) before any    *)
(* WASM ever ships.  Erased at extraction.                                   *)
(* ===================================================================== *)

(* [alg_offered tok] = is the decimal token [tok] one of the comma-separated
   entries of [wa_alg_csv]?  [existsb] over the split is structural and total. *)
Definition alg_offered (tok : string) : bool :=
  existsb (fun a => string_eqb (trim a) tok)
          (split_on_char_fuel wa_alg_csv ch_comma 0%int63 16%nat).

(* The guard: RS256 (-257) is in the offered algorithm list.  [reflexivity]
   forces full computation of the split + comparison at type-check time. *)
Example rs256_offered : alg_offered "-257" = true.
Proof. reflexivity. Qed.

(* Companion guards (same shape) so the whole declared set is pinned: dropping
   ES256 or EdDSA would also break the build here. *)
Example es256_offered : alg_offered "-7" = true.
Proof. reflexivity. Qed.

Example eddsa_offered : alg_offered "-8" = true.
Proof. reflexivity. Qed.
