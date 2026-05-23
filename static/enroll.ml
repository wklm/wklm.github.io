(* Browser-side reader enrollment — compiled to JavaScript by js_of_ocaml.
   Handles WebAuthn passkey creation + ECDH P-256 keypair generation.
   All JS interop via typed [external] declarations; zero Js.Unsafe. *)

open Js_of_ocaml

(* ======== JavaScript bridge externals ================================= *)

external crane_enrollCreateReader
  :  (Js.js_string Js.t -> unit) Js.callback -> unit
  = "crane_enrollCreateReader"

external crane_enrollIsEnrolled
  :  (Js.js_string Js.t -> unit) Js.callback -> unit
  = "crane_enrollIsEnrolled"

external crane_enrollGetPubkeys
  :  (Js.js_string Js.t -> unit) Js.callback -> unit
  = "crane_enrollGetPubkeys"

external crane_sessionStorageGet : string -> string
  = "crane_sessionStorageGet"
external crane_sessionStorageSet : string -> string -> unit
  = "crane_sessionStorageSet"
external crane_sessionStorageRemove : string -> unit
  = "crane_sessionStorageRemove"

(* ======== DOM helpers ================================================= *)

let el_by_id id =
  try Some (Dom_html.getElementById id) with _ -> None

let el_text el =
  match Js.Opt.to_option (el##.textContent) with
  | Some s -> Js.to_string s | None -> ""

let show_el id =
  match el_by_id id with
  | Some el -> el##.style##.display := Js.string "block"
  | None -> ()

let hide_el id =
  match el_by_id id with
  | Some el -> el##.style##.display := Js.string "none"
  | None -> ()

let set_text id text =
  match el_by_id id with
  | Some el -> el##.textContent := Js.some (Js.string text)
  | None -> ()

let el_value id =
  match el_by_id id with
  | Some el ->
    (match Js.Opt.to_option (Dom_html.CoerceTo.textarea el) with
     | Some ta -> Js.to_string (ta##.value)
     | None -> el_text el)
  | None -> ""

(* ======== Enrollment logic ============================================ *)

let key_id = ref ""
let pubkey_hex = ref ""

(* Simple JSON-field extraction: look for "field":"value" *)
let extract_field field s =
  let pat = "\"" ^ field ^ "\":\"" in
  let pat_len = String.length pat in
  let rec find i =
    if i + pat_len > String.length s then ""
    else if String.sub s i pat_len = pat then
      let start = i + pat_len in
      match String.index_from_opt s start '"' with
      | None -> ""
      | Some e -> String.sub s start (e - start)
    else find (i + 1)
  in find 0

let on_enroll_success json_str =
  let s = Js.to_string json_str in
  if s = "" then begin
    set_text "enroll-status" "Enrollment failed. Make sure your browser supports WebAuthn."
  end else
    let err = extract_field "error" s in
    if err <> "" then begin
      set_text "enroll-status" ("Enrollment failed: " ^ err)
    end else begin
      key_id := extract_field "keyId" s;
      pubkey_hex := extract_field "pubkeyHex" s;
      if !key_id = "" || !pubkey_hex = "" then
        set_text "enroll-status" "Failed to parse enrollment result."
      else begin
        hide_el "enroll-ui";
        show_el "enroll-result";
        set_text "reader-key-id" !key_id;
        set_text "reader-pubkey-hex" !pubkey_hex;
      end
    end

let on_is_enrolled json_str =
  let s = Js.to_string json_str in
  if s = "" then
    set_text "enroll-status" "Failed to check enrollment status."
  else
    let err = extract_field "error" s in
    if err <> "" then begin
      set_text "enroll-status" ("Enrollment check failed: " ^ err)
    end else
      let found =
        let pat = "\"enrolled\":" in
        let pat_len = String.length pat in
        let rec find i =
          if i + pat_len > String.length s then false
          else if String.sub s i pat_len = pat then
            String.sub s (i + pat_len) 4 = "true"
          else find (i + 1)
        in find 0
      in
      if found then begin
        hide_el "enroll-ui";
        set_text "enroll-existing-status" "You already have a reader key enrolled on this device.";
        show_el "enroll-existing";
        (* Fetch and display existing keys *)
        let cb = Js.wrap_callback (fun result ->
          let keys = Js.to_string result in
          if keys <> "" then begin
            set_text "enroll-existing-info" ("Enrolled keys: " ^ keys)
          end
        ) in
        crane_enrollGetPubkeys cb
      end else begin
        show_el "enroll-ui"
      end

let () =
  match el_by_id "enroll-button" with
  | None -> ()
  | Some btn ->
    btn##.onclick := Dom.handler (fun _ev ->
      set_text "enroll-status" "Creating credentials...";
      let cb = Js.wrap_callback (fun result ->
        on_enroll_success result
      ) in
      crane_enrollCreateReader cb;
      Js._false
    );
    (* Check existing enrollment *)
    let cb = Js.wrap_callback (fun result ->
      on_is_enrolled result
    ) in
    crane_enrollIsEnrolled cb;
    ()
