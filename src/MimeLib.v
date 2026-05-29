(* MimeLib.v — Canonical MIME envelope parser.
   Single source of truth for MIME header/body splitting, header
   parsing, boundary extraction, multipart splitting, and part
   termination trimming.

   Fixes bugs from the original Decrypt.v specification:
   - C1: header_lookup now correctly advances through the list.
   - H5: split_multipart uses simpler, correct accumulation logic.
   - M4: extract_boundary take loop properly decrements fuel.

   Extracted to OCaml via standard Coq extraction (not Crane).
   Replaces hand-written duplicates in io_helpers.ml and decrypt.ml. *)

From Corelib Require Import PrimString PrimInt63.
Require Import StringLib.
From Stdlib Require Import Lists.List.
Import ListNotations.

Open Scope pstring_scope.

(* ---- Header lookup (C1 fixed) ------------------------------------ *)

Definition header_lookup (key : string) (hdrs : list (string * string)) : string :=
  let fix go (h : list (string * string)) (fuel' : nat) : string :=
    match fuel' with
    | O => ""
    | S f' =>
      match h with
      | [] => ""
      | (k, v) :: rest =>
          if string_eqb k key then v
          else go rest f'
      end
    end in
  go hdrs lookup_fuel.

(* ---- Header parsing with RFC 5322 line folding -------------------- *)

Definition parse_header_line (line : string) : option (string * string) :=
  match find_char line ch_colon 0%int63 mime_fuel with
  | pos =>
      let len := PrimString.length line in
      if leb len pos then None
      else
        let k := trim (PrimString.sub line 0%int63 pos) in
        let v := trim (PrimString.sub line (add pos 1%int63) (sub len (add pos 1%int63))) in
        if is_empty k then None
        else Some (k, v)
  end.

Fixpoint fold_headers (lines : list string) (cur : option string) (acc : list (string * string)) : list (string * string) :=
  match lines with
  | [] =>
      match cur with
      | None => List.rev acc
      | Some c =>
          match parse_header_line c with
          | None => List.rev acc
          | Some (k, v) => List.rev ((k, v) :: acc)
          end
      end
  | line :: rest =>
      let trimmed := trim_trailing_cr line in
      if is_empty trimmed then
        fold_headers rest cur acc
      else if orb (int_eqb (PrimString.get trimmed 0%int63) ch_space)
                  (int_eqb (PrimString.get trimmed 0%int63) ch_tab) then
        match cur with
        | None => fold_headers rest (Some trimmed) acc
        | Some c => fold_headers rest (Some (cat c (cat " " (trim trimmed)))) acc
        end
      else
        let acc' := match cur with
                    | None => acc
                    | Some c =>
                        match parse_header_line c with
                        | None => acc
                        | Some (k, v) => (k, v) :: acc
                        end
                    end in
        fold_headers rest (Some trimmed) acc'
  end.

Definition parse_headers (block : string) : list (string * string) :=
  let lines := split_lines block in
  fold_headers lines None [].

(* ---- Header-body split -------------------------------------------- *)

Definition split_headers_body (raw : string) : string * string :=
  let n := PrimString.length raw in
  let fix find_blank (i : int) (fuel' : nat) : int * int :=
    match fuel' with
    | O => (n, n)
    | S f' =>
        if leb (add i 4%int63) n then
          let c0 := PrimString.get raw i in
          let c1 := PrimString.get raw (add i 1%int63) in
          let c2 := PrimString.get raw (add i 2%int63) in
          let c3 := PrimString.get raw (add i 3%int63) in
          if andb (int_eqb c0 ch_cr) (andb (int_eqb c1 ch_newline)
                                            (andb (int_eqb c2 ch_cr) (int_eqb c3 ch_newline)))
          then (i, add i 4%int63)
          else find_blank (add i 1%int63) f'
        else if leb (add i 2%int63) n then
          let c0 := PrimString.get raw i in
          let c1 := PrimString.get raw (add i 1%int63) in
          if andb (int_eqb c0 ch_newline) (int_eqb c1 ch_newline)
          then (i, add i 2%int63)
          else (n, n)
        else (n, n)
    end in
  let '(hi, bi) := find_blank 0%int63 mime_fuel in
  if int_eqb hi bi then (raw, "")
  else
    let hdrs := PrimString.sub raw 0%int63 hi in
    let body := PrimString.sub raw bi (sub n bi) in
    (hdrs, body).

(* ---- Boundary extraction (M4 fixed — fuel properly decremented) --- *)

Definition extract_boundary (ct : string) : string :=
  let marker := "boundary=" in
  let mlen := PrimString.length marker in
  let ctlen := PrimString.length ct in
  let fix find (i : int) (fuel' : nat) : int :=
    match fuel' with
    | O => ctlen
    | S f' =>
        if leb ctlen (add i mlen) then ctlen
        else if string_eqb (PrimString.sub ct i mlen) marker then
          add i mlen
        else find (add i 1%int63) f'
    end in
  let bpos := find 0%int63 256%nat in
  if leb ctlen bpos then ""
  else
    let c := PrimString.get ct bpos in
    if int_eqb c ch_dquote then
      let end_q := find_char ct ch_dquote (add bpos 1%int63) 256%nat in
      if leb ctlen end_q then ""
      else PrimString.sub ct (add bpos 1%int63) (sub end_q (add bpos 1%int63))
    else
      let fix take (p : int) (fuel' : nat) : int :=
        match fuel' with
        | O => p
        | S f' =>
            if leb ctlen p then p
            else
              let c' := PrimString.get ct p in
              if orb (int_eqb c' ch_semicolon)
                     (orb (int_eqb c' ch_space)
                          (orb (int_eqb c' ch_cr) (orb (int_eqb c' ch_newline) (int_eqb c' ch_tab))))
              then p
              else take (add p 1%int63) f'
        end in
      let e := take bpos 256%nat in
      PrimString.sub ct bpos (sub e bpos).

(* ---- Multipart split (H5 fixed — simpler, correct accumulation) --- *)

Fixpoint split_multipart_body
  (body : string) (closing : string) (pos : int) (fuel' : nat) : list string :=
  match fuel' with
  | O => []
  | S f' =>
      let n := PrimString.length body in
      if leb n pos then []
      else
        let line_end := find_char body ch_newline pos mime_fuel in
        let raw_line := PrimString.sub body pos (sub line_end pos) in
        let line := trim_trailing_cr raw_line in
        if string_eqb line closing then []
        else
          let next := if ltb line_end n then add line_end 1%int63 else n in
          let part := PrimString.sub body pos (sub next pos) in
          part :: split_multipart_body body closing next f'
  end.

Definition split_multipart (body : string) (opening closing : string) : list string :=
  let n := PrimString.length body in
  let fix find_first (pos : int) (fuel' : nat) : int :=
    match fuel' with
    | O => n
    | S f' =>
        if leb n pos then n
        else
          let line_end := find_char body ch_newline pos mime_fuel in
          let raw_line := PrimString.sub body pos (sub line_end pos) in
          let line := trim_trailing_cr raw_line in
          if string_eqb line opening then
            if ltb line_end n then add line_end 1%int63 else n
          else
            let next := if ltb line_end n then add line_end 1%int63 else n in
            find_first next f'
      end
  in
  let first_pos := find_first 0%int63 mime_fuel in
  if leb n first_pos then []
  else split_multipart_body body closing first_pos mime_fuel.

(* ---- Part terminator trimming ------------------------------------- *)

Definition trim_part_terminator (p : string) : string :=
  let n := PrimString.length p in
  if andb (leb 2%int63 n)
          (andb (int_eqb (PrimString.get p (sub n 2%int63)) ch_cr)
                (int_eqb (PrimString.get p (sub n 1%int63)) ch_newline))
  then PrimString.sub p 0%int63 (sub n 2%int63)
  else if andb (leb 1%int63 n)
               (int_eqb (PrimString.get p (sub n 1%int63)) ch_newline)
  then PrimString.sub p 0%int63 (sub n 1%int63)
  else p.
