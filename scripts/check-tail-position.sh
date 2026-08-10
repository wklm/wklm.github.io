#!/usr/bin/env bash
# check-tail-position.sh -- class-level stack-overflow prevention gate for the
# Crane-extracted C++ (research-stack-overflow-rootcause.md section 6).
#
# WHY THIS GATE EXISTS
# --------------------
# All five WASM stack-overflow bugs (body_to_html_aux and the four prior fixes
# eb1d2ac layout_all, 5cab40f scan_*, 5acd36c split_on_char_fuel, b99b788
# strip_ws) shared one mechanically-detectable signature: a Fixpoint whose
# recursive self-call is NOT in tail position (the recursive call nested inside
# another call -- StringLib::cat / List::cons -- or as an operand of `+`).
# Under em++ -O2 + Asyncify that shape grows one native frame per input byte,
# unbounded except by the fuel constant (65536) -- overflowing the 32 MB
# -sSTACK_SIZE.  ROCQ totality proofs can never see this (they are denotational;
# CIC has no call stack -- see the doc's section 2.2), so it must be re-checked
# on the *extracted* C++ at build time.
#
# WHAT THIS GATE CHECKS
# ---------------------
# For every Crane-emitted top-level function definition in the extracted
# .cpp files, every self-recursive call is classified:
#
#   TAIL  (accepted):
#     * the self-call is the returned expression of its return statement
#       (`return F(...);` -- the recursive call is the first call opened in the
#       return expression and nothing significant follows its closing paren;
#       argument sub-expressions such as `StringLib::cat(acc, ...)` INSIDE the
#       call are fine), or
#     * the self-call is the last statement of its path (`F(...); return; }` --
#       nothing but bare `return;`, block closes, and if/else branch structure
#       follows it; the frame is reusable, em++ TCOs it).
#
#   NON-TAIL  (violation):
#     * the self-call is an argument inside another call expression in a return
#       (`return StringLib::cat(chunk, F(...));`, `return List::cons(x, F(...));`
#       -- the exact body_to_html_aux / layout_all / scan_* / split_on_char_fuel
#       / strip_ws bug shapes), or
#     * the self-call is an operand (`return F(...) + 1;` -- the nat_of_int_fuel
#       shape), or
#     * the self-call is assigned / prefixed / a member or arrow callee
#       (`x = F(...);`, `x.F(...);` -- result is used), or
#     * the self-call's statement is followed by more code (not a bare return /
#       block close / else-branch), or
#     * the self-call is nested inside another self-call.
#
# The matcher is an awk state machine calibrated against REAL Crane 0.4 output
# (dune build from the current tree; e.g. `std::string
# InnerMime::body_to_html_aux(std::string s, int64_t pos, uint64_t fuel,
# std::string acc) {`).  It tracks paren/brace depth, skips string and char
# literals (the generated code embeds HTML/JS strings full of (){};), detects
# top-level definitions at column 0 (`NAME(` or `RetType NAME(`; long return
# types sit on their own lines), and ignores Crane's local `let fix` helpers
# compiled to self-passing lambdas (`auto go_impl = [&](auto &_self_go, ...)`)
# -- those are bounded by construction and out of scope (see the audit).
#
# GRANDFATHERED NON-TAIL FUNCTIONS
# --------------------------------
# The audit (research-stack-overflow-rootcause.md section 5 table + appendix)
# inventories the remaining non-tail self-recursions in the current tree.  They
# are input-bounded (small fields, image counts, lines of one SMTP session) or
# native-tool-only (no Asyncify amplification), and converting them to
# accumulator form is a .v source-level work item (out of scope here: this
# workflow may not touch src/).  They are grandfathered BY NAME below so the
# current tree passes the gate while ANY NEW non-tail self-recursion -- and any
# regression to the five fixed bug shapes -- fails CI.  Each entry cites its
# audit reference.  Removing an entry requires the corresponding .v fix first.
#
# USAGE
#   scripts/check-tail-position.sh [DIR]   # DIR with extracted *.cpp
#                                         (default: _build/default/FormalBlog)
#   scripts/check-tail-position.sh --selftest
#   scripts/check-tail-position.sh --list-grandfathered
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

GRANDFATHERED=(
  # -- browser decrypt surface (crane_decrypt.cpp / crane_enroll.cpp) --
  'MimeBuild::hex_decode_aux'      # audit §5 table: non-tail cat form, depth=hexlen/2<=65536.
                                   #   Listed "fix now" -- source-level debt, .v work item; the
                                   #   accumulator form is `acc + concat_all (rev acc)`.
  'MimeBuild::split_parts_aux'     # audit §5 table: one cons-wrapped branch; depth = MIME part
                                   #   boundaries (ordinary lines take the tail branch).
  'MimeBuild::concat_all'          # audit appendix candidate; depth = list length (small fields).
  'MimeBuild::join_comma'          # audit appendix candidate; depth = #recipients (small).
  'StringLib::nat_of_int_fuel'     # audit §5 safe list: `F(...)+1` shape but bounded by
                                   #   int-as-string length (~20 digits).
  'StringLib::hex_encode_aux'      # audit appendix candidate; depth = bytes to hex (small).
  'entries_to_triples'             # audit appendix candidate (DecryptApp); depth = wraps entries.
  'collect_ids_aux'                # enroll-side cons-wrapped; depth = enrolled key count.
  # -- Recipients.v (multi-recipient resolution; native tools only, depth capped) --
  'Recipients::mem_str'            # tail branch (or-branch) + argument-inside-call; depth = list len.
  'Recipients::dedup_str'          # cons-wrapped; depth = recipients (<= max_extra_recipients + 1 = 4).
  'Recipients::collect_kids'       # cons-wrapped; depth = comma-separated kids in frontmatter (small).
  'Recipients::take_kids'          # cons-wrapped; depth = max_extra_recipients (3).
  'Recipients::recips_ok'          # argument-inside-call; depth = recipients (<= 4).
  'Recipients::kid_list'           # cons-wrapped; depth = recipients (<= 4).
  'Recipients::wrap_all'           # cons-wrapped; depth = recipients (<= 4); one HPKE wrap per entry.
  'Recipients::readers_to'         # cons-wrapped; depth = recipients (<= 4).
  # -- generator (blog.cpp) --
  'html_escape_aux'                # per-byte cat-wrapped; depth = escaped chunk length.
  'nat_of_int_fuel0'               # `F(...)+1` shape; bounded by int-as-string length.
  'read_eml_list'                  # assigned recursion; depth = #posts-encrypted files.
  'insert_ep'                      # cons-wrapped; depth = #posts.
  'sort_eps'                       # self-call as argument of insert_ep; depth = #posts.
  # -- native tools (decrypt_post.exe / encrypt_post.exe) --
  'MimeBuild::inner_attachments'   # cons-wrapped; depth = #attachments.
  'read_images'                    # assigned recursion; depth = #images (native tool).
  'read_pubkeys'                   # assigned recursion; depth = #recipients (capped at max_extra_recipients + 1 = 4).
  'MimeBuild::wrap_base64_aux'     # cat-wrapped; depth = base64 lines of one image.
  'MimeBuild::collect_meta'        # cons-wrapped; depth = frontmatter lines.
  'MimeBuild::collect_images_aux'  # cons-wrapped; depth = markdown image refs.
  'MimeBuild::protected_block'     # cat-wrapped; depth = inner header count.
  'MimeBuild::image_parts'         # cat-wrapped; depth = #images.
  'MimeBuild::join_wraps'          # audit appendix candidate (HpkeEnvelope join class); depth = wraps.
  # -- SMTP listener (smtp_listener.cpp) --
  'clean_allow'                    # cons-wrapped; depth = allowlist entries.
  'StringLib::upcase_aux'          # audit appendix candidate; depth = header value length.
  'StringLib::downcase_aux'        # audit appendix candidate; depth = header value length.
  'ProcFFI::join_nul'              # cat-wrapped; depth = argv entries.
  'PostBuild::slugify_aux'         # cat-wrapped; depth = subject length.
  'MimeIngest::flatten_ws_aux'     # audit appendix candidate; depth = quoted-printable body.
  'MimeIngest::b64_decode_aux'     # audit appendix candidate; depth = base64 body.
  'MimeIngest::collect_text_parts' # audit appendix candidate; depth = MIME parts.
  'MimeIngest::join_blank'         # audit appendix candidate; depth = paragraphs.
)

# ---------------------------------------------------------------------------
# The matcher.  Emits one line per violation:
#   <file>:<line>: function <name> (def line <n>): <reason>
# and exits 1 if any violation was found.  Output format is part of the
# contract with the shell driver below (function name is field 3 after
# 'function').
#
# State machine notes (calibrated on real Crane output):
#   * top-level function defs start at column 0: `NAME(` or `RetType NAME(`
#     (a long return type sits on its own line(s) without `(`);
#   * the returned-expression rule keys on the FIRST callee opened in a
#     `return` statement and on nothing significant following its closing
#     paren (template-arg `>>(` and wrapper parens are tolerated);
#   * statement-tail calls (`F(...); return; }`) are resolved when the
#     function's body closes; between the call's `;` and the close only
#     `return` / `;` / `}` / `() ` (immediately-invoked lambdas) and
#     `} else { ... }` branch structure (suppression counter) may appear;
#   * local `let fix` lambdas are deliberately NOT treated as functions.
# ---------------------------------------------------------------------------
MATCHER='function reset_ret() {
  in_ret = 0; ret_first = ""; ret_line = 0; first_dep = -1
  first_closed = 0; self_count = 0; self_line = 0
}
function reset_stmt() {
  stmt_tokens = 0; stmt_self = 0; self_line = 0; self_dep = -1
  self_closed = 0
}
function viol(line, why) {
  if (!reported) {
    printf "%s:%d: function %s (def line %d): %s\n", FILENAME, line, fname, fdef, why
    bad = 1
  }
  reported = 1
}
FNR == 1 {
  infn = 0; pending_name = ""; pdep = 0; bdep = 0
  in_str = 0; in_chr = 0; np = 0; prev_sig = ""
  suppress_from = 0; supd = 0
  reset_ret(); reset_stmt()
}
{
  if (!infn && !pending_name && $0 ~ /^[A-Za-z_][A-Za-z0-9_:<> ,&*]*\(/) {
    pre = $0; sub(/\(.*/, "", pre)
    name = pre; sub(/^.*[^A-Za-z0-9_:]/, "", name)
    if (name != "" && name !~ /[^A-Za-z0-9_:]/) {
      pending_name = name; pending_line = NR; pdep = 0
    }
  }
  n = length($0)
  for (i = 1; i <= n; i++) {
    c = substr($0, i, 1)
    if (in_str) { if (c == "\\") i++; else if (c == "\"") in_str = 0; continue }
    if (in_chr) { if (c == "\\") i++; else if (c == "\x27") in_chr = 0; continue }
    if (c == "\"") { in_str = 1; tok = ""; continue }
    if (c == "\x27") { in_chr = 1; tok = ""; continue }
    if (c ~ /[A-Za-z0-9_:]/) { tok = tok c; continue }
    # ---- non-identifier char: token boundary ----
    if (tok != "") {
      if (c == "(") {
        # callee token
        if (infn) {
          if (in_ret) {
            if (ret_first == "") { ret_first = tok; first_dep = pdep }
            if (tok == fname) {
              self_count++; if (!self_line) self_line = NR
              if (self_count > 1) {
                viol(NR, "self-call nested inside another self-call in the same return statement")
              } else if (ret_first != fname) {
                viol(NR, "self-call is an argument inside call (" ret_first ") -- not the returned expression")
              } else if (first_closed) {
                viol(NR, "self-call appears after the returned expression first call closed -- not in tail position")
              }
            }
          } else if (tok == fname) {
            # self-call outside a return statement: only acceptable as the
            # bare last statement of its path (F(...); return; })
            if (stmt_self) {
              viol(NR, "nested self-call in the same statement")
            } else if (stmt_tokens > 1 || prev_sig == "." || prev_sig == ">") {
              viol(NR, "self-call is not the whole statement (prefixed or member/arrow callee) -- result is used or sequenced")
            } else {
              stmt_self = 1; self_line = NR; self_dep = pdep
            }
          } else if (np > 0 && np > suppress_from) {
            viol(pend_line[np], "statement-tail self-call is followed by call [" tok "]() -- not in tail position")
            np--
          }
        }
        # note: the ( itself is counted by the shared paren handler below
      } else {
        if (tok == "return" && pdep == 0 && !in_ret) {
          if (stmt_self) {
            stmt_self = 0
            viol(self_line, "self-call in a condition/prefix before a return -- not in tail position")
          }
          in_ret = 1; ret_line = NR; reported = 0
        } else if (tok == "else" && np > 0 && prev_sig == "}") {
          suppress_from = np; supd = 0
        } else if (infn && !in_ret && pdep == 0) {
          # any other top-level token: statement content / prefix / post-code
          stmt_tokens++
          if (stmt_self) {
            stmt_self = 0
            viol(self_line, "self-call statement is followed by more code -- not in tail position")
          } else if (np > 0 && np > suppress_from) {
            viol(pend_line[np], "statement-tail self-call is followed by more code -- not in tail position")
            np--
          }
        }
      }
      prev_sig = tok
      tok = ""
    } else if (c ~ /[+\-*\/%.,?:&|^!~=<]/) {
      # operator: statement content, post-close computation, or return tail check
      if (infn && !in_ret && pdep == 0) {
        stmt_tokens++
        if (stmt_self) {
          stmt_self = 0
          viol(self_line, "self-call result is used by operator [" c "] -- not in tail position")
        } else if (np > 0 && np > suppress_from) {
          viol(pend_line[np], "statement-tail self-call is followed by more code -- not in tail position")
          np--
        }
      }
      if (in_ret && first_closed && self_count > 0 && pdep == first_dep) {
        viol(self_line, "self-call is followed by operator [" c "] -- result computed after the call (non-tail)")
      }
      prev_sig = c
    }
    if (c == "(") { pdep++ }
    else if (c == ")") {
      pdep--
      if (in_ret && ret_first != "" && !first_closed && pdep == first_dep) first_closed = 1
      if (stmt_self && !self_closed && pdep == self_dep) self_closed = 1
      prev_sig = ")"
    }
    else if (c == "{") {
      if (pending_name != "" && pdep == 0) {
        infn = 1; fname = pending_name; fdef = pending_line
        pending_name = ""; bdep = 1; reported = 0
        np = 0; suppress_from = 0; supd = 0
        reset_ret(); reset_stmt(); prev_sig = "{"
      } else if (infn) {
        bdep++
        if (pdep == 0) {
          # real block (brace-init like sstate{...} sits at pdep > 0)
          if (np > 0 && np > suppress_from) {
            viol(pend_line[np], "statement-tail self-call is followed by a new block -- not in tail position")
            np--
          } else if (suppress_from > 0) {
            supd++
          }
          if (stmt_self) {
            stmt_self = 0
            viol(self_line, "self-call in an if/loop/block condition or prefix -- not in tail position")
          }
          reset_stmt()
        }
        prev_sig = "{"
      }
    }
    else if (c == "}") {
      if (infn) {
        bdep--
        if (pdep == 0 && supd > 0) {
          supd--
          if (supd == 0) suppress_from = 0
        }
        if (bdep == 0) {
          # function close: statement-tail candidates all resolved OK
          np = 0; suppress_from = 0; supd = 0
          infn = 0; fname = ""; reset_ret(); reset_stmt()
        }
      }
      prev_sig = "}"
    }
    else if (c == ";") {
      if (pdep == 0) {
        if (in_ret) reset_ret()
        if (stmt_self) {
          if (self_closed) {
            np++; pend_line[np] = self_line
          } else {
            viol(self_line, "self-call statement never closed cleanly")
          }
          stmt_self = 0
        }
        reset_stmt()
      }
      prev_sig = ";"
    }
  }
}
END {
  if (bad) exit 1
  exit 0
}'

in_list() { # name, array-name
  local needle="$1" arr="$2" e
  eval "for e in \"\${$arr[@]}\"; do [ \"\$e\" = \"$needle\" ] && return 0; done"
  return 1
}

# check_dir DIR -- run matcher + grandfather filter; prints report; exit 0/1.
check_dir() {
  local dir="$1" files raw rc name line
  shopt -s nullglob
  files=("$dir"/*.cpp)
  if [ ${#files[@]} -eq 0 ]; then
    echo "check-tail-position: no extracted C++ in $dir (build the builder image first)." >&2
    return 1
  fi
  set +e
  raw="$(awk "$MATCHER" "${files[@]}" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "check-tail-position: OK -- no non-tail self-recursion in $(basename "$dir")/*.cpp (${#files[@]} files)."
    return 0
  fi
  local flagged=() notes=()
  while IFS= read -r line; do
    name="$(sed -nE 's/^[^:]*:[0-9]+: function ([^ ]+) .*/\1/p' <<<"$line")"
    if [ -n "$name" ] && in_list "$name" GRANDFATHERED; then
      notes+=("$line")
    else
      flagged+=("$line")
    fi
  done <<<"$raw"
  if [ ${#notes[@]} -gt 0 ]; then
    echo "check-tail-position: ${#notes[@]} grandfathered non-tail call(s) (audit-tracked debt; see script header):"
    printf '  %s\n' "${notes[@]}"
  fi
  if [ ${#flagged[@]} -gt 0 ]; then
    echo "check-tail-position: FAIL -- non-tail self-recursion in extracted C++ (tail-position gate):" >&2
    printf '  %s\n' "${flagged[@]}" >&2
    return 1
  fi
  echo "check-tail-position: OK -- non-tail self-recursion only in grandfathered functions (${#notes[@]})."
  return 0
}

selftest() {
  local tmp; tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp:-}"' EXIT
  local pass=0 fail=0 out rc fname
  local label want tag

  run_case() {
    label="$1"; want="$2"; tag="$3"
    awk -v tag="$tag" '
      $0 == "### " tag { on = 1; next }
      $0 == "### end " tag { on = 0 }
      on { print }
    ' "$0" > "$tmp/case.cpp"
    out="$(check_dir "$tmp" 2>&1 || true)"
    rc=0; check_dir "$tmp" >/dev/null 2>&1 || rc=$?
    fname="$(sed -nE 's/^[^:]*:[0-9]+: function ([^ ]+) .*/\1/p' <<<"$out" | head -1)"
    if [ "$want" = pass ]; then
      if [ "$rc" -eq 0 ]; then echo "  [PASS] $label"; pass=$((pass+1))
      else echo "  [FAIL] $label -- expected PASS, got: $out"; fail=$((fail+1)); fi
    else
      if [ "$rc" -ne 0 ] && [ -n "$fname" ]; then echo "  [PASS] $label (caught: $fname)"; pass=$((pass+1))
      else echo "  [FAIL] $label -- expected a violation naming the function, got: $out"; fail=$((fail+1)); fi
    fi
  }

  echo "check-tail-position --selftest"
  echo "  historical stack-overflow bug shapes (MUST be caught):"
  run_case "old body_to_html_aux (cat-wrapped, root cause)"    fail bug_body
  run_case "old layout_all (cons-wrapped)"                      fail bug_layout
  run_case "old scan_width (cons-wrapped)"                      fail bug_scan
  run_case "old split_on_char_fuel (cons-wrapped)"              fail bug_split
  run_case "old strip_ws_aux (cat-wrapped)"                     fail bug_strip
  run_case "nat_of_int_fuel shape (F(...)+1)"                   fail bug_plus
  run_case "assigned self-call (x = F(...))"                    fail bug_assign
  run_case "self-call followed by more code in statement"       fail bug_seq
  echo "  current-codebase tail shapes (MUST pass):"
  run_case "layout_all_tr tail accumulator (multi-line return)" pass ok_layout_tr
  run_case "body_to_html_aux tail accumulator (cat in args)"    pass ok_body_tr
  run_case "scan_width_tr tail"                                 pass ok_scan_tr
  run_case "statement-tail void recursion (F(); return; }"      pass ok_stmt_tail
  run_case "statement-tail with else-branch"                    pass ok_stmt_else
  run_case "local let-fix lambda (out of scope)"                pass ok_lambda
  run_case "grandfathered non-tail (MimeBuild::hex_decode_aux)" pass ok_grandfathered
  run_case "no self-recursion at all"                           pass ok_plain

  echo "  selftest: $pass passed, $fail failed"
  if [ "$fail" -ne 0 ]; then
    echo "check-tail-position: SELFTEST FAILED" >&2
    exit 1
  fi
}

case "${1:-}" in
  --selftest) selftest; exit 0 ;;
  --list-grandfathered) printf '%s\n' "${GRANDFATHERED[@]}"; exit 0 ;;
esac

check_dir "${1:-_build/default/FormalBlog}"

# ---------------------------------------------------------------------------
# Synthetic test fixtures (used by --selftest; embedded in a heredoc so the
# shell never executes them -- the selftest extracts them from this file text).
# ---------------------------------------------------------------------------
cat <<'TAIL_FIXTURES_EOF' >/dev/null
### bug_body
std::string InnerMime::body_to_html_aux(std::string s, int64_t pos, uint64_t fuel) {
  if (fuel <= 0) {
    return "";
  } else {
    uint64_t f_ = fuel - 1;
    return StringLib::cat(PrimString::sub(s, pos, 1),
                          InnerMime::body_to_html_aux(s, pos + 1, f_));
  }
}
### end bug_body
### bug_layout
List<ParaLayout> layout_all(const List<std::string> &ps) {
  if (std::holds_alternative<typename List<std::string>::Nil>(ps.v())) {
    return List<ParaLayout>::nil();
  } else {
    const auto &[a0, a1] = std::get<typename List<std::string>::Cons>(ps.v());
    return List<ParaLayout>::cons(ParaLayout::pltext(a0), layout_all(*a1));
  }
}
### end bug_layout
### bug_scan
List<sp> KnuthPlass::scan_width(int64_t acc, const List<Item> &p) {
  if (std::holds_alternative<typename List<Item>::Nil>(p.v())) {
    return List<sp>::nil();
  } else {
    const auto &[a0, a1] = std::get<typename List<Item>::Cons>(p.v());
    return List<sp>::cons(sp(acc), KnuthPlass::scan_width(acc + 1, *a1));
  }
}
### end bug_scan
### bug_split
List<std::string> StringLib::split_on_char_fuel(std::string s, int64_t ch, int64_t pos, uint64_t f) {
  if (f <= 0) {
    return List<std::string>::nil();
  } else {
    uint64_t f_ = f - 1;
    int64_t nl = StringLib::find_char(s, ch, pos, UINT64_C(65536));
    if (nl < 0) {
      return List<std::string>::nil();
    } else {
      return List<std::string>::cons(StringLib::sub(s, pos, nl),
                                     StringLib::split_on_char_fuel(s, ch, nl + 1, f_));
    }
  }
}
### end bug_split
### bug_strip
std::string MimeBuild::strip_ws_aux(std::string s, int64_t pos, uint64_t fuel) {
  if (fuel <= 0) {
    return "";
  } else {
    uint64_t f_ = fuel - 1;
    return StringLib::cat(PrimString::sub(s, pos, 1),
                          MimeBuild::strip_ws_aux(s, pos + 1, f_));
  }
}
### end bug_strip
### bug_plus
uint64_t count_digits(int64_t i, uint64_t remaining) {
  if (remaining <= 0) {
    return 0;
  } else {
    uint64_t remaining_ = remaining - 1;
    if (i < 0) {
      return 0;
    } else {
      return (count_digits(i / 10, remaining_) + 1);
    }
  }
}
### end bug_plus
### bug_assign
std::string load_images(const List<std::string> &rels) {
  if (std::holds_alternative<typename List<std::string>::Nil>(rels.v())) {
    return "";
  } else {
    const auto &[a0, a1] = std::get<typename List<std::string>::Cons>(rels.v());
    std::string rest = load_images(*a1);
    return rest;
  }
}
### end bug_assign
### bug_seq
void write_pages(const List<std::string> &eps) {
  if (std::holds_alternative<typename List<std::string>::Nil>(eps.v())) {
    return;
  } else {
    const auto &[a0, a1] = std::get<typename List<std::string>::Cons>(eps.v());
    write_pages(*a1);
    flush();
    return;
  }
}
### end bug_seq
### ok_layout_tr
List<ParaLayout> layout_all_tr(const List<std::string> &ps,
                               List<ParaLayout> acc) {
  if (std::holds_alternative<typename List<std::string>::Nil>(ps.v())) {
    return std::move(acc).rev();
  } else {
    const auto &[a0, a1] = std::get<typename List<std::string>::Cons>(ps.v());
    if (is_latex_para(a0)) {
      return layout_all_tr(
          *a1, List<ParaLayout>::cons(ParaLayout::pllatex(a0), std::move(acc)));
    } else {
      return layout_all_tr(
          *a1,
          List<ParaLayout>::cons(
              ParaLayout::pltext(GlyphLayout::layout_paragraph(
                  Metrics::advance_of, MEASURE, Metrics::shape_paragraph(a0))),
              std::move(acc)));
    }
  }
}
### end ok_layout_tr
### ok_body_tr
std::string InnerMime::body_to_html_aux(std::string s, int64_t pos,
                                        uint64_t fuel, std::string acc) {
  int64_t n = static_cast<int64_t>(s.length());
  if (fuel <= 0) {
    return acc;
  } else {
    uint64_t f_ = fuel - 1;
    if (n <= pos) {
      return acc;
    } else {
      int64_t c = s[pos];
      if (StringLib::int_eqb(c, INT64_C(10))) {
        if ((((pos + INT64_C(1)) & 0x7FFFFFFFFFFFFFFFLL) < n &&
             StringLib::int_eqb(s[((pos + INT64_C(1)) & 0x7FFFFFFFFFFFFFFFLL)],
                                INT64_C(10)))) {
          return InnerMime::body_to_html_aux(
              s, ((pos + INT64_C(2)) & 0x7FFFFFFFFFFFFFFFLL), f_,
              StringLib::cat(acc, "</p><p>"));
        } else {
          return InnerMime::body_to_html_aux(
              s, ((pos + INT64_C(1)) & 0x7FFFFFFFFFFFFFFFLL), f_,
              StringLib::cat(acc, "<br>"));
        }
      } else {
        return InnerMime::body_to_html_aux(
            s, ((pos + INT64_C(1)) & 0x7FFFFFFFFFFFFFFFLL), f_,
            StringLib::cat(acc, InnerMime::escape_byte(c)));
      }
    }
  }
}
### end ok_body_tr
### ok_scan_tr
List<sp> KnuthPlass::scan_width_tr(int64_t acc, const List<Item> &p,
                                   List<sp> acc_l) {
  if (std::holds_alternative<typename List<Item>::Nil>(p.v())) {
    return std::move(acc_l).rev();
  } else {
    const auto &[a0, a1] = std::get<typename List<Item>::Cons>(p.v());
    return KnuthPlass::scan_width_tr(acc + 1, *a1,
                                     List<sp>::cons(sp(acc), std::move(acc_l)));
  }
}
### end ok_scan_tr
### ok_stmt_tail
void write_eml_pages(std::string output_dir, const List<EncryptedPost> &eps,
                     std::string version) {
  if (std::holds_alternative<typename List<EncryptedPost>::Nil>(eps.v())) {
    return;
  } else {
    const auto &[a0, a1] =
        std::get<typename List<EncryptedPost>::Cons>(eps.v());
    [&]() {
      std::ofstream file(file_output_path(output_dir, a0.ep_slug));
      file << render_eml_page(a0, version);
    }();
    write_eml_pages(output_dir, *a1, version);
    return;
  }
}
### end ok_stmt_tail
### ok_stmt_else
void render_paras(const List<ParaLayout> &qss, int64_t dy) {
  if (std::holds_alternative<typename List<ParaLayout>::Nil>(qss.v())) {
    return;
  } else {
    const auto &[a0, a1] = std::get<typename List<ParaLayout>::Cons>(qss.v());
    if (std::holds_alternative<typename ParaLayout::PLText>(a0.v())) {
      const auto &[a00] = std::get<typename ParaLayout::PLText>(a0.v());
      draw_quads_at(a00, dy);
      render_paras(*a1, ((dy + max_qy(a00, INT64_C(0))) + para_gap));
      return;
    } else {
      const auto &[a00] = std::get<typename ParaLayout::PLLatex>(a0.v());
      render_paras(*a1, ((dy + max_qy(a00, INT64_C(0))) + para_gap));
      return;
    }
  }
}
### end ok_stmt_else
### ok_lambda
std::string scan_boundary(std::string body) {
  int64_t n = static_cast<int64_t>(body.length());
  auto scan_impl = [&](auto &_self_scan, int64_t pos,
                       uint64_t fuel_) -> std::string {
    if (fuel_ <= 0) {
      return "";
    } else {
      uint64_t f_ = fuel_ - 1;
      if (n <= pos) {
        return "";
      } else {
        return _self_scan(_self_scan, ((pos + INT64_C(1)) & 0x7FFFFFFFFFFFFFFFLL), f_);
      }
    }
  };
  auto scan = [&](int64_t pos, uint64_t fuel_) -> std::string {
    return scan_impl(scan_impl, pos, fuel_);
  };
  return scan(INT64_C(0), UINT64_C(65536));
}
### end ok_lambda
### ok_grandfathered
std::string MimeBuild::hex_decode_aux(std::string s, int64_t pos, uint64_t fuel) {
  if (fuel <= 0) {
    return "";
  } else {
    uint64_t f_ = fuel - 1;
    int64_t n = static_cast<int64_t>(s.length());
    if (n <= (pos + 1)) {
      return "";
    } else {
      return StringLib::cat(PrimString::make(1, s[pos]),
                            MimeBuild::hex_decode_aux(s, pos + 2, f_));
    }
  }
}
### end ok_grandfathered
### ok_plain
std::string StringLib::trim(std::string s) {
  return StringLib::trim_right(StringLib::trim_left(s));
}
### end ok_plain
TAIL_FIXTURES_EOF
