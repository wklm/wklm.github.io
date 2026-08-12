(* InnerMimeTests.v — machine-checked Examples for the markdown renderer
   (md_to_html / md_inline / the block classifiers).  Every assertion is an
   [Example ... := eq_refl] closed by conversion, so @proofs machine-checks
   the renderer's actual byte output for each construct.

   NOTE ON NEWLINES: Coq string literals do NOT process "\\n" escapes — the
   bytes of "a\\nb" are a,\,n,b.  The markdown bodies the renderer sees at
   runtime contain REAL LF bytes (0x0A), so the fixtures below build their
   line breaks with [lf] (MimeBuild.lf = PrimString.make 1 10) and verify the
   expected outputs the same way.

   The T1 discipline is exercised here too: the "<script>" fixture must come
   out fully escaped — the only tags in the output are the fixed literals the
   renderer emits, never input-derived markup. *)

From Corelib Require Import PrimString PrimInt63.
Require Import InnerMime.
Require Import MimeBuild.        (* lf : the real LF byte *)
From Stdlib Require Import Lists.List.
Open Scope pstring_scope.

(* ---- paragraphs ------------------------------------------------------ *)

Example md_plain_paragraph : md_to_html "Hello world" = "<p>Hello world</p>"
  := eq_refl.

Example md_two_paragraphs :
  md_to_html (cat "First paragraph." (cat lf (cat lf "Second paragraph.")))
  = "<p>First paragraph.</p><p>Second paragraph.</p>"
  := eq_refl.

Example md_softbreak_br :
  md_to_html (cat "line one" (cat lf "line two"))
  = "<p>line one<br>line two</p>"
  := eq_refl.

Example md_frontmatter_stripped :
  md_to_html (cat "---" (cat lf
     (cat "title: Hidden" (cat lf
     (cat "date: 2026-01-01" (cat lf
     (cat "---" (cat lf (cat lf "Body text.")))))))))
  = "<p>Body text.</p>"
  := eq_refl.

(* ---- headings -------------------------------------------------------- *)

Example md_h1 : md_to_html "# Title" = "<h1>Title</h1>" := eq_refl.
Example md_h2 : md_to_html "## Subtitle" = "<h2>Subtitle</h2>" := eq_refl.
Example md_h3 : md_to_html "### Third" = "<h3>Third</h3>" := eq_refl.
Example md_h6 : md_to_html "###### Deepest" = "<h6>Deepest</h6>" := eq_refl.
Example md_hash_no_space_is_not_heading :
  md_to_html "#notaheading" = "<p>#notaheading</p>" := eq_refl.

(* ---- inline formatting ----------------------------------------------- *)

Example md_bold : md_to_html "a **bold** bit"
  = "<p>a <strong>bold</strong> bit</p>" := eq_refl.
Example md_italic : md_to_html "an *em* bit"
  = "<p>an <em>em</em> bit</p>" := eq_refl.
Example md_code_span : md_to_html "use `crane`"
  = "<p>use <code>crane</code></p>" := eq_refl.
Example md_link : md_to_html "[docs](https://x.example/a)"
  = "<p><a href='https://x.example/a'>docs</a></p>" := eq_refl.
Example md_link_escapes_url : md_to_html "[x](https://x/?a=1&b=2)"
  = "<p><a href='https://x/?a=1&amp;b=2'>x</a></p>" := eq_refl.
Example md_link_escapes_apos_in_url : md_to_html "[x](https://x/a'b)"
  = "<p><a href='https://x/a&#39;b'>x</a></p>" := eq_refl.
Example md_unmatched_star_stays_literal :
  md_to_html "a * b" = "<p>a * b</p>" := eq_refl.

(* ---- lists ----------------------------------------------------------- *)

Example md_ul :
  md_to_html (cat "- one" (cat lf (cat "- two" (cat lf "- three"))))
  = "<ul><li>one</li><li>two</li><li>three</li></ul>" := eq_refl.
Example md_ul_star :
  md_to_html (cat "* one" (cat lf "* two"))
  = "<ul><li>one</li><li>two</li></ul>" := eq_refl.
Example md_ol :
  md_to_html (cat "1. first" (cat lf "2. second"))
  = "<ol><li>first</li><li>second</li></ol>" := eq_refl.
Example md_list_inline : md_to_html "- **bold** item"
  = "<ul><li><strong>bold</strong> item</li></ul>" := eq_refl.

(* ---- blockquote / code / hr ------------------------------------------ *)

Example md_quote :
  md_to_html "> quoted line" = "<blockquote><p>quoted line</p></blockquote>"
  := eq_refl.
Example md_quote_multi :
  md_to_html (cat "> first" (cat lf "> second"))
  = "<blockquote><p>first</p><p>second</p></blockquote>" := eq_refl.
Example md_code_fence :
  md_to_html (cat "```" (cat lf (cat "let x = 1 < 2" (cat lf "```"))))
  = cat "<pre><code>let x = 1 &lt; 2" (cat lf "</code></pre>") := eq_refl.
Example md_hr : md_to_html "---" = "<hr>" := eq_refl.
Example md_hr_asterisks : md_to_html "***" = "<hr>" := eq_refl.

(* ---- inline stripping (canvas path) --------------------------------- *)

Example md_strip_bold : md_strip_inline "a **bold** bit" = "a bold bit"
  := eq_refl.
Example md_strip_em_code : md_strip_inline "*em* and `code`" = "em and code"
  := eq_refl.
Example md_strip_link : md_strip_inline "[label](https://x)" = "label"
  := eq_refl.
Example md_strip_unmatched : md_strip_inline "a * b" = "a * b"
  := eq_refl.

(* ---- escaping discipline (T1) ---------------------------------------- *)

Example md_script_stays_escaped :
  md_to_html "<script>alert('x')</script>"
  = "<p>&lt;script&gt;alert('x')&lt;/script&gt;</p>" := eq_refl.
Example md_angle_and_amp :
  md_to_html "a < b && c > d"
  = "<p>a &lt; b &amp;&amp; c &gt; d</p>" := eq_refl.
