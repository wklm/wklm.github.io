# crane_blog

A static site generator whose core is written in [Rocq](https://rocq-prover.org)
and extracted to C++ by [Bloomberg's Crane](https://github.com/bloomberg/crane).
Deployed at <https://wklm.github.io>.

## Engine

`src/Logic.v` contains the entire transformation: frontmatter parser,
Markdown subset, page assembly, HTML shell, stylesheet. Every `Fixpoint`
is total (structural recursion or explicit `nat` fuel). `dune build`
runs `Crane Extraction "blog" run`, which emits `blog.h` / `blog.cpp`;
`src/dune` emits `main.cpp`; clang compiles everything at `-std=c++2b -O2`
into `blog_generator.exe`. The binary reads `./posts/`, writes
`./_site/`, exits. No runtime interpretation, no hand-written C++.

Totality, Rocq type-checking, successful extraction, and clang
acceptance all hold by construction. The *semantics* of the parser and
renderer are reviewed, not proven; `html_escape` is trusted; I/O
handlers are trusted.

## Post syntax

A post is a UTF-8 Markdown file in `posts/`. Frontmatter is delimited
by two `---` lines at the top.

### Frontmatter keys

| key              | meaning                                                         |
|------------------|-----------------------------------------------------------------|
| `title`          | `<h1>` and `<title>`; falls back to first heading in the body   |
| `date`           | rendered verbatim; also the lexicographic sort key (descending) |
| `slug`           | output directory; falls back to the file stem                   |
| `topic`          | small label before the date in the meta line                    |
| `summary`        | `<meta name='description'>` on the post page                    |
| `lead_image`     | filename in `posts/`; rendered between header and body (essays) |
| `lead_image_alt` | alt text for the lead image                                     |
| `kind`           | `photo` for photo posts; anything else is an essay (default)    |
| `draft`          | exactly `true` drops the post from the site                     |

Unknown keys are silently ignored. Slugs are whitelisted: anything
outside `[a-z0-9-]` becomes `-`.

### Markdown

- **Headings.** `#` and `##` → `<h2>`; `###` → `<h3>`. The page's
  sole `<h1>` is the frontmatter title.
- **Fenced code.** ` ``` ` opens/closes a `<pre><code>`; the fence
  tag becomes `data-lang`.
- **Images on their own line.** `![alt](src)` → `<figure class='plate'>`.
  In a `kind: photo` post, the first such image becomes the cover
  plate (`fetchpriority='high'`, no `loading='lazy'`).
- **Inlines.** `[label](url)`, `` `code` ``, `*em*`, `**strong**`.
  Unterminated markers emit literal asterisks.
- **Paragraphs.** Any run of non-empty lines that doesn't match the
  above.

No lists, blockquotes, tables, HTML pass-through, reference links,
autolinks, setext headings, or hard breaks. Adding any of these means
editing `Logic.v`.

## Build

```bash
docker build -t crane-blog .
docker run --name crane-blog-run crane-blog
docker cp crane-blog-run:/home/opam/crane-blog/_site ./_site
docker rm crane-blog-run
```

Pinned: opam 2.5, OCaml 5.4, Rocq 9.0.0, `coq-itree`, `coq-paco`,
`coq-ext-lib`, `rocq-crane` (from upstream). A cold build takes ~5 min.

Iterative work:

```bash
docker run --rm -it -v "$PWD":/home/opam/crane-blog crane-blog bash
eval $(opam env) && dune build src/blog_generator.exe
./_build/default/src/blog_generator.exe
```

## Deploy

`.github/workflows/deploy.yml` runs on every push to `main`: builds
the image, runs the container, `docker cp`s `_site` out, uploads via
`actions/upload-pages-artifact`, publishes via `actions/deploy-pages`.

## Credits

[Crane](https://github.com/bloomberg/crane) is developed by Bloomberg;
this repository uses it as an opam dependency.
