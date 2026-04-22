(lang dune 3.21)
(name crane_blog)
(version 0.1)

(warnings (deprecated_coq_lang disabled))

(using coq 0.8)

(package
 (name crane_blog)
 (synopsis "A verified static site generator using Crane")
 (description "A verified static site generator using Crane Rocq plugin.")
 (depends
  (dune (>= 3.21))
  (coq (>= 9.0))
  (rocq-crane (>= 0.1))))
