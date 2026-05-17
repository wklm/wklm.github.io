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
   (js_of_ocaml (>= 5.0))
   (rocq-crane (>= 0.1))
   (mirage-crypto (>= 1.0))
   (mirage-crypto-ec (>= 1.0))
   (mirage-crypto-rng (>= 1.0))
   (digestif (>= 1.2))
   (base64 (>= 3.5))))
