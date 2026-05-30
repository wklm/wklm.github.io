# syntax=docker/dockerfile:1.7

# ──────────────────────────────────────────────────────────────────────
# JS compilation stage — builds decrypt.js and enroll.js from OCaml via
# js_of_ocaml.  Placed first so that [--target js] builds only this
# stage without touching the heavy Rocq/Crane toolchain.
FROM ocaml/opam:debian-13-ocaml-5.4 AS js

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libgmp-dev curl \
    && rm -rf /var/lib/apt/lists/*

USER opam
RUN opam update && opam install -y ocamlfind js_of_ocaml js_of_ocaml-ppx

USER root
WORKDIR /home/opam/crane-blog
RUN chown opam:opam /home/opam/crane-blog
USER opam

COPY --chown=opam:opam static/ ./static/
COPY --chown=opam:opam dune-project ./
COPY --chown=opam:opam static/crane_bridge.js static/

RUN eval $(opam env) && \
    cd /tmp && mkdir -p build && cd build && \
    echo '(lang dune 3.21)' > dune-project && \
    echo '(name crane_js)' >> dune-project && \
    echo '(executables (names decrypt enroll) (modes js) (libraries js_of_ocaml) (preprocess (pps js_of_ocaml-ppx)))' > dune && \
    cp /home/opam/crane-blog/static/decrypt.ml . && \
    cp /home/opam/crane-blog/static/enroll.ml . && \
    JSOO_TARGET_ENV=browser dune build decrypt.bc.js && \
    JSOO_TARGET_ENV=browser dune build enroll.bc.js && \
    chmod u+w /home/opam/crane-blog/static/decrypt.js 2>/dev/null || true && \
    chmod u+w /home/opam/crane-blog/static/enroll.js 2>/dev/null || true && \
    cp _build/default/decrypt.bc.js /home/opam/crane-blog/static/decrypt.js && \
    cp _build/default/enroll.bc.js /home/opam/crane-blog/static/enroll.js

USER root
CMD ["sh", "-c", "mkdir -p /out && cp /home/opam/crane-blog/static/decrypt.js /home/opam/crane-blog/static/enroll.js /home/opam/crane-blog/static/crane_bridge.js /out/"]

# ──────────────────────────────────────────────────────────────────────
# Build the Rocq/Crane generator once in a toolchain image.
FROM ocaml/opam:debian-13-ocaml-5.4 AS builder

# Install system dependencies
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    clang \
    clang-format \
    libgmp-dev \
    libssl-dev \
    libstdc++-14-dev \
    linux-libc-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install opam 2.5.0
RUN curl -fsSL https://opam.ocaml.org/install.sh -o /tmp/install-opam.sh && \
    echo /usr/bin | sh /tmp/install-opam.sh --version 2.5.0 && \
    rm /tmp/install-opam.sh

# Switch back to the opam user
USER opam

# Update opam repo (remove stale cache first to avoid cp -PRp overlay failure)
RUN rm -rf ~/.opam/repo/default && opam update
RUN opam repo add coq-released https://coq.inria.fr/opam/released
RUN opam install -y dune

# Install Coq 9.0.0 specifically to support rocq-crane requirements
RUN opam install -y coq=9.0.0 coq-itree coq-paco coq-ext-lib

# Clone, remove tests, and install rocq-crane.
# Pinned to the exact upstream commit (bloomberg/crane main HEAD as of the
# Crane upgrade) for reproducibility; `main` is a moving target. Verified:
#   git ls-remote https://github.com/bloomberg/crane.git refs/heads/main
#   -> 39720e232aa1fb1444426ce7a046262aa0a0b80c  (matches crane-blog:builder)
# A pinned SHA can't be used with `clone --branch`, so init+fetch the commit.
ARG CRANE_REF=39720e232aa1fb1444426ce7a046262aa0a0b80c
RUN git init rocq-crane-src \
    && cd rocq-crane-src \
    && git remote add origin https://github.com/bloomberg/crane.git \
    && git fetch --depth 1 origin "$CRANE_REF" \
    && git checkout FETCH_HEAD \
    && rm -rf .git tests \
    && opam pin add -y .

# Set the working directory and ensure permissions
USER root
WORKDIR /home/opam/crane-blog
RUN chown opam:opam /home/opam/crane-blog
USER opam

# Copy only generator sources before the expensive build. New posts should not
# invalidate the Rocq/Crane compile layer.
COPY --chown=opam:opam dune-project ./
COPY --chown=opam:opam src/ ./src/
COPY --chown=opam:opam tools/ ./tools/

# Build: compile Rocq -> extract C++ -> compile binaries: generator + CLI tools
# + Facet-C SMTP listener (smtp/ image consumes smtp_server.exe) + Facet-A
# browser Crane extraction & native stub-check (emits FormalBlog/crane_{decrypt,
# enroll}.{h,cpp} for the wasm stage; proves the extracted C++ is std::any-free).
RUN eval $(opam env) && \
    dune build src/blog_generator.exe tools/encrypt_post.exe tools/decrypt_post.exe \
               src/smtp_server.exe src/crane_decrypt.check src/crane_enroll.check

# ──────────────────────────────────────────────────────────────────────
# Facet A — WASM stage.  Consumes the Crane-extracted browser C++ from the
# `builder` stage and links it to crane_decrypt.{mjs,wasm} / crane_enroll.{mjs,wasm}
# with em++.  Pinned emsdk 3.1.61 (matches the lost/shipped gh-pages build).
#
# Flags rationale (crane-extraction-gotchas):
#   -std=c++2b            Crane emits C++23
#   -O0                   skip Emscripten's acorn JS minifier (a JS regex literal
#                         in an EM_ASM throws "Unterminated regular expression"
#                         at higher -O; we also keep all EM_ASM regex-free)
#   -fbracket-depth=1024  deeply-nested extracted expressions
#   -lembind              link Embind (harmless; emval_* symbols resolve even
#                         though we use raw EM_ASM, not emscripten::val)
#   -sASYNCIFY            suspend the WASM stack across crypto.subtle / IndexedDB
#                         / WebAuthn promises (Asyncify.handleAsync in the shim)
#   -sMODULARIZE=1 -sEXPORT_ES6=1   emit an ES6 default-export factory the page
#                         imports as a module
#   -sINVOKE_RUN=0 + callMain   the page calls m.callMain([]) after the factory
#                         resolves (and again on each Decrypt/Enroll click via
#                         the keepalive re-entry)
#   -DCRANE_BROWSER_BUILD render crypto_helpers.h inert (browser_helpers.h owns
#                         the nine primitives; avoids OpenSSL + double-definition)
FROM emscripten/emsdk:3.1.61 AS wasm

WORKDIR /wasm

# The Crane-extracted browser sources + the Emscripten FFI shim headers.
COPY --from=builder /home/opam/crane-blog/_build/default/FormalBlog/crane_decrypt.cpp ./
COPY --from=builder /home/opam/crane-blog/_build/default/FormalBlog/crane_decrypt.h ./
COPY --from=builder /home/opam/crane-blog/_build/default/FormalBlog/crane_enroll.cpp ./
COPY --from=builder /home/opam/crane-blog/_build/default/FormalBlog/crane_enroll.h ./
COPY src/browser_helpers.h ./
COPY src/browser_helpers_stub.h ./
COPY src/crypto_helpers.h ./

# main shims: the extracted unit exposes run(); the page drives callMain().
RUN printf '#include "crane_decrypt.h"\nint main(){ run(); return 0; }\n' > decrypt_main.cpp && \
    printf '#include "crane_enroll.h"\nint main(){ run(); return 0; }\n' > enroll_main.cpp

# Link both modules.  EXPORTED_FUNCTIONS keeps _malloc/_free (the EM_ASM bodies
# allocate the length-prefixed return buffers); EXPORTED_RUNTIME_METHODS exposes
# callMain + UTF8ToString/HEAPU8 used by the shim.
RUN em++ -std=c++2b -O0 -fbracket-depth=1024 -DCRANE_BROWSER_BUILD -I . \
      crane_decrypt.cpp decrypt_main.cpp \
      -lembind -sASYNCIFY -sMODULARIZE=1 -sEXPORT_ES6=1 -sINVOKE_RUN=0 \
      -sALLOW_MEMORY_GROWTH=1 -sEXPORTED_FUNCTIONS=_main,_malloc,_free \
      -sEXPORTED_RUNTIME_METHODS=callMain,UTF8ToString,stringToUTF8,HEAPU8,lengthBytesUTF8 \
      -o crane_decrypt.mjs && \
    em++ -std=c++2b -O0 -fbracket-depth=1024 -DCRANE_BROWSER_BUILD -I . \
      crane_enroll.cpp enroll_main.cpp \
      -lembind -sASYNCIFY -sMODULARIZE=1 -sEXPORT_ES6=1 -sINVOKE_RUN=0 \
      -sALLOW_MEMORY_GROWTH=1 -sEXPORTED_FUNCTIONS=_main,_malloc,_free \
      -sEXPORTED_RUNTIME_METHODS=callMain,UTF8ToString,stringToUTF8,HEAPU8,lengthBytesUTF8 \
      -o crane_enroll.mjs

# Sanity: all four artifacts exist (the Facet-A gate).
RUN test -s crane_decrypt.mjs && test -s crane_decrypt.wasm && \
    test -s crane_enroll.mjs && test -s crane_enroll.wasm && \
    ls -la crane_decrypt.mjs crane_decrypt.wasm crane_enroll.mjs crane_enroll.wasm

CMD ["bash", "-c", "mkdir -p /out && cp /wasm/crane_decrypt.mjs /wasm/crane_decrypt.wasm /wasm/crane_enroll.mjs /wasm/crane_enroll.wasm /out/"]

# ──────────────────────────────────────────────────────────────────────
# Runtime image: blog_generator + encrypt_post + static JS, no Rocq.
FROM debian:13-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /site
COPY --from=builder /home/opam/crane-blog/_build/default/src/blog_generator.exe /usr/local/bin/blog_generator
COPY --from=builder /home/opam/crane-blog/_build/default/tools/encrypt_post.exe /usr/local/bin/encrypt_post
COPY --from=builder /home/opam/crane-blog/_build/default/tools/decrypt_post.exe /usr/local/bin/decrypt_post

# posts-encrypted/ and _site/ are mounted at runtime.  Clean only the
# contents of _site so the mount point itself survives.
CMD ["sh", "-c", "mkdir -p posts-encrypted _site && (rm -rf _site/* _site/.[!.]* _site/..?* 2>/dev/null || true) && blog_generator"]
