# syntax=docker/dockerfile:1.7

# ──────────────────────────────────────────────────────────────────────
# JS compilation stage — builds decrypt.js from OCaml via js_of_ocaml
# and vendors OpenPGP.js.  Placed first so that [--target js] builds
# only this stage without touching the heavy Rocq/Crane toolchain.
FROM ocaml/opam:debian-13-ocaml-5.4 AS js

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libgmp-dev curl \
    && rm -rf /var/lib/apt/lists/*

USER opam
RUN opam update && opam install -y ocamlfind js_of_ocaml js_of_ocaml-ppx

# Download OpenPGP.js (vendored)
RUN curl -fsSL -o /tmp/openpgp.min.js \
    https://unpkg.com/openpgp@6.2.0/dist/openpgp.min.js

USER root
WORKDIR /home/opam/crane-blog
RUN chown opam:opam /home/opam/crane-blog
USER opam

COPY --chown=opam:opam static/ ./static/
RUN cp /tmp/openpgp.min.js static/openpgp.min.js

RUN eval $(opam env) && \
    cd /tmp && mkdir -p build && cd build && \
    echo '(lang dune 3.21)' > dune-project && \
    echo '(name crane_js)' >> dune-project && \
    echo '(executable (name decrypt) (modes js) (libraries js_of_ocaml) (preprocess (pps js_of_ocaml-ppx)))' > dune && \
    cp /home/opam/crane-blog/static/decrypt.ml . && \
    JSOO_TARGET_ENV=browser dune build decrypt.bc.js && \
    chmod u+w /home/opam/crane-blog/static/decrypt.js 2>/dev/null || true && \
    cp _build/default/decrypt.bc.js /home/opam/crane-blog/static/decrypt.js

USER root
CMD ["sh", "-c", "mkdir -p /out && cp /home/opam/crane-blog/static/decrypt.js /out/decrypt.js && cp /home/opam/crane-blog/static/openpgp.min.js /out/openpgp.min.js"]

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
    gnupg \
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
ARG CRANE_REF=main
RUN git clone --depth 1 --branch "$CRANE_REF" https://github.com/bloomberg/crane.git rocq-crane-src \
    && cd rocq-crane-src \
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

# Build: compile Rocq -> extract C++ -> compile binary.
RUN eval $(opam env) && dune build src/blog_generator.exe

# ──────────────────────────────────────────────────────────────────────
# Runtime image: no Rocq, no opam switch, no source tree, no posts.
FROM debian:13-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /site
COPY --from=builder /home/opam/crane-blog/_build/default/src/blog_generator.exe /usr/local/bin/blog_generator

# posts-encrypted/ and _site/ are mounted at runtime.  Clean only the
# contents of _site so the mount point itself survives.
CMD ["sh", "-c", "mkdir -p posts-encrypted _site && (rm -rf _site/* _site/.[!.]* _site/..?* 2>/dev/null || true) && blog_generator"]
