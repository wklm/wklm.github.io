# syntax=docker/dockerfile:1.7

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

# Runtime image: no Rocq, no opam switch, no source tree, no posts.
FROM debian:13-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /site
COPY --from=builder /home/opam/crane-blog/_build/default/src/blog_generator.exe /usr/local/bin/blog_generator

# posts-encrypted/ and _site/ are mounted at runtime.  Clean only the
# contents of _site so the mount point itself survives.
CMD ["sh", "-c", "mkdir -p posts-encrypted _site && (rm -rf _site/* _site/.[!.]* _site/..?* 2>/dev/null || true) && blog_generator"]
