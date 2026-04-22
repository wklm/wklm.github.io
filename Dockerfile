# Use a clean OCaml image to install specific Coq/Rocq version
FROM ocaml/opam:debian-13-ocaml-5.4

# Install system dependencies
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    clang \
    clang-format \
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

# Clone, remove tests, and install rocq-crane
RUN git clone https://github.com/bloomberg/crane.git rocq-crane-src \
    && cd rocq-crane-src \
    && rm -rf .git tests \
    && opam pin add -y .

# Set the working directory and ensure permissions
USER root
WORKDIR /home/opam/crane-blog
RUN chown opam:opam /home/opam/crane-blog
USER opam

# Copy the project files into the container
COPY --chown=opam:opam . .

# Build: compile Rocq -> extract C++ -> compile binary
RUN eval $(opam env) && dune build src/blog_generator.exe

# Run the generator on ./posts by default.  We clear any stale _site/
# that may have been copied in from the build context before running so
# the tree written by the extracted binary is the only output.
CMD ["sh", "-c", "eval $(opam env) && rm -rf _site && ./_build/default/src/blog_generator.exe"]
