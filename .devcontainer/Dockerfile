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
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Add sudo support for opam user
RUN echo "opam ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/opam \
    && chmod 0440 /etc/sudoers.d/opam

# Install opam 2.5.0
RUN curl -fsSL https://opam.ocaml.org/install.sh -o /tmp/install-opam.sh && \
    echo /usr/bin | sh /tmp/install-opam.sh --version 2.5.0 && \
    rm /tmp/install-opam.sh

# Switch back to the opam user
USER opam

# Update opam repo (remove stale cache first to avoid cp -PRp overlay failure)
RUN rm -rf ~/.opam/repo/default && opam update
RUN opam install -y dune

# Install Coq 9.0.0 specifically to support rocq-crane requirements
RUN opam install -y coq=9.0.0

# Install OCaml development tools
RUN opam install -y ocaml-lsp-server ocamlformat utop

# Clone, remove tests, and install rocq-crane
RUN git clone https://github.com/bloomberg/crane.git rocq-crane-src \
    && cd rocq-crane-src \
    && rm -rf .git tests \
    && opam pin add -y .

# Make sure opam environment is available by default
RUN echo "eval \$(opam env)" >> ~/.bashrc
