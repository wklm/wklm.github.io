# syntax=docker/dockerfile:1.7

# ──────────────────────────────────────────────────────────────────────
# OCaml tools stage — builds encrypt_post (HPKE-based encryption tool)
FROM ocaml/opam:debian-13-ocaml-5.4 AS tools

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libgmp-dev \
    && rm -rf /var/lib/apt/lists/*

USER opam
RUN opam update && opam install -y dune mirage-crypto mirage-crypto-ec \
    mirage-crypto-rng digestif base64

WORKDIR /home/opam/crane-blog
RUN mkdir -p tools src-static
COPY --chown=opam:opam tools/encrypt_post.ml tools/io_helpers.ml tools/
COPY --chown=opam:opam src/crane_crypto.ml src-static/

RUN eval $(opam env) && \
    cp src-static/crane_crypto.ml tools/ && \
    echo '(lang dune 3.21)' > dune-project && \
    echo '(name crane_tools)' >> dune-project && \
    echo '(executables (names encrypt_post) (libraries unix mirage-crypto mirage-crypto-ec mirage-crypto-rng digestif base64))' > dune && \
    echo '(rule (copy ../tools/io_helpers.ml io_helpers.ml))' >> dune && \
    dune build encrypt_post.exe

# ──────────────────────────────────────────────────────────────────────
# Runtime image: Python + encrypt_post binary, no gpg.
FROM python:3.12-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends git openssh-client ca-certificates ocaml-base libgmp10 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir aiosmtpd==1.4.6

WORKDIR /app
COPY listener.py entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

COPY --from=tools /home/opam/crane-blog/_build/default/encrypt_post.exe /usr/local/bin/encrypt_post

ENV PYTHONUNBUFFERED=1 \
    BLOG_REPO_PATH=/repo \
    BLOG_BRANCH=main \
    SMTP_HOST=0.0.0.0 \
    SMTP_PORT=2525 \
    ENCRYPT_POST_BIN=/usr/local/bin/encrypt_post

ENTRYPOINT ["/app/entrypoint.sh"]
