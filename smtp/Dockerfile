# syntax=docker/dockerfile:1.7

# ──────────────────────────────────────────────────────────────────────
# Crane Blog SMTP listener (Facet C).
#
# The listener is now ROCQ -> Crane(C++23) -> native: src/SmtpServer.v
# extracted and compiled to smtp_server.exe in the shared crane-blog:builder
# image (which `dune build`s src/smtp_server.exe).  No Python / aiosmtpd /
# OCaml in the runtime — only the static binary plus git + openssh-client for
# the publish step.
#
# Build the builder image first (from the repo root):
#     docker build --target builder -t crane-blog:builder .
# then this image (context = ./smtp):
#     docker build -t crane-blog-smtp:latest ./smtp
# (compose.yml does exactly this via `build: ./smtp`.)
ARG BUILDER_IMAGE=crane-blog:builder
FROM ${BUILDER_IMAGE} AS builder

# ──────────────────────────────────────────────────────────────────────
# Runtime image: smtp_server.exe + git + openssh-client, no Rocq/Python/OCaml.
FROM debian:13-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       git openssh-client ca-certificates libssl3 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    # Single-tenant container: trust the checkout regardless of bind-mount
    # ownership (git's dubious-ownership guard otherwise blocks operations on a
    # host-owned volume).  System-level so it applies to every git invocation,
    # including the listener's procE subprocesses.
    && git config --system --add safe.directory '*'

WORKDIR /app
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# The Crane-extracted native listener.
COPY --from=builder /home/opam/crane-blog/_build/default/src/smtp_server.exe /usr/local/bin/smtp_server

ENV BLOG_REPO_PATH=/repo \
    BLOG_BRANCH=main \
    SMTP_HOST=0.0.0.0 \
    SMTP_PORT=2525

ENTRYPOINT ["/app/entrypoint.sh"]
