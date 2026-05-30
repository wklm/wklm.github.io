#!/bin/sh
# Crane Blog SMTP container entrypoint (Facet C).
# Ensures $BLOG_REPO_PATH is a checkout of $BLOG_REPO_URL, then execs the
# Crane-extracted native listener (smtp_server.exe) from inside that checkout.
#
# Encryption is in-process (HPKE, src/SmtpServer.v) — no encrypt_post binary,
# no GPG keyring, no Python.  The per-DATA `git fetch` + R4-guarded
# `git reset --hard origin/$BLOG_BRANCH` lives inside the listener; the
# listener only runs that reset when its CWD basename matches the repo dir, so
# we cd into the checkout before exec.
set -eu

: "${BLOG_REPO_URL:?BLOG_REPO_URL is required}"
: "${BLOG_REPO_PATH:=/repo}"
: "${BLOG_BRANCH:=main}"
: "${KEYS_DIR:=/keys}"

# Validate keys directory has at least the author's public key.
if [ ! -d "${KEYS_DIR}" ] || [ -z "$(ls -A "${KEYS_DIR}" 2>/dev/null)" ]; then
    echo "entrypoint: warning: keys directory ${KEYS_DIR} is empty or missing" >&2
fi

# Configure git identity from env.
git config --global user.name "${GIT_AUTHOR_NAME:-Crane Blog SMTP}"
git config --global user.email "${GIT_AUTHOR_EMAIL:-smtp@crane-blog.local}"
git config --global --add safe.directory "${BLOG_REPO_PATH}"
git config --global init.defaultBranch "${BLOG_BRANCH}"

if [ ! -d "${BLOG_REPO_PATH}/.git" ]; then
    echo "entrypoint: cloning ${BLOG_REPO_URL} into ${BLOG_REPO_PATH}"
    git clone --branch "${BLOG_BRANCH}" "${BLOG_REPO_URL}" "${BLOG_REPO_PATH}"
else
    echo "entrypoint: existing checkout at ${BLOG_REPO_PATH}"
    git -C "${BLOG_REPO_PATH}" remote set-url origin "${BLOG_REPO_URL}"
    git -C "${BLOG_REPO_PATH}" fetch origin "${BLOG_BRANCH}"
    git -C "${BLOG_REPO_PATH}" checkout "${BLOG_BRANCH}"
fi

# Copy the author public key(s) into the checkout so the listener can read
# keys/<kid>.pub relative to its CWD (the publish pipeline reads keys/ from the
# repo root, exactly as encrypt_post does).
if [ -d "${KEYS_DIR}" ]; then
    mkdir -p "${BLOG_REPO_PATH}/keys"
    cp -f "${KEYS_DIR}"/*.pub "${BLOG_REPO_PATH}/keys/" 2>/dev/null || true
fi

# Run the listener from inside the checkout (CWD basename == repo dir name, so
# the listener's R4 guard permits its `git reset --hard`).
cd "${BLOG_REPO_PATH}"
exec smtp_server
