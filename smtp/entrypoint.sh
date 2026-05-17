#!/bin/sh
# Crane Blog SMTP container entrypoint.
# Ensures /repo is a fresh clone of $BLOG_REPO_URL, then execs the listener.
# No GPG keyring needed — encryption is handled by the encrypt_post OCaml binary.
set -eu

: "${BLOG_REPO_URL:?BLOG_REPO_URL is required}"
: "${BLOG_REPO_PATH:=/repo}"
: "${BLOG_BRANCH:=main}"
: "${KEYS_DIR:=/keys}"

# Validate keys directory has at least the author's public key
if [ ! -d "${KEYS_DIR}" ] || [ -z "$(ls -A "${KEYS_DIR}" 2>/dev/null)" ]; then
    echo "entrypoint: warning: keys directory ${KEYS_DIR} is empty or missing" >&2
fi

# Configure git identity from env (GIT_*_NAME / GIT_*_EMAIL also work but
# `git commit` ignores GIT_AUTHOR_NAME without a configured user.email).
git config --global user.name "${GIT_AUTHOR_NAME:-Crane Blog SMTP}"
git config --global user.email "${GIT_AUTHOR_EMAIL:-smtp@crane-blog.local}"
git config --global --add safe.directory "${BLOG_REPO_PATH}"
git config --global init.defaultBranch "${BLOG_BRANCH}"

if [ ! -d "${BLOG_REPO_PATH}/.git" ]; then
    echo "entrypoint: cloning ${BLOG_REPO_URL} into ${BLOG_REPO_PATH}"
    rm -rf "${BLOG_REPO_PATH:?}/"* "${BLOG_REPO_PATH:?}/".[!.]* 2>/dev/null || true
    git clone --branch "${BLOG_BRANCH}" "${BLOG_REPO_URL}" "${BLOG_REPO_PATH}"
else
    echo "entrypoint: existing checkout at ${BLOG_REPO_PATH}"
    git -C "${BLOG_REPO_PATH}" remote set-url origin "${BLOG_REPO_URL}"
    git -C "${BLOG_REPO_PATH}" fetch origin "${BLOG_BRANCH}"
    git -C "${BLOG_REPO_PATH}" checkout "${BLOG_BRANCH}"
    git -C "${BLOG_REPO_PATH}" reset --hard "origin/${BLOG_BRANCH}"
fi

exec python3 /app/listener.py
