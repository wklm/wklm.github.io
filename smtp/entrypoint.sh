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

# Auto-resolve the configured default readers (BLOG_PUBLIC_KEYS: kid1,kid2)
# from the public key directory (Cloudflare Worker + KV), so a reader who
# enrolled on the site is automatically known to the listener — the author
# never adds a reader key file by hand.  Unknown kids only warn: the listener
# still works for posts addressed to the author alone.
KEYDIR_URL="${KEYDIR_URL:-https://crane-blog-keydir.wojtekkulma.workers.dev}"
if [ -n "${BLOG_PUBLIC_KEYS:-}" ] && command -v curl >/dev/null 2>&1; then
    for kid in $(printf '%s' "${BLOG_PUBLIC_KEYS}" | tr ',' ' '); do
        case "$kid" in
            [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f])
                if [ -f "${BLOG_REPO_PATH}/keys/${kid}.pub" ]; then continue; fi
                if out=$(curl -fsS --max-time 10 "${KEYDIR_URL}/keys/${kid}" 2>/dev/null); then
                    if [ "${#out}" -eq 130 ]; then
                        printf '%s' "$out" > "${BLOG_REPO_PATH}/keys/${kid}.pub"
                        echo "entrypoint: resolved reader key ${kid} from key directory"
                    else
                        echo "entrypoint: warning: unexpected directory response for ${kid}" >&2
                    fi
                else
                    echo "entrypoint: warning: reader key ${kid} not in key directory" >&2
                fi
                ;;
        esac
    done
fi

# Run the listener from inside the checkout (CWD basename == repo dir name, so
# the listener's R4 guard permits its `git reset --hard`).
cd "${BLOG_REPO_PATH}"
exec smtp_server
