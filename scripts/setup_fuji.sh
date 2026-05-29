#!/bin/bash
# Idempotent fuji deploy. Runs in two modes:
#   - on fuji directly:  ./scripts/setup_fuji.sh
#   - from your laptop:  ssh fuji bash -s < scripts/setup_fuji.sh
# Stops the legacy host-installed python listener (if present) and brings the
# Docker compose stack up. Nothing else on fuji is modified.
set -euo pipefail

REPO_DIR="${REPO_DIR:-/home/wojtek/crane_blog}"
KNOWN_HOSTS="/home/wojtek/.ssh/known_hosts"
KEYS_DIR="/home/wojtek/crane_blog_keys"

# 1. Decommission the legacy systemd unit (host-installed python listener).
if systemctl list-unit-files | grep -q '^crane_blog_smtp\.service'; then
    echo "==> stopping and disabling crane_blog_smtp.service"
    sudo systemctl disable --now crane_blog_smtp.service || true
    sudo rm -f /etc/systemd/system/crane_blog_smtp.service
    sudo systemctl daemon-reload
fi

# 2. Ensure the repo checkout exists and is current.
if [ ! -d "${REPO_DIR}/.git" ]; then
    echo "==> cloning fresh checkout into ${REPO_DIR}"
    rm -rf "${REPO_DIR}"
    git clone ssh://git@fuji.tail2acfcc.ts.net:222/wklm/wklm.github.io.git "${REPO_DIR}"
else
    echo "==> updating ${REPO_DIR}"
    git -C "${REPO_DIR}" fetch origin main
    git -C "${REPO_DIR}" reset --hard origin/main
fi

# 3. Pin the Forgejo SSH host key so the container can push without prompting.
if ! grep -q '^\[fuji.tail2acfcc.ts.net\]:222 ' "${KNOWN_HOSTS}" 2>/dev/null; then
    echo "==> recording Forgejo (fuji.tail2acfcc.ts.net:222) host key in ${KNOWN_HOSTS}"
    ssh-keyscan -p 222 -t rsa,ecdsa,ed25519 fuji.tail2acfcc.ts.net >> "${KNOWN_HOSTS}"
    chmod 600 "${KNOWN_HOSTS}"
fi

# 4. Bring the compose stack up.
if [ ! -d "${KEYS_DIR}" ] || [ -z "$(ls -A "${KEYS_DIR}" 2>/dev/null)" ]; then
    echo "Warning: keys directory ${KEYS_DIR} is empty or missing" >&2
    echo "Place reader public key files (*.pub) there before deploying" >&2
fi

cd "${REPO_DIR}"
echo "==> docker compose up -d --build"
docker compose up -d --build

echo
echo "==> status"
docker compose ps
echo
echo "==> recent logs"
docker compose logs --tail=20 smtp || true
echo
echo "Done. Mail.app settings:"
echo "  Server: 100.99.77.105"
echo "  Port:   2525"
echo "  TLS:    off"
echo "  Auth:   none"
echo ""
echo "The container accepts normal plaintext email, encrypts it in memory with"
echo "the mounted reader public keys, and commits only posts-encrypted/*.eml."
