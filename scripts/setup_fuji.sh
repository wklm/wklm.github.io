#!/bin/bash
# Idempotent fuji deploy. Runs in two modes:
#   - on fuji directly:  ./scripts/setup_fuji.sh
#   - from your laptop:  ssh fuji bash -s < scripts/setup_fuji.sh
# Stops the legacy host-installed python listener (if present) and brings the
# Docker compose stack up. Nothing else on fuji is modified.
set -euo pipefail

REPO_DIR="${REPO_DIR:-/home/wojtek/crane_blog}"
KNOWN_HOSTS="/home/wojtek/.ssh/known_hosts"

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
    git clone git@github.com:wklm/wklm.github.io.git "${REPO_DIR}"
else
    echo "==> updating ${REPO_DIR}"
    git -C "${REPO_DIR}" fetch origin main
    git -C "${REPO_DIR}" reset --hard origin/main
fi

# 3. Pin github.com host key so the container can push without prompting.
if ! grep -q '^github.com ' "${KNOWN_HOSTS}" 2>/dev/null; then
    echo "==> recording github.com host key in ${KNOWN_HOSTS}"
    ssh-keyscan -t rsa,ecdsa,ed25519 github.com >> "${KNOWN_HOSTS}"
    chmod 600 "${KNOWN_HOSTS}"
fi

# 4. Bring the compose stack up.
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
echo "the public key in smtp/author.pub, and commits only posts-encrypted/*.eml."
