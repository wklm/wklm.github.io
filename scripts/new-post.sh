#!/usr/bin/env bash
# new-post.sh -- scaffold a plaintext post under posts/<slug>.md
# Usage: scripts/new-post.sh <slug>
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <slug>" >&2
    exit 2
fi

slug="$1"
if ! [[ "$slug" =~ ^[a-z0-9-]+$ ]]; then
    echo "slug must match [a-z0-9-]+" >&2
    exit 2
fi

repo="$(git rev-parse --show-toplevel)"
path="$repo/posts/$slug.md"
if [[ -e "$path" ]]; then
    echo "$path already exists" >&2
    exit 1
fi
mkdir -p "$repo/posts"
cat > "$path" <<EOF
---
title: 
date: $(date +%Y-%m-%d)
slug: $slug
# recipients: alice@example.com, bob@example.com
---

EOF
echo "wrote $path"
