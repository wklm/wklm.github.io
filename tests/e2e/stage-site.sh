#!/usr/bin/env bash
# stage-site.sh -- stage a servable _site for the Facet A WASM e2e gate.
#
# 1. Extract the four WASM artifacts (crane_{decrypt,enroll}.{mjs,wasm}) from
#    the wasm image into static/ (so the generator copies them to _site/static/).
# 2. Build the runtime generator image (cached after the first run) and render
#    _site from posts-encrypted/ + static/, exactly as the deploy workflow and
#    scripts/test-roundtrip.sh do.
#
# Idempotent: safe to re-run.  Used by the Playwright global-setup AND by CI.
#
# Env overrides:
#   CRANE_BLOG_WASM_IMAGE   image holding /wasm/crane_*.{mjs,wasm}  (default crane-blog:wasm-merged)
#   CRANE_BLOG_GEN_IMAGE    runtime generator image tag             (default crane-blog-gen)
#   CRANE_BLOG_BUILD_GEN    1 => (re)build the generator image      (default 1)
set -euo pipefail

repo="$(git rev-parse --show-toplevel)"
cd "$repo"

wasm_image="${CRANE_BLOG_WASM_IMAGE:-crane-blog:wasm-merged}"
gen_image="${CRANE_BLOG_GEN_IMAGE:-crane-blog-gen}"
build_gen="${CRANE_BLOG_BUILD_GEN:-1}"

if ! command -v docker >/dev/null 2>&1; then
  echo "FAIL: docker required to stage the site (WASM artifacts + generator)" >&2
  exit 1
fi

# ---- 1. Extract the four WASM artifacts into static/ ----------------------
if ! docker image inspect "$wasm_image" >/dev/null 2>&1; then
  echo "FAIL: wasm image '$wasm_image' not found." >&2
  echo "Build it:  docker build --target wasm -t $wasm_image ." >&2
  exit 1
fi

echo "staging: extracting WASM artifacts from $wasm_image ..."
cid="$(docker create "$wasm_image")"
trap 'docker rm "$cid" >/dev/null 2>&1 || true' EXIT
for f in crane_decrypt.mjs crane_decrypt.wasm crane_enroll.mjs crane_enroll.wasm; do
  docker cp "$cid:/wasm/$f" "static/$f"
  test -s "static/$f" || { echo "FAIL: static/$f empty after extract" >&2; exit 1; }
done
docker rm "$cid" >/dev/null 2>&1 || true
trap - EXIT
echo "staging: static/crane_{decrypt,enroll}.{mjs,wasm} present."

# ---- 2. Build the generator image + render _site --------------------------
if [[ "$build_gen" == "1" ]]; then
  echo "staging: building runtime generator image ($gen_image) ..."
  docker build --target runtime -t "$gen_image" . >/dev/null
elif ! docker image inspect "$gen_image" >/dev/null 2>&1; then
  echo "FAIL: generator image '$gen_image' not found and CRANE_BLOG_BUILD_GEN=0." >&2
  exit 1
fi

echo "staging: rendering _site ..."
rm -rf _site
mkdir -p _site
# DinD-safe: the self-hosted runner mounts only docker.sock, so -v bind mounts
# resolve against the HOST daemon and $PWD/... is an empty dir.  Use docker cp
# instead (works identically on a plain host with a local daemon).
cid="$(docker create "$gen_image")"
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
docker cp posts-encrypted "$cid":/site/posts-encrypted
docker cp static "$cid":/site/static
[ -f keys/author-signing.pub ] && docker cp keys "$cid":/site/keys || true
docker start -a "$cid"
# Trailing /. copies CONTENTS into the existing _site dir
# (a bare path would nest as _site/_site).
docker cp "$cid":/site/_site/. ./_site/
docker rm -f "$cid" >/dev/null 2>&1 || true
trap - EXIT

# ---- 3. Sanity: artifacts + script tags landed in _site -------------------
for f in crane_decrypt.mjs crane_decrypt.wasm crane_enroll.mjs crane_enroll.wasm; do
  test -s "_site/static/$f" || { echo "FAIL: _site/static/$f missing" >&2; exit 1; }
done
grep -q "crane_enroll.mjs" _site/enroll/index.html \
  || { echo "FAIL: enroll page does not reference crane_enroll.mjs" >&2; exit 1; }
grep -rq "crane_decrypt.mjs" _site/index.html \
  || { echo "FAIL: inbox does not reference crane_decrypt.mjs" >&2; exit 1; }

echo "staging: OK — _site is servable with the WASM runtime."
