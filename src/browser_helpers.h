#pragma once

// browser_helpers.h -- Emscripten/WebCrypto/WebAuthn/IndexedDB/DOM capability
// shim for the browser-side Crane extraction (FFI boundary C2/C3).
//
// This is the *browser* realization of:
//   - the nine CryptoSpec.v cryptographic primitives (BrowserCrypto.v), backed
//     by crypto.subtle / crypto.getRandomValues;
//   - the brE effect algebra (BrowserEffect.v): DOM read/write, sessionStorage,
//     IndexedDB, WebAuthn, RandomBytes.
//
// It is the faithful Emscripten parallel of src/crypto_helpers.h (the native
// OpenSSL shim).  Like that header it contains NO domain logic: no MIME, no
// HPKE protocol framing, no policy — only platform delegation + byte
// marshalling.  All protocol logic (HPKE wrap/unwrap, the KDF, MIME parsing,
// page flow) lives in ROCQ (CryptoSpec.v / MimeBuild.v / InnerMime.v /
// DecryptApp.v / EnrollApp.v).
//
// CRITICAL (crane-extraction-gotchas): this header is compiled ONLY by em++ for
// the WASM build.  It must NEVER include crypto_helpers.h or any OpenSSL header
// (OpenSSL is absent under Emscripten); it includes only Emscripten + libc++.
//
// Async ops (crypto.subtle, IndexedDB, WebAuthn) suspend the WASM stack via
// Asyncify.handleAsync so the pure-ROCQ caller sees an ordinary synchronous
// return.  The em++ link therefore needs -sASYNCIFY (and -lembind is harmless;
// we use raw EM_ASM, not emscripten::val, so no _emval_* symbols are emitted).
//
// Marshalling convention (matches the shipped gh-pages build): every JS body
// that returns variable-length bytes _malloc's a buffer whose first 4 bytes are
// the little-endian length, followed by the payload; the C++ wrapper copies it
// into a std::string and frees it.  Fixed-length (32-byte) returns skip the
// length prefix.  No JS regex literals appear anywhere (acorn throws
// "Unterminated regular expression" even at -O0 in some emsdk builds, and the
// shipped build's one regex was visibly mangled) — whitespace stripping is done
// in ROCQ (MimeBuild.strip_ws) before any base64 decode reaches JS.

// Outside Emscripten (the dune native compile-check that catches std::any in
// the fast crane-blog:builder loop), fall back to the signature-identical stub:
// the extracted crane_decrypt.cpp / crane_enroll.cpp #include this header
// unconditionally, and plain clang++ has no <emscripten.h>.  Under em++,
// __EMSCRIPTEN__ is defined and the real EM_ASM bodies below are used.
#ifndef __EMSCRIPTEN__
#include "browser_helpers_stub.h"
#else

#include <string>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <variant>
#include <emscripten.h>

namespace crane_browser_detail {

// Read a length-prefixed buffer at [p] (4-byte LE length + payload) into a
// std::string, then free(p).  p==0 yields "".
inline std::string take_lp(char* p) {
    if (p == nullptr) return std::string();
    unsigned char* u = reinterpret_cast<unsigned char*>(p);
    std::uint32_t len = static_cast<std::uint32_t>(u[0])
                      | (static_cast<std::uint32_t>(u[1]) << 8)
                      | (static_cast<std::uint32_t>(u[2]) << 16)
                      | (static_cast<std::uint32_t>(u[3]) << 24);
    std::string s(reinterpret_cast<char*>(p + 4), len);
    std::free(p);
    return s;
}

// Read a fixed 32-byte buffer at [p] into a std::string, then free(p).
inline std::string take32(char* p) {
    if (p == nullptr) return std::string();
    std::string s(p, 32);
    std::free(p);
    return s;
}

}  // namespace crane_browser_detail

// ===========================================================================
// Cryptographic primitives (CryptoSpec.v axioms) via crypto.subtle / RNG.
// ===========================================================================

// random_bytes(n): crypto.getRandomValues into a length-prefixed buffer.
// Synchronous in the browser (no Asyncify needed).
inline std::string random_bytes(int n) {
    if (n <= 0) return std::string();
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        var n = $0;
        var buf = new Uint8Array(n);
        crypto.getRandomValues(buf);
        var ptr = _malloc(4 + n);
        HEAPU8[ptr] = (n >> 0) & 0xff;
        HEAPU8[ptr + 1] = (n >> 8) & 0xff;
        HEAPU8[ptr + 2] = (n >> 16) & 0xff;
        HEAPU8[ptr + 3] = (n >> 24) & 0xff;
        HEAPU8.set(buf, ptr + 4);
        return ptr;
    }, n));
    return crane_browser_detail::take_lp(p);
}

// sha256(bytes): crypto.subtle.digest -> 32 raw bytes.
inline std::string sha256(const std::string& in) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            var buf = HEAPU8.slice($0, $0 + $1);
            var hash = await crypto.subtle.digest('SHA-256', buf);
            var result = new Uint8Array(hash);
            var ptr = _malloc(32);
            HEAPU8.set(result, ptr);
            return ptr;
        });
    }, in.data(), (int)in.size()));
    return crane_browser_detail::take32(p);
}

// ecdh_p256_generate(_): WebCrypto generateKey, export raw public + JWK private.
// Returns a std::pair(uncompressed_pub_65, priv_jwk_json_string) — Crane maps
// Coq prod to std::pair directly, so no adapter IIFE is needed.  The ROCQ side
// (BrowserCrypto) treats the private component opaquely (it is a JWK string,
// not a raw scalar — WebCrypto cannot import a bare 32-byte EC scalar) and only
// ever feeds it back to ecdh_p256_agree.
inline std::pair<std::string, std::string> ecdh_p256_generate(std::monostate) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            var kp = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
            var rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
            var jwkPriv = await crypto.subtle.exportKey('jwk', kp.privateKey);
            var jwkStr = JSON.stringify(jwkPriv);
            var enc = new TextEncoder();
            var jwkBytes = enc.encode(jwkStr);
            var total = 4 + rawPub.length + 4 + jwkBytes.length;
            var ptr = _malloc(total);
            var off = 0;
            HEAPU8[ptr + off++] = (rawPub.length >> 0) & 0xff;
            HEAPU8[ptr + off++] = (rawPub.length >> 8) & 0xff;
            HEAPU8[ptr + off++] = (rawPub.length >> 16) & 0xff;
            HEAPU8[ptr + off++] = (rawPub.length >> 24) & 0xff;
            HEAPU8.set(rawPub, ptr + off); off += rawPub.length;
            HEAPU8[ptr + off++] = (jwkBytes.length >> 0) & 0xff;
            HEAPU8[ptr + off++] = (jwkBytes.length >> 8) & 0xff;
            HEAPU8[ptr + off++] = (jwkBytes.length >> 16) & 0xff;
            HEAPU8[ptr + off++] = (jwkBytes.length >> 24) & 0xff;
            HEAPU8.set(jwkBytes, ptr + off);
            return ptr;
        });
    }, 0));
    if (p == nullptr) return { std::string(), std::string() };
    unsigned char* u = reinterpret_cast<unsigned char*>(p);
    auto rd = [&](std::size_t at) -> std::uint32_t {
        return (std::uint32_t)u[at] | ((std::uint32_t)u[at+1] << 8)
             | ((std::uint32_t)u[at+2] << 16) | ((std::uint32_t)u[at+3] << 24);
    };
    std::uint32_t l0 = rd(0);
    std::string pub(reinterpret_cast<char*>(p + 4), l0);
    std::uint32_t l1 = rd(4 + l0);
    std::string priv(reinterpret_cast<char*>(p + 4 + l0 + 4), l1);
    std::free(p);
    return { pub, priv };
}

// ecdh_p256_public_key(privJwk): re-export the public point from the private
// JWK as 65-byte uncompressed.  (Used by neither flow today but declared by
// CryptoSpec; realized for completeness.)
inline std::string ecdh_p256_public_key(const std::string& priv_jwk) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            try {
                var jwk = JSON.parse(UTF8ToString($0));
                delete jwk.key_ops; delete jwk.use; delete jwk.alg; delete jwk.ext;
                var priv = await crypto.subtle.importKey('jwk', jwk,
                    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                var pub = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
                var k = await crypto.subtle.importKey('jwk', pub,
                    { name: 'ECDH', namedCurve: 'P-256' }, true, []);
                var raw = new Uint8Array(await crypto.subtle.exportKey('raw', k));
                var ptr = _malloc(4 + raw.length);
                HEAPU8[ptr] = (raw.length >> 0) & 0xff;
                HEAPU8[ptr+1] = (raw.length >> 8) & 0xff;
                HEAPU8[ptr+2] = (raw.length >> 16) & 0xff;
                HEAPU8[ptr+3] = (raw.length >> 24) & 0xff;
                HEAPU8.set(raw, ptr + 4);
                return ptr;
            } catch (e) {
                var ptr = _malloc(4); HEAPU8[ptr]=0; HEAPU8[ptr+1]=0;
                HEAPU8[ptr+2]=0; HEAPU8[ptr+3]=0; return ptr;
            }
        });
    }, priv_jwk.data()));
    return crane_browser_detail::take_lp(p);
}

// ecdh_p256_agree(privJwk, pubRaw): import the private JWK and the encapsulated
// uncompressed public key (65 bytes), deriveBits(256) -> 32-byte shared secret.
// "" on any failure.  Mirrors the ECDH portion of the shipped _hpkeDecrypt.
inline std::string ecdh_p256_agree(const std::string& priv_jwk,
                                   const std::string& pub_raw) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            try {
                var privJwk = JSON.parse(UTF8ToString($0));
                var pubBytes = HEAPU8.slice($1, $1 + $2);
                // Build a JWK for the uncompressed (0x04||x||y) encapsulated key.
                function b64url(u8) {
                    var s = '';
                    for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
                    return btoa(s).split('+').join('-').split('/').join('_').split('=').join('');
                }
                var x = pubBytes.slice(1, 33);
                var y = pubBytes.slice(33, 65);
                var pubJwk = { kty: 'EC', crv: 'P-256', x: b64url(x), y: b64url(y) };
                var encPub = await crypto.subtle.importKey('jwk', pubJwk,
                    { name: 'ECDH', namedCurve: 'P-256' }, false, []);
                delete privJwk.key_ops; delete privJwk.use; delete privJwk.alg; delete privJwk.ext;
                var privKey = await crypto.subtle.importKey('jwk', privJwk,
                    { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
                var bits = await crypto.subtle.deriveBits(
                    { name: 'ECDH', public: encPub }, privKey, 256);
                var shared = new Uint8Array(bits);
                var ptr = _malloc(32);
                HEAPU8.set(shared, ptr);
                return ptr;
            } catch (e) {
                return 0;
            }
        });
    }, priv_jwk.data(), pub_raw.data(), (int)pub_raw.size()));
    if (p == nullptr) return std::string();
    return crane_browser_detail::take32(p);
}

// aes_256_gcm_encrypt(key, nonce, pt, aad) -> std::pair(ciphertext, tag).
// crypto.subtle returns ciphertext||tag concatenated; we split off the last 16
// bytes as the tag to match the native crypto_helpers.h contract (and Crane's
// prod -> std::pair).  Used only by the (unused-in-browser) encrypt side of
// CryptoSpec; realized for completeness so the extraction links.
inline std::pair<std::string, std::string> aes_256_gcm_encrypt(
        const std::string& key, const std::string& nonce,
        const std::string& pt, const std::string& aad) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            try {
                var keyBuf = HEAPU8.slice($0, $0 + $1);
                var nonceBuf = HEAPU8.slice($2, $2 + $3);
                var ptBuf = HEAPU8.slice($4, $4 + $5);
                var aadBuf = HEAPU8.slice($6, $6 + $7);
                var k = await crypto.subtle.importKey('raw', keyBuf,
                    { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
                var algo = { name: 'AES-GCM', iv: nonceBuf, tagLength: 128 };
                if (aadBuf.length > 0) algo.additionalData = aadBuf;
                var out = new Uint8Array(await crypto.subtle.encrypt(algo, k, ptBuf));
                var ptr = _malloc(4 + out.length);
                HEAPU8[ptr] = (out.length >> 0) & 0xff;
                HEAPU8[ptr+1] = (out.length >> 8) & 0xff;
                HEAPU8[ptr+2] = (out.length >> 16) & 0xff;
                HEAPU8[ptr+3] = (out.length >> 24) & 0xff;
                HEAPU8.set(out, ptr + 4);
                return ptr;
            } catch (e) { return 0; }
        });
    }, key.data(), (int)key.size(), nonce.data(), (int)nonce.size(),
       pt.data(), (int)pt.size(), aad.data(), (int)aad.size()));
    std::string combined = crane_browser_detail::take_lp(p);
    if (combined.size() < 16) return { std::string(), std::string() };
    std::string ct = combined.substr(0, combined.size() - 16);
    std::string tg = combined.substr(combined.size() - 16);
    return { ct, tg };
}

// aes_256_gcm_decrypt(key, nonce, ct, tag, aad) -> plaintext ("" on tag
// mismatch).  crypto.subtle.decrypt wants ciphertext||tag, so we append the tag
// to ct inside JS.  Mirrors the shipped _aesGcmDecrypt.
inline std::string aes_256_gcm_decrypt(
        const std::string& key, const std::string& nonce,
        const std::string& ct, const std::string& tag,
        const std::string& aad) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            try {
                var keyBuf = HEAPU8.slice($0, $0 + $1);
                var nonceBuf = HEAPU8.slice($2, $2 + $3);
                var ctBuf = HEAPU8.slice($4, $4 + $5);
                var tagBuf = HEAPU8.slice($6, $6 + $7);
                var aadBuf = HEAPU8.slice($8, $8 + $9);
                var combined = new Uint8Array(ctBuf.length + tagBuf.length);
                combined.set(ctBuf, 0);
                combined.set(tagBuf, ctBuf.length);
                var k = await crypto.subtle.importKey('raw', keyBuf,
                    { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
                var algo = { name: 'AES-GCM', iv: nonceBuf, tagLength: 128 };
                if (aadBuf.length > 0) algo.additionalData = aadBuf;
                var plainBuf = await crypto.subtle.decrypt(algo, k, combined);
                var plain = new Uint8Array(plainBuf);
                var ptr = _malloc(4 + plain.length);
                HEAPU8[ptr] = (plain.length >> 0) & 0xff;
                HEAPU8[ptr+1] = (plain.length >> 8) & 0xff;
                HEAPU8[ptr+2] = (plain.length >> 16) & 0xff;
                HEAPU8[ptr+3] = (plain.length >> 24) & 0xff;
                HEAPU8.set(plain, ptr + 4);
                return ptr;
            } catch (e) {
                var ptr = _malloc(4); HEAPU8[ptr]=0; HEAPU8[ptr+1]=0;
                HEAPU8[ptr+2]=0; HEAPU8[ptr+3]=0; return ptr;
            }
        });
    }, key.data(), (int)key.size(), nonce.data(), (int)nonce.size(),
       ct.data(), (int)ct.size(), tag.data(), (int)tag.size(),
       aad.data(), (int)aad.size()));
    return crane_browser_detail::take_lp(p);
}

// base64_encode(bytes): btoa over a binary string -> ascii.
inline std::string base64_encode(const std::string& in) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        var bytes = HEAPU8.slice($0, $0 + $1);
        var s = '';
        for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
        var out = btoa(s);
        var enc = new TextEncoder();
        var ob = enc.encode(out);
        var ptr = _malloc(4 + ob.length);
        HEAPU8[ptr] = (ob.length >> 0) & 0xff;
        HEAPU8[ptr+1] = (ob.length >> 8) & 0xff;
        HEAPU8[ptr+2] = (ob.length >> 16) & 0xff;
        HEAPU8[ptr+3] = (ob.length >> 24) & 0xff;
        HEAPU8.set(ob, ptr + 4);
        return ptr;
    }, in.data(), (int)in.size()));
    return crane_browser_detail::take_lp(p);
}

// base64_decode(ascii): atob -> bytes.  Input MUST already be whitespace-free
// (ROCQ's MimeBuild.strip_ws is applied before this is reached), so NO regex is
// needed here — avoiding the acorn "Unterminated regular expression" trap.
inline std::string base64_decode(const std::string& in) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        try {
            var s = UTF8ToString($0);
            var binary = atob(s);
            var len = binary.length;
            var ptr = _malloc(4 + len);
            HEAPU8[ptr] = (len >> 0) & 0xff;
            HEAPU8[ptr+1] = (len >> 8) & 0xff;
            HEAPU8[ptr+2] = (len >> 16) & 0xff;
            HEAPU8[ptr+3] = (len >> 24) & 0xff;
            for (var i = 0; i < len; i++) HEAPU8[ptr + 4 + i] = binary.charCodeAt(i);
            return ptr;
        } catch (e) {
            var ptr = _malloc(4); HEAPU8[ptr]=0; HEAPU8[ptr+1]=0;
            HEAPU8[ptr+2]=0; HEAPU8[ptr+3]=0; return ptr;
        }
    }, in.data()));
    return crane_browser_detail::take_lp(p);
}

// ===========================================================================
// DOM (brE) — text read/write, escaped innerHTML, show/hide.  textContent only
// for untrusted text; set_inner_html receives only ROCQ-escaped HTML.
// ===========================================================================

inline std::string dom_get_text(const std::string& id) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        var el = document.getElementById(UTF8ToString($0));
        var s = el ? (el.textContent || '') : '';
        var enc = new TextEncoder();
        var b = enc.encode(s);
        var ptr = _malloc(4 + b.length);
        HEAPU8[ptr] = (b.length >> 0) & 0xff;
        HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
        HEAPU8[ptr+2] = (b.length >> 16) & 0xff;
        HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
        HEAPU8.set(b, ptr + 4);
        return ptr;
    }, id.data()));
    return crane_browser_detail::take_lp(p);
}

inline std::monostate dom_set_text(const std::string& id, const std::string& text) {
    EM_ASM({
        var el = document.getElementById(UTF8ToString($0));
        if (el) el.textContent = UTF8ToString($1);
    }, id.data(), text.data());
    return std::monostate{};
}

inline std::monostate dom_set_inner_html(const std::string& id, const std::string& html) {
    EM_ASM({
        var el = document.getElementById(UTF8ToString($0));
        if (el) el.innerHTML = UTF8ToString($1);
    }, id.data(), html.data());
    return std::monostate{};
}

inline std::monostate dom_show(const std::string& id) {
    EM_ASM({
        var el = document.getElementById(UTF8ToString($0));
        if (el) el.style.display = 'block';
    }, id.data());
    return std::monostate{};
}

inline std::monostate dom_hide(const std::string& id) {
    EM_ASM({
        var el = document.getElementById(UTF8ToString($0));
        if (el) el.style.display = 'none';
    }, id.data());
    return std::monostate{};
}

// ---------------------------------------------------------------------------
// Verified-Reader canvas (Wave 1).  The ROCQ Typeset engine lays the decrypted
// body into integer glyph quads (x,y in scaled points, 65536 sp = 1 pt); these
// two effects paint that buffer onto a <canvas> with the Canvas-2D API.
//
//   reader_begin(id): grab the canvas + its 2D context, size its backing store
//   to the CSS box * devicePixelRatio (crisp on HiDPI), scale the context by
//   dpr so all later drawing is in CSS px, clear it, set the fill colour (the
//   element's computed `color`) and an alphabetic baseline, and select a serif
//   font.  The context is stashed on Module.__rdr for reader_glyph to reuse.
//
//   reader_glyph(x_sp,y_sp,cp): fillText one codepoint at the sp->px-converted
//   pen.  sp/65536 = pt; px = pt * 96/72 (the CSS px-per-pt).  PXPT is the
//   sp->px scale; the font size below uses the SAME factor on the 10pt design
//   size so glyph advances (computed in ROCQ at 10pt) line up with the painted
//   glyphs.  Both blocks are regex-free (acorn-safe at -O2) and OpenSSL-free.
// ---------------------------------------------------------------------------

inline std::monostate reader_begin(const std::string& id) {
    EM_ASM({
        var c = document.getElementById(UTF8ToString($0));
        if (!c) return;
        var cx = c.getContext('2d');
        if (!cx) return;
        var dpr = window.devicePixelRatio || 1;
        // CSS box -> backing store px (HiDPI crispness).  Fall back to the
        // element's attribute/intrinsic size if it is not yet laid out.
        var cssW = c.clientWidth || c.width || 600;
        var cssH = c.clientHeight || c.height || 400;
        c.width = Math.max(1, Math.round(cssW * dpr));
        c.height = Math.max(1, Math.round(cssH * dpr));
        cx.setTransform(1, 0, 0, 1, 0, 0);
        cx.scale(dpr, dpr);
        cx.clearRect(0, 0, cssW, cssH);
        var col = '';
        try { col = getComputedStyle(c).color; } catch (e) {}
        cx.fillStyle = col || '#111';
        cx.textBaseline = 'alphabetic';
        // 10pt design size * 96/72 px-per-pt ~= 13.33px Georgia/Times serif.
        cx.font = (10 * 96 / 72) + 'px Georgia, "Times New Roman", serif';
        Module.__rdr = { cx: cx };
    }, id.data());
    return std::monostate{};
}

inline std::monostate reader_glyph(double x_sp, double y_sp, int cp) {
    EM_ASM({
        var r = Module.__rdr;
        if (!r || !r.cx) return;
        var PXPT = 96 / 72;          // CSS px per typographic point
        var x = ($0 / 65536) * PXPT; // sp -> pt -> px
        var y = ($1 / 65536) * PXPT;
        r.cx.fillText(String.fromCharCode($2), x, y);
    }, x_sp, y_sp, cp);
    return std::monostate{};
}

// location.pathname's last non-empty path segment (the post slug).
inline std::string dom_path_slug(std::monostate) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        var path = window.location.pathname;
        while (path.length > 0 && path[path.length - 1] === '/')
            path = path.substring(0, path.length - 1);
        var parts = path.split('/');
        var slug = parts.length > 0 ? parts[parts.length - 1] : '';
        if (slug === '') slug = 'post';
        var enc = new TextEncoder();
        var b = enc.encode(slug);
        var ptr = _malloc(4 + b.length);
        HEAPU8[ptr] = (b.length >> 0) & 0xff;
        HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
        HEAPU8[ptr+2] = (b.length >> 16) & 0xff;
        HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
        HEAPU8.set(b, ptr + 4);
        return ptr;
    }, 0));
    return crane_browser_detail::take_lp(p);
}

// ===========================================================================
// sessionStorage (brE).
// ===========================================================================

inline std::string ss_get(const std::string& key) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        var v = '';
        try { v = sessionStorage.getItem(UTF8ToString($0)) || ''; } catch (e) {}
        var enc = new TextEncoder();
        var b = enc.encode(v);
        var ptr = _malloc(4 + b.length);
        HEAPU8[ptr] = (b.length >> 0) & 0xff;
        HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
        HEAPU8[ptr+2] = (b.length >> 16) & 0xff;
        HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
        HEAPU8.set(b, ptr + 4);
        return ptr;
    }, key.data()));
    return crane_browser_detail::take_lp(p);
}

inline std::monostate ss_set(const std::string& key, const std::string& value) {
    EM_ASM({
        try { sessionStorage.setItem(UTF8ToString($0), UTF8ToString($1)); } catch (e) {}
    }, key.data(), value.data());
    return std::monostate{};
}

inline std::monostate ss_remove(const std::string& key) {
    EM_ASM({
        try { sessionStorage.removeItem(UTF8ToString($0)); } catch (e) {}
    }, key.data());
    return std::monostate{};
}

// ===========================================================================
// IndexedDB (brE) — DB "crane-blog-v2" v1; stores reader-keys(keyPath id),
// passkeys(keyPath credentialId).  getAll returns a JSON array string; put
// stores a JSON-encoded record.  All async via Asyncify.
// ===========================================================================

inline std::string idb_get_all(const std::string& store) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            try {
                var storeName = UTF8ToString($0);
                var req = indexedDB.open('crane-blog-v2', 1);
                await new Promise((resolve, reject) => {
                    req.onupgradeneeded = () => {
                        var db = req.result;
                        if (!db.objectStoreNames.contains('reader-keys'))
                            db.createObjectStore('reader-keys', { keyPath: 'id' });
                        if (!db.objectStoreNames.contains('passkeys'))
                            db.createObjectStore('passkeys', { keyPath: 'credentialId' });
                    };
                    req.onsuccess = () => resolve();
                    req.onerror = () => reject(req.error);
                });
                var db = req.result;
                var tx = db.transaction(storeName, 'readonly');
                var st = tx.objectStore(storeName);
                var getAllReq = st.getAll();
                var results = await new Promise((resolve, reject) => {
                    getAllReq.onsuccess = () => resolve(getAllReq.result || []);
                    getAllReq.onerror = () => reject(getAllReq.error);
                });
                db.close();
                var json = JSON.stringify(results);
                var enc = new TextEncoder();
                var b = enc.encode(json);
                var ptr = _malloc(4 + b.length);
                HEAPU8[ptr] = (b.length >> 0) & 0xff;
                HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
                HEAPU8[ptr+2] = (b.length >> 16) & 0xff;
                HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
                HEAPU8.set(b, ptr + 4);
                return ptr;
            } catch (e) {
                var enc = new TextEncoder();
                var b = enc.encode('[]');
                var ptr = _malloc(4 + b.length);
                HEAPU8[ptr] = (b.length >> 0) & 0xff;
                HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
                HEAPU8[ptr+2] = (b.length >> 16) & 0xff;
                HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
                HEAPU8.set(b, ptr + 4);
                return ptr;
            }
        });
    }, store.data()));
    return crane_browser_detail::take_lp(p);
}

// idb_put(store, jsonRecord): parse the JSON record and store.put it.  Returns
// "1" on success, "" on failure (so the ROCQ side can branch on a string).
inline std::string idb_put(const std::string& store, const std::string& json_record) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            try {
                var storeName = UTF8ToString($0);
                var value = JSON.parse(UTF8ToString($1));
                var req = indexedDB.open('crane-blog-v2', 1);
                await new Promise((resolve, reject) => {
                    req.onupgradeneeded = () => {
                        var db = req.result;
                        if (!db.objectStoreNames.contains('reader-keys'))
                            db.createObjectStore('reader-keys', { keyPath: 'id' });
                        if (!db.objectStoreNames.contains('passkeys'))
                            db.createObjectStore('passkeys', { keyPath: 'credentialId' });
                    };
                    req.onsuccess = () => resolve();
                    req.onerror = () => reject(req.error);
                });
                var db = req.result;
                var tx = db.transaction(storeName, 'readwrite');
                tx.objectStore(storeName).put(value);
                await new Promise((resolve, reject) => {
                    tx.oncomplete = () => resolve();
                    tx.onerror = () => reject(tx.error);
                });
                db.close();
                var enc = new TextEncoder(); var b = enc.encode('1');
                var ptr = _malloc(4 + b.length);
                HEAPU8[ptr] = (b.length >> 0) & 0xff; HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
                HEAPU8[ptr+2] = (b.length >> 16) & 0xff; HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
                HEAPU8.set(b, ptr + 4);
                return ptr;
            } catch (e) {
                var ptr = _malloc(4); HEAPU8[ptr]=0; HEAPU8[ptr+1]=0;
                HEAPU8[ptr+2]=0; HEAPU8[ptr+3]=0; return ptr;
            }
        });
    }, store.data(), json_record.data()));
    return crane_browser_detail::take_lp(p);
}

// ===========================================================================
// WebAuthn (brE).  create returns the new credential rawId as hex ("" on
// failure); get authenticates an existing credential by hex id, returning "1"
// on success / "" on failure.  Challenge/user strings are supplied by ROCQ.
// ===========================================================================

inline std::string webauthn_create(const std::string& challenge,
                                   const std::string& rp_name,
                                   const std::string& user_display) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            try {
                var challengeStr = UTF8ToString($0);
                var rpName = UTF8ToString($1);
                var userDisplay = UTF8ToString($2);
                var challenge = new TextEncoder().encode(challengeStr);
                var userIdBuf = await crypto.subtle.digest('SHA-256', challenge);
                var userId = new Uint8Array(userIdBuf).slice(0, 16);
                var cred = await navigator.credentials.create({ publicKey: {
                    rp: { name: rpName },
                    user: { id: userId, name: 'reader-' + challengeStr.slice(-12),
                            displayName: userDisplay },
                    challenge: challenge,
                    pubKeyCredParams: [ { type: 'public-key', alg: -7 },
                                        { type: 'public-key', alg: -8 } ],
                    authenticatorSelection: { residentKey: 'required',
                                              userVerification: 'preferred' },
                    timeout: 120000 } });
                var rawId = new Uint8Array(cred.rawId);
                var hex = Array.from(rawId).map(function(b) {
                    return b.toString(16).padStart(2, '0'); }).join('');
                var enc = new TextEncoder(); var b = enc.encode(hex);
                var ptr = _malloc(4 + b.length);
                HEAPU8[ptr] = (b.length >> 0) & 0xff; HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
                HEAPU8[ptr+2] = (b.length >> 16) & 0xff; HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
                HEAPU8.set(b, ptr + 4);
                return ptr;
            } catch (e) {
                console.error('WebAuthn create failed:', e);
                var ptr = _malloc(4); HEAPU8[ptr]=0; HEAPU8[ptr+1]=0;
                HEAPU8[ptr+2]=0; HEAPU8[ptr+3]=0; return ptr;
            }
        });
    }, challenge.data(), rp_name.data(), user_display.data()));
    return crane_browser_detail::take_lp(p);
}

// webauthn_get(credIdHex, challenge): assert an existing passkey.  "1" success.
inline std::string webauthn_get(const std::string& cred_id_hex,
                                const std::string& challenge) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        return Asyncify.handleAsync(async () => {
            try {
                var hex = UTF8ToString($0);
                var n = hex.length / 2;
                var idBuf = new Uint8Array(n);
                for (var i = 0; i < n; i++) idBuf[i] = parseInt(hex.substr(i*2, 2), 16);
                await navigator.credentials.get({ publicKey: {
                    challenge: new TextEncoder().encode(UTF8ToString($1)),
                    allowCredentials: [ { id: idBuf, type: 'public-key' } ],
                    timeout: 60000, userVerification: 'preferred' } });
                var enc = new TextEncoder(); var b = enc.encode('1');
                var ptr = _malloc(4 + b.length);
                HEAPU8[ptr] = (b.length >> 0) & 0xff; HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
                HEAPU8[ptr+2] = (b.length >> 16) & 0xff; HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
                HEAPU8.set(b, ptr + 4);
                return ptr;
            } catch (e) {
                var ptr = _malloc(4); HEAPU8[ptr]=0; HEAPU8[ptr+1]=0;
                HEAPU8[ptr+2]=0; HEAPU8[ptr+3]=0; return ptr;
            }
        });
    }, cred_id_hex.data(), challenge.data()));
    return crane_browser_detail::take_lp(p);
}

// ===========================================================================
// JSON field extraction over an IndexedDB getAll() result string.  These are
// thin marshalling helpers (parse a JSON array, pull a field) — no domain
// branching — kept here so the ROCQ side works with plain strings.  The ROCQ
// flow decides which record matches; these only project fields.
// ===========================================================================

// Number of records in a JSON array string.
inline int json_array_len(const std::string& json) {
    return EM_ASM_INT({
        try { var a = JSON.parse(UTF8ToString($0)); return Array.isArray(a) ? a.length : 0; }
        catch (e) { return 0; }
    }, json.data());
}

// String field [field] of the [i]-th element of a JSON array string ("" if
// absent).  For nested object fields (e.g. privkeyJwk) the value is
// re-stringified so the ROCQ side can pass it back to ecdh_p256_agree.
inline std::string json_array_field(const std::string& json, int i,
                                     const std::string& field) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        var out = '';
        try {
            var a = JSON.parse(UTF8ToString($0));
            var f = UTF8ToString($2);
            if (Array.isArray(a) && $1 >= 0 && $1 < a.length && a[$1] != null) {
                var v = a[$1][f];
                if (v === undefined || v === null) out = '';
                else if (typeof v === 'string') out = v;
                else out = JSON.stringify(v);
            }
        } catch (e) { out = ''; }
        var enc = new TextEncoder(); var b = enc.encode(out);
        var ptr = _malloc(4 + b.length);
        HEAPU8[ptr] = (b.length >> 0) & 0xff; HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
        HEAPU8[ptr+2] = (b.length >> 16) & 0xff; HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
        HEAPU8.set(b, ptr + 4);
        return ptr;
    }, json.data(), i, field.data()));
    return crane_browser_detail::take_lp(p);
}

// ===========================================================================
// Keepalive re-entry (binding only).  The WASM main ([run]) runs once per
// invocation; click handlers re-invoke it.  bind_invoke attaches a click
// listener on [id] that sets window.__crane_action='1' and re-runs main via
// callMain([]); action_flag reads-and-clears that flag so the ROCQ [run] can
// dispatch the on-load path vs. the click action.  Pure binding — no domain
// logic.  (Emscripten is built with -sINVOKE_RUN=0 so the first callMain is
// driven by the loader; see the Dockerfile wasm stage / the page's module
// bootstrap.)
// ===========================================================================

inline std::monostate bind_invoke(const std::string& id) {
    EM_ASM({
        var el = document.getElementById(UTF8ToString($0));
        if (el && !el.__craneBound) {
            el.__craneBound = true;
            el.addEventListener('click', function () {
                window.__crane_action = '1';
                try { Module.callMain([]); } catch (e) { console.error(e); }
            });
        }
    }, id.data());
    return std::monostate{};
}

inline std::string crane_action_flag(std::monostate) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        var v = (window.__crane_action === '1') ? '1' : '';
        window.__crane_action = '';
        var enc = new TextEncoder(); var b = enc.encode(v);
        var ptr = _malloc(4 + b.length);
        HEAPU8[ptr] = (b.length >> 0) & 0xff; HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
        HEAPU8[ptr+2] = (b.length >> 16) & 0xff; HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
        HEAPU8.set(b, ptr + 4);
        return ptr;
    }, 0));
    return crane_browser_detail::take_lp(p);
}

// Build a JSON object string from up to four string fields (k_i, v_i); empty
// keys are skipped.  Marshalling helper for idb_put records (reader-keys /
// passkeys).  No domain logic — the ROCQ side chooses the keys and values.
inline std::string json_object4(const std::string& k0, const std::string& v0,
                                 const std::string& k1, const std::string& v1,
                                 const std::string& k2, const std::string& v2,
                                 const std::string& k3, const std::string& v3) {
    char* p = reinterpret_cast<char*>(EM_ASM_PTR({
        var o = {};
        function add(k, v) { if (k && k.length > 0) o[k] = v; }
        add(UTF8ToString($0), UTF8ToString($1));
        add(UTF8ToString($2), UTF8ToString($3));
        add(UTF8ToString($4), UTF8ToString($5));
        add(UTF8ToString($6), UTF8ToString($7));
        var s = JSON.stringify(o);
        var enc = new TextEncoder(); var b = enc.encode(s);
        var ptr = _malloc(4 + b.length);
        HEAPU8[ptr] = (b.length >> 0) & 0xff; HEAPU8[ptr+1] = (b.length >> 8) & 0xff;
        HEAPU8[ptr+2] = (b.length >> 16) & 0xff; HEAPU8[ptr+3] = (b.length >> 24) & 0xff;
        HEAPU8.set(b, ptr + 4);
        return ptr;
    }, k0.data(), v0.data(), k1.data(), v1.data(),
       k2.data(), v2.data(), k3.data(), v3.data()));
    return crane_browser_detail::take_lp(p);
}

#endif  // __EMSCRIPTEN__
