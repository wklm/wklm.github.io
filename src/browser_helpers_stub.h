#pragma once

// browser_helpers_stub.h -- a NON-Emscripten stub of browser_helpers.h.
//
// Purpose: let plain clang++ (no emsdk) type-check + compile the Crane-extracted
// crane_decrypt.cpp / crane_enroll.cpp natively, so std::any leaks (the #1 Crane
// gotcha — chained-if-in-let, recursive-tuple-returns, nested let-fix) and other
// C++ type errors surface in the fast `crane-blog:builder` loop BEFORE the heavy
// em++ WASM link.  It provides the exact same function signatures as
// browser_helpers.h but with trivial, side-effect-free bodies (no EM_ASM, no
// crypto, no DOM).  It is compiled ONLY by the dune compile-check rule; the real
// behavior comes from browser_helpers.h under em++.
//
// Because every signature matches, a successful compile here means the extracted
// C++ is well-typed and std::any-free; it says nothing about runtime behavior
// (that is the em++ build + owner in-browser gate).

#include <string>
#include <cstdint>
#include <utility>
#include <variant>

// ---- crypto primitives ----
inline std::string random_bytes(int) { return std::string(); }
inline std::string sha256(const std::string&) { return std::string(32, '\0'); }
inline std::pair<std::string, std::string> ecdh_p256_generate(std::monostate) {
    return { std::string(65, '\0'), std::string() };
}
inline std::string ecdh_p256_public_key(const std::string&) { return std::string(65, '\0'); }
inline std::string ecdh_p256_agree(const std::string&, const std::string&) {
    return std::string(32, '\0');
}
inline std::pair<std::string, std::string> aes_256_gcm_encrypt(
        const std::string&, const std::string&, const std::string&, const std::string&) {
    return { std::string(), std::string(16, '\0') };
}
inline std::string aes_256_gcm_decrypt(
        const std::string&, const std::string&, const std::string&,
        const std::string&, const std::string&) { return std::string(); }
inline std::string base64_encode(const std::string&) { return std::string(); }
inline std::string base64_decode(const std::string&) { return std::string(); }
inline std::string ecdsa_p256_sign(const std::string&, const std::string&) { return std::string(64, '\0'); }
inline bool ecdsa_p256_verify(const std::string&, const std::string&, const std::string&) { return false; }

// ---- DOM ----
inline std::string   dom_get_text(const std::string&) { return std::string(); }
inline std::monostate dom_set_text(const std::string&, const std::string&) { return {}; }
inline std::monostate dom_set_inner_html(const std::string&, const std::string&) { return {}; }
inline std::monostate dom_show(const std::string&) { return {}; }
inline std::monostate dom_hide(const std::string&) { return {}; }
inline std::string   dom_path_slug(std::monostate) { return std::string(); }

// ---- Verified-Reader canvas (Wave 1) ----
inline std::monostate reader_begin(const std::string&, double) { return {}; }
inline std::monostate reader_glyph(double, double, int) { return {}; }
inline std::monostate reader_style(int) { return {}; }
inline int64_t render_latex_canvas(const std::string&, int64_t, int64_t) { return 0; }

// ---- sessionStorage ----
inline std::string   ss_get(const std::string&) { return std::string(); }
inline std::monostate ss_set(const std::string&, const std::string&) { return {}; }
inline std::monostate ss_remove(const std::string&) { return {}; }

// ---- IndexedDB ----
inline std::string idb_get_all(const std::string&) { return std::string("[]"); }
inline std::string idb_put(const std::string&, const std::string&) { return std::string(); }
inline std::string keydir_register(const std::string&, const std::string&) { return std::string(); }

// ---- WebAuthn ----
// Signatures match browser_helpers.h: the ceremony policy (alg CSV, residentKey,
// userVerification, timeout) is passed in by ROCQ (BrowserPolicy.v), not baked
// into the shim.
inline std::string webauthn_create(const std::string&, const std::string&, const std::string&,
                                   const std::string&, const std::string&, const std::string&,
                                   int) {
    return std::string();
}
inline std::string webauthn_get(const std::string&, const std::string&,
                                const std::string&, int) { return std::string(); }

// ---- keepalive ----
inline std::monostate bind_invoke(const std::string&) { return {}; }
inline std::string    crane_action_flag(std::monostate) { return std::string(); }

// ---- JSON marshalling ----
inline int         json_array_len(const std::string&) { return 0; }
inline std::string json_array_field(const std::string&, int, const std::string&) {
    return std::string();
}
inline std::string json_object4(const std::string&, const std::string&,
                                const std::string&, const std::string&,
                                const std::string&, const std::string&,
                                const std::string&, const std::string&) {
    return std::string();
}
