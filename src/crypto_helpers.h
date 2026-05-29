#pragma once

// crypto_helpers.h -- OpenSSL EVP FFI shim for the CryptoSpec.v primitives.
//
// This is the *native* realization (C1 in the FFI boundary catalog) of the
// nine cryptographic axioms declared in src/CryptoSpec.v.  Semantics match the
// retired hand-written src/crane_crypto.ml (mirage_crypto + digestif) exactly:
//
//   - public keys are SEC1 *uncompressed* (65 bytes: 0x04 || x32 || y32);
//   - private keys are the 32-byte P-256 scalar;
//   - ECDH agreement returns the 32-byte x-coordinate of the shared point;
//   - AES-256-GCM packages are nonce(12) || ciphertext || tag(16); aad == ""
//     means "no additional authenticated data"; decrypt returns "" on tag
//     mismatch (or any error);
//   - random_bytes(n) returns "" for n <= 0;
//   - base64 returns "" on decode error.
//
// The two tuple-returning primitives return std::pair DIRECTLY (Crane maps Coq
// [prod] to std::pair with .first/.second), so no prod-adapter IIFE is needed.
//
// NO domain logic lives here: no MIME, no protocol framing, no policy.  This
// header is linked only into the native build (-lssl -lcrypto); browser builds
// must NOT include it (OpenSSL is absent under Emscripten).

#include <string>
#include <utility>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <variant>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

namespace crane_crypto_detail {

// ---- helpers --------------------------------------------------------------

inline std::string bytes_to_string(const unsigned char* p, std::size_t n) {
    return std::string(reinterpret_cast<const char*>(p), n);
}

// Build an EC_KEY for P-256 from a 32-byte private scalar.  Returns nullptr on
// error.  If with_pub is true, the public point is also computed.
inline EC_KEY* ec_key_from_scalar(const std::string& sk, bool with_pub) {
    if (sk.size() != 32) return nullptr;
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return nullptr;
    BIGNUM* bn = BN_bin2bn(reinterpret_cast<const unsigned char*>(sk.data()),
                           static_cast<int>(sk.size()), nullptr);
    if (!bn) { EC_KEY_free(key); return nullptr; }
    if (EC_KEY_set_private_key(key, bn) != 1) {
        BN_free(bn); EC_KEY_free(key); return nullptr;
    }
    if (with_pub) {
        const EC_GROUP* group = EC_KEY_get0_group(key);
        EC_POINT* pub = EC_POINT_new(group);
        BN_CTX* ctx = BN_CTX_new();
        if (!pub || !ctx ||
            EC_POINT_mul(group, pub, bn, nullptr, nullptr, ctx) != 1 ||
            EC_KEY_set_public_key(key, pub) != 1) {
            if (pub) EC_POINT_free(pub);
            if (ctx) BN_CTX_free(ctx);
            BN_free(bn); EC_KEY_free(key); return nullptr;
        }
        EC_POINT_free(pub);
        BN_CTX_free(ctx);
    }
    BN_free(bn);
    return key;
}

// Serialize the public point of an EC_KEY as 65-byte SEC1 uncompressed.
inline std::string ec_pub_uncompressed(const EC_KEY* key) {
    const EC_GROUP* group = EC_KEY_get0_group(key);
    const EC_POINT* pub = EC_KEY_get0_public_key(key);
    if (!group || !pub) return std::string();
    BN_CTX* ctx = BN_CTX_new();
    unsigned char buf[65];
    size_t n = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                  buf, sizeof(buf), ctx);
    BN_CTX_free(ctx);
    if (n != 65) return std::string();
    return bytes_to_string(buf, 65);
}

// Parse a 65-byte SEC1 uncompressed public key into an EC_POINT on P-256.
inline EC_POINT* ec_point_from_uncompressed(const EC_GROUP* group,
                                            const std::string& pk) {
    if (pk.size() != 65) return nullptr;
    EC_POINT* pt = EC_POINT_new(group);
    BN_CTX* ctx = BN_CTX_new();
    int ok = EC_POINT_oct2point(group, pt,
                                reinterpret_cast<const unsigned char*>(pk.data()),
                                pk.size(), ctx);
    BN_CTX_free(ctx);
    if (ok != 1) { EC_POINT_free(pt); return nullptr; }
    return pt;
}

}  // namespace crane_crypto_detail

// ---- 1. ECDH P-256 keypair generation -------------------------------------
// (unit) -> (uncompressed_pubkey 65B, scalar 32B).  The ROCQ side passes [tt]
// as a freshness token; Crane extracts [unit] as std::monostate and always
// applies it, so the helper accepts and ignores a std::monostate argument.
inline std::pair<std::string, std::string>
ecdh_p256_generate(std::monostate) {
    using namespace crane_crypto_detail;
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) return {std::string(), std::string()};
    if (EC_KEY_generate_key(key) != 1) {
        EC_KEY_free(key);
        return {std::string(), std::string()};
    }
    std::string pub = ec_pub_uncompressed(key);
    const BIGNUM* priv = EC_KEY_get0_private_key(key);
    unsigned char sk[32] = {0};
    // Left-pad the scalar to a fixed 32 bytes.
    int len = BN_num_bytes(priv);
    if (len > 32) { EC_KEY_free(key); return {std::string(), std::string()}; }
    BN_bn2bin(priv, sk + (32 - len));
    std::string priv_s = bytes_to_string(sk, 32);
    EC_KEY_free(key);
    return {pub, priv_s};
}

// ---- 2. Derive public key from private scalar -----------------------------
inline std::string ecdh_p256_public_key(std::string sk) {
    using namespace crane_crypto_detail;
    EC_KEY* key = ec_key_from_scalar(sk, true);
    if (!key) return std::string();
    std::string pub = ec_pub_uncompressed(key);
    EC_KEY_free(key);
    return pub;
}

// ---- 3. ECDH key agreement ------------------------------------------------
// agree(sk, pk) -> 32-byte x-coordinate of sk * pk; "" on any error.
inline std::string ecdh_p256_agree(std::string sk, std::string pk) {
    using namespace crane_crypto_detail;
    EC_KEY* key = ec_key_from_scalar(sk, false);
    if (!key) return std::string();
    const EC_GROUP* group = EC_KEY_get0_group(key);
    EC_POINT* peer = ec_point_from_uncompressed(group, pk);
    if (!peer) { EC_KEY_free(key); return std::string(); }
    unsigned char shared[32];
    int n = ECDH_compute_key(shared, sizeof(shared), peer, key, nullptr);
    EC_POINT_free(peer);
    EC_KEY_free(key);
    if (n != 32) return std::string();
    return bytes_to_string(shared, 32);
}

// ---- 4. Random bytes ------------------------------------------------------
inline std::string random_bytes(int n) {
    if (n <= 0) return std::string();
    std::string out(static_cast<std::size_t>(n), '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&out[0]), n) != 1)
        return std::string();
    return out;
}

// ---- 5. SHA-256 -----------------------------------------------------------
inline std::string sha256(std::string s) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), digest);
    return crane_crypto_detail::bytes_to_string(digest, SHA256_DIGEST_LENGTH);
}

// ---- 6. AES-256-GCM encrypt -----------------------------------------------
// encrypt(key32, nonce12, pt, aad) -> (ciphertext, tag16).
// aad == "" => no AAD.  On any error returns ("", "").
inline std::pair<std::string, std::string>
aes_256_gcm_encrypt(std::string key, std::string nonce,
                    std::string pt, std::string aad) {
    if (key.size() != 32 || nonce.size() != 12)
        return {std::string(), std::string()};
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {std::string(), std::string()};
    auto fail = [&]() -> std::pair<std::string, std::string> {
        EVP_CIPHER_CTX_free(ctx);
        return {std::string(), std::string()};
    };
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return fail();
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        return fail();
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           reinterpret_cast<const unsigned char*>(nonce.data())) != 1)
        return fail();
    int outl = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &outl,
                              reinterpret_cast<const unsigned char*>(aad.data()),
                              static_cast<int>(aad.size())) != 1)
            return fail();
    }
    std::string ct(pt.size(), '\0');
    if (!pt.empty()) {
        if (EVP_EncryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(&ct[0]), &outl,
                              reinterpret_cast<const unsigned char*>(pt.data()),
                              static_cast<int>(pt.size())) != 1)
            return fail();
    }
    int tmpl = 0;
    unsigned char final_buf[16];
    if (EVP_EncryptFinal_ex(ctx, final_buf, &tmpl) != 1) return fail();
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) return fail();
    EVP_CIPHER_CTX_free(ctx);
    return {ct, crane_crypto_detail::bytes_to_string(tag, 16)};
}

// ---- 7. AES-256-GCM decrypt -----------------------------------------------
// decrypt(key32, nonce12, ct, tag16, aad) -> plaintext; "" on tag mismatch
// or any error.  aad == "" => no AAD.
inline std::string
aes_256_gcm_decrypt(std::string key, std::string nonce,
                    std::string ct, std::string tag, std::string aad) {
    if (key.size() != 32 || nonce.size() != 12 || tag.size() != 16)
        return std::string();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::string();
    auto fail = [&]() -> std::string {
        EVP_CIPHER_CTX_free(ctx);
        return std::string();
    };
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return fail();
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1)
        return fail();
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           reinterpret_cast<const unsigned char*>(key.data()),
                           reinterpret_cast<const unsigned char*>(nonce.data())) != 1)
        return fail();
    int outl = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &outl,
                              reinterpret_cast<const unsigned char*>(aad.data()),
                              static_cast<int>(aad.size())) != 1)
            return fail();
    }
    std::string pt(ct.size(), '\0');
    if (!ct.empty()) {
        if (EVP_DecryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(&pt[0]), &outl,
                              reinterpret_cast<const unsigned char*>(ct.data()),
                              static_cast<int>(ct.size())) != 1)
            return fail();
    }
    // Set expected tag, then finalize to verify.
    unsigned char tagbuf[16];
    std::memcpy(tagbuf, tag.data(), 16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagbuf) != 1)
        return fail();
    int tmpl = 0;
    unsigned char final_buf[16];
    int ok = EVP_DecryptFinal_ex(ctx, final_buf, &tmpl);
    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1) return std::string();  // tag mismatch
    return pt;
}

// ---- 8/9. Base64 ----------------------------------------------------------
// Standard base64 with padding, no line wrapping.
inline std::string base64_encode(std::string s) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((s.size() + 2) / 3) * 4);
    std::size_t i = 0;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(s.data());
    std::size_t len = s.size();
    while (i + 3 <= len) {
        unsigned b0 = p[i], b1 = p[i + 1], b2 = p[i + 2];
        out.push_back(tbl[b0 >> 2]);
        out.push_back(tbl[((b0 & 0x3) << 4) | (b1 >> 4)]);
        out.push_back(tbl[((b1 & 0xf) << 2) | (b2 >> 6)]);
        out.push_back(tbl[b2 & 0x3f]);
        i += 3;
    }
    std::size_t rem = len - i;
    if (rem == 1) {
        unsigned b0 = p[i];
        out.push_back(tbl[b0 >> 2]);
        out.push_back(tbl[(b0 & 0x3) << 4]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        unsigned b0 = p[i], b1 = p[i + 1];
        out.push_back(tbl[b0 >> 2]);
        out.push_back(tbl[((b0 & 0x3) << 4) | (b1 >> 4)]);
        out.push_back(tbl[(b1 & 0xf) << 2]);
        out.push_back('=');
    }
    return out;
}

// Decode standard base64; ignores whitespace; "" on a structurally invalid
// character.  Mirrors the mirage base64 "Error => empty" contract.
inline std::string base64_decode(std::string s) {
    int dec[256];
    for (int i = 0; i < 256; ++i) dec[i] = -1;
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; ++i) dec[static_cast<unsigned char>(tbl[i])] = i;
    std::string out;
    int bits = 0, nbits = 0;
    for (unsigned char c : s) {
        if (c == '=') continue;
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int v = dec[c];
        if (v < 0) return std::string();
        bits = (bits << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            out.push_back(static_cast<char>((bits >> nbits) & 0xff));
        }
    }
    return out;
}

// ===========================================================================
// Process-IO platform shim (backs IoEffects.v's [toolE]).
//
// Pure platform delegation — argv access, getenv, stderr, exit.  No domain
// branching, no string/MIME/protocol construction (thin-shim test passes).
// The globals are populated once by the dune-generated main.cpp:
//     int main(int c, char** v) { tool_set_args(c, v); run(); }
// Defined inline here (the single allowed FFI header) so the extracted
// encrypt_post.cpp / decrypt_post.cpp can see the declarations via the
// From "crypto_helpers.h" clauses in IoEffects.v.
// ===========================================================================

inline int   g_tool_argc = 0;
inline char** g_tool_argv = nullptr;

inline void tool_set_args(int argc, char** argv) {
    g_tool_argc = argc;
    g_tool_argv = argv;
}

// Number of argv entries (includes argv[0], the program name) as int64_t to
// match Crane's int63 -> int64_t mapping.
inline int64_t tool_arg_count() {
    return static_cast<int64_t>(g_tool_argc);
}

// argv[i] as std::string; "" when out of range.
inline std::string tool_arg_get(int64_t i) {
    if (i < 0 || i >= g_tool_argc || g_tool_argv == nullptr) return std::string();
    const char* a = g_tool_argv[i];
    return a ? std::string(a) : std::string();
}

// getenv(name); "" when unset.
inline std::string tool_getenv(const std::string& name) {
    const char* v = std::getenv(name.c_str());
    return v ? std::string(v) : std::string();
}

// Write to stderr (no trailing newline added).
inline void tool_eprint(const std::string& s) {
    std::cerr << s;
}

// Terminate the process with the given exit code (never returns).
inline void tool_exit(int64_t code) {
    std::exit(static_cast<int>(code));
}
