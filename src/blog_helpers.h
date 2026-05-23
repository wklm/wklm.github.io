#pragma once

// Linear-time helpers that override default Crane extractions where the naive
// fixpoint emission would be asymptotically worse than necessary.  These are
// registered via [Crane Extract Inlined Constant] in Logic.v.
//
// The helpers are templates so they don't need to know the concrete [List<T>]
// instantiation up front; instantiation happens at the call site inside the
// generated [blog.cpp] where the full definition of [List] is in scope.

#include <cstddef>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <variant>

#include <openssl/evp.h>

// Concatenate a Coq-extracted [list string] in a single pass.  The default
// fixpoint extraction compiles to a right fold over [std::string operator+]
// which is O(n^2) in the total output length; this version walks the list
// twice -- once to sum the sizes, once to append -- so the allocation count
// is bounded by a single [reserve] plus one [std::string] output.
//
// Crane generates List<T> with Cons fields: T a; unique_ptr<List<T>> l;
template <typename List>
inline std::string concat_all_std(const List& xs) {
    using Nil = typename List::Nil;
    using Cons = typename List::Cons;
    std::size_t total = 0;
    for (auto p = &xs; p && !std::holds_alternative<Nil>(p->v()); ) {
        const auto& c = std::get<Cons>(p->v());
        total += c.a.size();
        p = c.l.get();
    }
    std::string out;
    out.reserve(total);
    for (auto p = &xs; p && !std::holds_alternative<Nil>(p->v()); ) {
        const auto& c = std::get<Cons>(p->v());
        out.append(c.a);
        p = c.l.get();
    }
    return out;
}

// Truncated SHA-256 hash (first 12 hex chars) for content-addressed
// inbox labels.  Registered via [Crane Extract Inlined Constant] in Logic.v.
inline std::string sha256_trunc_std(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    std::ostringstream oss;
    for (unsigned int i = 0; i < 12 && i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}
