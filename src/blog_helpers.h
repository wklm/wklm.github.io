#pragma once

// Linear-time helpers that override default Crane extractions where the naive
// fixpoint emission would be asymptotically worse than necessary.  These are
// registered via [Crane Extract Inlined Constant] in Logic.v.
//
// The helpers are templates so they don't need to know the concrete [List<T>]
// instantiation up front; instantiation happens at the call site inside the
// generated [blog.cpp] where the full definition of [List] is in scope.

#include <cstddef>
#include <memory>
#include <string>
#include <variant>

// Concatenate a Coq-extracted [list string] in a single pass.  The default
// fixpoint extraction compiles to a right fold over [std::string operator+]
// which is O(n^2) in the total output length; this version walks the list
// twice -- once to sum the sizes, once to append -- so the allocation count
// is bounded by a single [reserve] plus one [std::string] output.
template <typename List>
inline std::string concat_all_std(const std::shared_ptr<List>& xs) {
    using Nil = typename List::Nil;
    using Cons = typename List::Cons;
    std::size_t total = 0;
    for (auto p = xs; p && !std::holds_alternative<Nil>(p->v()); ) {
        const auto& c = std::get<Cons>(p->v());
        total += c.d_a0.size();
        p = c.d_a1;
    }
    std::string out;
    out.reserve(total);
    for (auto p = xs; p && !std::holds_alternative<Nil>(p->v()); ) {
        const auto& c = std::get<Cons>(p->v());
        out.append(c.d_a0);
        p = c.d_a1;
    }
    return out;
}
