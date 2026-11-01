#pragma once
#include "adi/internal.hpp"

namespace apple_auth::detail {
inline void add_wrapped(std::span<std::uint8_t> output, std::size_t index, std::uint32_t delta) {
    auto& value = output[index % output.size()];
    value = static_cast<std::uint8_t>(value + delta);
}

inline void fold_adjustment_tables(std::span<std::uint8_t> output,
                                   const std::array<std::uint8_t, 64>& working,
                                   const std::array<std::uint8_t, 64>& local) {
    for (std::size_t index = 0; index < working.size(); ++index) {
        output[index % output.size()] ^= working[index] ^ local[index];
    }
}
} // namespace apple_auth::detail
