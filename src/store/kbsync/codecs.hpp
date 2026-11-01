#pragma once
#include "store/data/codecs.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace apple_auth::detail::kbsync {

inline void apply_input_codec(std::span<std::uint8_t> data, std::size_t offset = 0) {
    for (auto& byte : data) {
        byte ^= input_mask[offset++ & 15u];
    }
}

inline void apply_output_codec(std::span<std::uint8_t> data, std::size_t offset = 0) {
    for (auto& byte : data) {
        byte ^= output_mask[offset++ & 15u];
    }
}

} // namespace apple_auth::detail::kbsync
