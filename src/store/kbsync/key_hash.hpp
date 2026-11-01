#pragma once
#include "adi/internal.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace apple_auth::detail::kbsync {

inline Md5Digest key_material_hash(std::uint64_t dsid, std::span<const std::uint8_t, 255> body) {
    std::array<std::uint8_t, 263> message{};
    for (std::size_t byte = 0; byte < 8; ++byte) {
        message[byte] = static_cast<std::uint8_t>(dsid >> ((7 - byte) * 8));
    }
    for (std::size_t byte = 0; byte < body.size(); ++byte) {
        message[8 + byte] = body[byte];
    }
    return md5(message);
}

} // namespace apple_auth::detail::kbsync
