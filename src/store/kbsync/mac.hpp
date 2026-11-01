#pragma once
#include "adi/internal.hpp"
#include "store/data/arithmetic.hpp"
#include "store/data/keys.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace apple_auth::detail::kbsync {

inline AesBlock derive_mac_key(AesBlock inner_key) {
    for (std::size_t index = 0; index < inner_key.size(); ++index) {
        inner_key[index] ^= mac_key_mask[index];
    }
    return inner_key;
}

inline Sha1Digest compute_mac192(std::span<const std::uint8_t, 192> packet,
                                 const AesBlock& inner_key) {
    const auto key = derive_mac_key(inner_key);
    std::array<std::uint8_t, 256> inner{};
    std::array<std::uint8_t, 84> outer{};
    for (std::size_t index = 0; index < 64; ++index) {
        const auto byte = index < key.size() ? key[index] : std::uint8_t{0};
        inner[index] = static_cast<std::uint8_t>(byte ^ mac_values[0]);
        outer[index] = static_cast<std::uint8_t>(byte ^ mac_values[1]);
    }
    for (std::size_t index = 0; index < packet.size(); ++index) {
        inner[64 + index] = packet[index];
    }
    const auto digest = sha1(inner);
    for (std::size_t index = 0; index < digest.size(); ++index) {
        outer[64 + index] = digest[index];
    }
    return sha1(outer);
}

} // namespace apple_auth::detail::kbsync
