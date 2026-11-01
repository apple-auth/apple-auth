#pragma once
#include "crypto.hpp"

#include "key_material.hpp"
#include "mac_key.hpp"

namespace apple_auth::detail::sap {

struct SessionKeys {
    ::apple_auth::detail::AesBlock mac;
    ::apple_auth::detail::AesBlock profile;
};

// Field 2 encrypts the profile; field 4 encodes the authenticator key.
inline SessionKeys decode_session_keys(std::span<const std::uint8_t> encoded_material,
                                       const KeyMaterialParameters& loader,
                                       const std::array<std::uint8_t, 16>& position_mask,
                                       const MacKeyParameters& mac,
                                       std::span<const std::uint8_t> pair_masks,
                                       std::span<const std::uint8_t> expected_nonce = {}) {
    if (!expected_nonce.empty() && expected_nonce.size() != 16) {
        throw std::invalid_argument("Expected SAP setup nonce16");
    }
    const auto logical = decode_key_material(encoded_material, loader);
    const auto fields = parse_key_material_fields(logical, position_mask);
    if (!expected_nonce.empty()) {
        unsigned difference = 0;
        for (std::size_t byte = 0; byte < 16; ++byte) {
            difference |= fields.final_field[byte] ^ expected_nonce[byte];
        }
        if (difference != 0) {
            throw std::invalid_argument("SAP reply does not match the setup nonce");
        }
    }
    return {recover_mac_key_from_field(fields.large_fields[1], mac, pair_masks),
            fields.small_fields[2]};
}

inline ::apple_auth::detail::AesBlock
decode_session_key(std::span<const std::uint8_t> encoded_material,
                   const KeyMaterialParameters& loader,
                   const std::array<std::uint8_t, 16>& position_mask,
                   const MacKeyParameters& mac,
                   std::span<const std::uint8_t> pair_masks) {
    return decode_session_keys(encoded_material, loader, position_mask, mac, pair_masks).mac;
}

} // namespace apple_auth::detail::sap
