#pragma once
#include "crypto.hpp"
#include "data_mask.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace apple_auth::detail::sap {

// The last entropy byte selects a 16–32-byte prefix.
inline std::vector<std::uint8_t> make_profile_info(std::span<const std::uint8_t> entropy) {
    if (entropy.size() != 33) {
        throw std::invalid_argument("Expected SAP profile entropy33");
    }
    return {entropy.begin(), entropy.begin() + 16 + entropy[32] % 17};
}

inline std::array<std::uint8_t, 256> make_profile_certificate() {
    static const auto pattern =
        data_mask::decode(std::array<std::uint8_t, 3>{0x63, 0xBA, 0x27}, 0x13BD7017U);
    std::array<std::uint8_t, 256> result{};
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = pattern[i % pattern.size()];
    }
    return result;
}

// A 16-byte profile produces 448 bytes; longer profiles produce 464.
inline std::vector<std::uint8_t> make_session_blob(std::span<const std::uint8_t> certificate,
                                                   std::span<const std::uint8_t> profile_info,
                                                   std::span<const std::uint8_t> profile_key,
                                                   std::span<const std::uint8_t> server_ticket,
                                                   std::uint32_t device_type = 66) {
    if (certificate.size() != 256 || profile_info.size() < 16 || profile_info.size() > 32 ||
        profile_key.size() != 16 || server_ticket.size() != 159) {
        throw std::invalid_argument("Unsupported SAP profile certificate/info/key/ticket lengths");
    }
    std::vector<std::uint8_t> result((432 + profile_info.size() + 15) & ~std::size_t(15));
    std::size_t offset = 0;
    auto append = [&](std::span<const std::uint8_t> value) {
        std::copy(value.begin(), value.end(), result.begin() + offset);
        offset += value.size();
    };
    auto append_length = [&](std::size_t length) {
        for (unsigned byte = 0; byte < 4; ++byte) {
            result[offset++] = static_cast<std::uint8_t>(length >> (24 - 8 * byte));
        }
    };
    result[offset++] = 3;
    append_length(device_type);
    append_length(certificate.size());
    append(certificate);
    append_length(profile_info.size());
    const auto schedule = ::apple_auth::detail::expand_aes128_key(
        std::span<const std::uint8_t, 16>(profile_key.data(), 16));
    // Encrypt only the first block, including for 32-byte profiles.
    ::apple_auth::detail::AesBlock block{};
    std::copy_n(profile_info.begin(), 16, block.begin());
    append(::apple_auth::detail::encrypt_aes128_block(block, schedule));
    append(profile_info.subspan(16));
    append_length(server_ticket.size());
    append(server_ticket);
    return result; // Trailing bytes are zero-filled to the block boundary.
}

} // namespace apple_auth::detail::sap
