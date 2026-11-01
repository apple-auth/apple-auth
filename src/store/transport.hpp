#pragma once
#include "adi/internal.hpp"
#include "store/data/transport.hpp"
#include <algorithm>
#include <array>
#include <span>

namespace apple_auth::detail::store_transport {

struct Parameters {
    AesBlock key;
    AesBlock iv;
};

inline Parameters derive_parameters_for_profile(std::span<const std::uint8_t> hardware,
                                                std::span<const std::uint8_t, 88> dp_info,
                                                const FixedProfile& profile) {
    const auto schedule = expand_aes128_key(profile.key);
    const auto fixed_encrypt = [&](AesBlock input) {
        for (std::size_t i = 0; i < 16; ++i) {
            input[i] ^= profile.input_mask[i];
        }
        auto output = encrypt_aes128_block(input, schedule);
        for (std::size_t i = 0; i < 16; ++i) {
            output[i] ^= profile.output_mask[i];
        }
        return output;
    };
    AesBlock first{};
    const auto count = hardware.size();
    std::copy(hardware.begin(), hardware.end(), first.begin());
    std::copy_n(dp_info.begin() + 4, 4, first.begin() + count);
    std::copy_n(dp_info.begin() + 24, 12 - count, first.begin() + count + 4);
    const auto digest = sha1(fixed_encrypt(first));
    std::array<std::uint8_t, 32> record{};
    std::copy(digest.begin(), digest.end(), record.begin());
    std::copy_n(dp_info.begin() + 36 - count, 10, record.begin() + 20);
    record[30] = 0xff;
    AesBlock chain{};
    std::copy_n(dp_info.begin() + 40, 16, chain.begin());
    for (std::size_t offset = 0; offset < 32; offset += 16) {
        for (std::size_t i = 0; i < 16; ++i) {
            chain[i] ^= record[offset + i];
        }
        chain = fixed_encrypt(chain);
    }
    const auto wrapping_schedule = expand_aes128_key(chain);
    std::copy_n(dp_info.begin() + 40, 16, chain.begin());
    std::array<AesBlock, 2> output{};
    for (std::size_t index = 0; index < 2; ++index) {
        AesBlock cipher{};
        std::copy_n(dp_info.begin() + 56 + 16 * index, 16, cipher.begin());
        output[index] = decrypt_aes128_block(cipher, wrapping_schedule);
        for (std::size_t i = 0; i < 16; ++i) {
            output[index][i] ^= chain[i];
        }
        chain = cipher;
    }
    return {output[0], output[1]};
}

inline Parameters derive_parameters(std::span<const std::uint8_t, 20> hardware,
                                    std::span<const std::uint8_t, 88> dp_info) {
    return derive_parameters_for_profile(hardware.first<8>(), dp_info, mac27_profile);
}

inline Parameters derive_mac_store_parameters(std::span<const std::uint8_t, 6> hardware,
                                              std::span<const std::uint8_t, 88> dp_info) {
    return derive_parameters_for_profile(hardware, dp_info, mac_store_v3_profile);
}

} // namespace apple_auth::detail::store_transport
