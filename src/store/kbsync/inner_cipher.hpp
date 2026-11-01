#pragma once
#include "adi/internal.hpp"
#include "codecs.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace apple_auth::detail::kbsync {

struct InnerCipherParameters {
    AesBlock key;
    AesBlock iv;
    AesBlock input_whitening;
    AesBlock output_whitening;
};

inline std::array<std::uint8_t, 176> encrypt_inner176(std::span<const std::uint8_t, 176> input,
                                                      const InnerCipherParameters& parameters) {
    const auto schedule = expand_aes128_key(parameters.key);
    auto previous = parameters.iv;
    std::array<std::uint8_t, 176> output{};
    for (std::size_t offset = 0; offset < output.size(); offset += 16) {
        AesBlock block{};
        for (std::size_t index = 0; index < block.size(); ++index) {
            block[index] = input[offset + index] ^ input_mask[index] ^
                           parameters.input_whitening[index] ^ previous[index];
        }
        previous = encrypt_aes128_block(block, schedule);
        for (std::size_t index = 0; index < block.size(); ++index) {
            output[offset + index] =
                previous[index] ^ parameters.output_whitening[index] ^ output_mask[index];
        }
    }
    return output;
}

} // namespace apple_auth::detail::kbsync
