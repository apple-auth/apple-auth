#pragma once
#include "sap/data/macos_certificate.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>

namespace apple_auth::detail::sap {

inline std::array<std::uint8_t, 128>
transform_macos_certificate_block(std::span<const std::uint8_t, 128> seed) {
    namespace parameters = macos_certificate_constants;
    std::array<std::uint8_t, 128> state{};
    std::transform(seed.begin(), seed.end(), state.begin(), [](auto value) {
        return static_cast<std::uint8_t>(value ^ parameters::arithmetic[0]);
    });
    for (unsigned round = 0; round < 7; ++round) {
        std::array<std::uint8_t, 80> work{};
        for (std::size_t index = 0; index < work.size(); ++index) {
            const auto source = index < 64 ? state[64 + index] : parameters::tail16[index - 64];
            work[index] = static_cast<std::uint8_t>((source ^ parameters::arithmetic[0]) + index) ^
                          parameters::arithmetic[1];
        }
        for (std::size_t index = 0; index < work.size(); ++index) {
            work[index] = static_cast<std::uint8_t>(
                              parameters::first[work[index] ^ parameters::arithmetic[1]] +
                              parameters::arithmetic[2] + index) ^
                          parameters::arithmetic[1];
        }
        // Each pass updates in place: later bytes see earlier byte updates.
        for (const auto bias : {parameters::arithmetic[3],
                                parameters::arithmetic[4],
                                parameters::arithmetic[5],
                                parameters::arithmetic[6]}) {
            for (std::size_t index = 0; index < work.size(); ++index) {
                work[index] ^= static_cast<std::uint8_t>(
                    parameters::left[work[(index + 75) % 80] ^ parameters::arithmetic[1]] +
                    parameters::right[work[(index + 55) % 80] ^ parameters::arithmetic[1]] + bias +
                    index);
            }
        }
        for (std::size_t index = 0; index < work.size(); ++index) {
            work[index] = static_cast<std::uint8_t>(
                              parameters::last[work[index] ^ parameters::arithmetic[1]] +
                              parameters::arithmetic[7] + index) ^
                          parameters::arithmetic[1];
        }
        std::array<std::uint8_t, 128> next{};
        std::copy_n(state.begin() + 64, 64, next.begin());
        for (std::size_t index = 0; index < 64; ++index) {
            next[64 + index] = state[index] ^ work[index] ^ parameters::arithmetic[1];
        }
        state = next;
    }
    for (auto& value : state) {
        value ^= parameters::arithmetic[0];
    }
    return state;
}

// The caller supplies 78 uniformly sampled, nonzero bytes. Native storage
// rejects 0x5f; applying its codec here preserves that rejection policy.
inline std::array<std::uint8_t, 256>
make_macos_profile_certificate(std::span<const std::uint8_t> entropy) {
    if (entropy.size() != 78 || std::find(entropy.begin(), entropy.end(), 0) != entropy.end()) {
        throw std::invalid_argument("Expected SAP macOS certificate entropy78 without zero bytes");
    }
    namespace parameters = macos_certificate_constants;
    std::array<std::uint8_t, 128> first{}, second{};
    std::copy(parameters::header68.begin(), parameters::header68.end(), first.begin());
    std::copy(parameters::header110.begin(), parameters::header110.end(), second.begin());
    for (std::size_t index = 0; index < 60; ++index) {
        first[68 + index] = entropy[index] ^ parameters::arithmetic[8];
    }
    for (std::size_t index = 0; index < 18; ++index) {
        second[110 + index] = entropy[60 + index] ^ parameters::arithmetic[8];
    }
    const auto left = transform_macos_certificate_block(first);
    const auto right = transform_macos_certificate_block(second);
    std::array<std::uint8_t, 256> result{};
    std::copy(left.begin(), left.end(), result.begin());
    std::copy(right.begin(), right.end(), result.begin() + 128);
    return result;
}

} // namespace apple_auth::detail::sap
