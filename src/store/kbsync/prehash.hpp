#pragma once
#include "key_material.hpp"
#include "prehash_byte_kernel.hpp"
#include "store/data/arithmetic.hpp"
#include "store/data/prehash.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>

namespace apple_auth::detail::kbsync {

inline std::uint8_t prehash_rotate8(std::uint8_t value, unsigned count) {
    return static_cast<std::uint8_t>((value << count) | (value >> (8 - count)));
}

inline std::array<std::uint8_t, 319> prehash_mix319(std::span<const std::uint8_t> input) {
    if (input.empty()) {
        throw std::invalid_argument("Prehash input must be nonempty");
    }
    std::array<std::uint8_t, 319> state{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = input[index % input.size()];
    }
    for (std::uint32_t index = 0; index < 1276; ++index) {
        const auto one = state[(index - 13u) % 319u];
        const auto two = state[(index - 57u) % 319u];
        const auto three = state[(index - 155u) % 319u];
        const auto mixed = static_cast<std::uint8_t>(state[index % 319u] ^ prehash_rotate8(one, 3) ^
                                                     prehash_values[0]);
        const auto added = static_cast<std::uint8_t>(
            mixed + prehash_rotate8(static_cast<std::uint8_t>(two ^ prehash_values[1]), 5) -
            prehash_rotate8(static_cast<std::uint8_t>(three ^ prehash_values[1]), 7));
        state[index % 319u] = static_cast<std::uint8_t>(added ^ prehash_values[1]);
    }
    return state;
}

inline std::array<std::uint8_t, 16> prehash_bytes(std::span<const std::uint8_t> input) {
    auto state = prehash_mix319(input);
    auto table = detail::prehash_table;
    auto pad = detail::prehash_pad;
    std::array<std::uint8_t, 16> output{};
    detail::prehash_byte_kernel(table, state, pad, detail::prehash_source_pad, output);
    for (std::size_t index = 0; index < 64; ++index) {
        output[index & 15u] ^= pad[index];
    }
    for (std::size_t index = 0; index < 64; ++index) {
        output[index & 15u] ^= table[index] ^ prehash_values[1];
    }
    for (std::size_t index = 0; index < state.size(); ++index) {
        output[index & 15u] ^= state[index] ^ prehash_values[1];
    }
    for (std::uint32_t index = 0; index < 256; ++index) {
        output[index & 15u] ^= prehash_values[2] ^ prehash_rotate8(output[(index - 7u) & 15u], 1) ^
                               prehash_rotate8(output[(index - 37u) & 15u], 6) ^
                               prehash_rotate8(output[(index - 177u) & 15u], 5);
    }
    return output;
}

inline std::array<std::uint8_t, 16> prehash40(std::span<const std::uint8_t, 40> input) {
    return prehash_bytes(input);
}

inline std::uint8_t prehash_scramble_byte(std::size_t index, std::uint8_t value) {
    const auto first = static_cast<std::uint8_t>((value ^ prehash_values[3]) + prehash_values[4]);
    const auto second = static_cast<std::uint8_t>((value ^ prehash_values[5]) - prehash_values[5]);
    const auto third = static_cast<std::uint8_t>((value ^ prehash_values[6]) - prehash_values[6]);
    auto temporary =
        static_cast<std::uint8_t>((index ^ 1u) - ((index + prehash_values[7]) ^ prehash_values[8]) +
                                  (third ^ first ^ second));
    const auto folded = static_cast<std::uint8_t>(temporary + prehash_values[9]);
    temporary = static_cast<std::uint8_t>(((prehash_values[10] - temporary) & prehash_values[11]) |
                                          prehash_values[12]);
    temporary ^= folded & prehash_values[13];
    auto mixed = static_cast<std::uint8_t>((folded & 6u) ^ temporary);
    mixed = static_cast<std::uint8_t>(((folded ^ 4u) & (mixed << 1)) ^ temporary);
    for (unsigned count = 0; count < 4; ++count) {
        mixed =
            static_cast<std::uint8_t>(((folded ^ prehash_values[14]) & (mixed << 1)) ^ temporary);
    }
    return static_cast<std::uint8_t>(folded ^ (mixed << 1) ^ prehash_values[15]);
}

inline std::array<std::uint8_t, 255> prepare_key_body(std::span<const std::uint8_t> hardware,
                                                      std::span<const std::uint8_t, 12> context) {
    if (hardware.size() != 6 && hardware.size() != 20) {
        throw std::invalid_argument("Expected Store hardware6 or TestFlight hardware20");
    }
    auto body = detail::prehash_template;
    for (std::size_t index = 0; index < hardware.size(); ++index) {
        body[index] ^= hardware[index];
    }
    for (std::size_t index = 0; index < context.size(); ++index) {
        body[hardware.size() + index] ^= context[index];
    }
    for (std::size_t index = 0; index < hardware.size() + 8; ++index) {
        body[index] = prehash_scramble_byte(index, body[index]);
    }
    const auto prefix =
        prehash_bytes(std::span<const std::uint8_t>(body.data(), hardware.size() + 20));
    for (std::size_t index = 0; index < prefix.size(); ++index) {
        body[index] = prefix[index];
    }
    for (auto& byte : body) {
        byte ^= prehash_values[1];
    }
    return body;
}

inline AesBlock derive_inner_key(std::uint64_t dsid,
                                 std::span<const std::uint8_t> hardware,
                                 std::span<const std::uint8_t, 12> context) {
    return key_material_from_body(dsid, prepare_key_body(hardware, context));
}

} // namespace apple_auth::detail::kbsync
