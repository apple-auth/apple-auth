#pragma once
#include "crypto.hpp"
#include "sap/data/keys.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace apple_auth::detail::sap {

struct KeyStreamStep {
    std::uint8_t output;
    KeyStreamState state;
};

// Arithmetic wraps at 32 bits; feedback uses the byte before XOR.
inline KeyStreamStep decode_key_stream_byte(KeyStreamState state, std::uint8_t input) {
    const auto [a, b, c, d] = state;
    const std::uint32_t mixed = a + input * key_stream_coefficients[0] + key_stream_coefficients[1];
    const std::uint32_t reduced = mixed ^ (mixed % 257U);
    const std::uint32_t combined = reduced + b - c;
    const std::uint32_t feedback = (combined ^ d) + key_stream_coefficients[2];
    const std::uint32_t first = (b + feedback + c - (d ^ feedback)) ^ key_stream_coefficients[3];
    return {static_cast<std::uint8_t>(input ^ a),
            {first, (b + feedback) ^ first, (c ^ feedback) - first, (d ^ feedback) - first}};
}

inline std::vector<std::uint8_t> unmask_key_material(std::span<const std::uint8_t> input) {
    if (input.size() != 1248) {
        throw std::invalid_argument("Expected a 1248-byte SAP key-material block");
    }
    std::vector<std::uint8_t> output(input.begin(), input.end());
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] ^= key_material_mask[index % key_material_mask.size()];
    }
    return output;
}

struct KeyMaterialParameters {
    std::array<std::uint8_t, 16> key;
    std::array<std::uint8_t, 16> iv;
    std::array<std::uint8_t, 16> input_mask;
    std::array<std::uint8_t, 16> output_mask;
};

// Feedback uses the decoded byte, followed by masked AES-128 CBC.
inline std::vector<std::uint8_t>
decode_key_material_blocks(std::span<const std::uint8_t> input,
                           const KeyMaterialParameters& parameters) {
    if (input.size() != 1248) {
        throw std::invalid_argument("Expected a 1248-byte SAP key-material block");
    }
    auto state = initial_key_stream_state;
    const auto schedule = ::apple_auth::detail::expand_aes128_key(parameters.key);
    auto previous = parameters.iv;
    std::vector<std::uint8_t> output(input.size());
    for (std::size_t offset = 0; offset < input.size(); offset += 16) {
        std::array<std::uint8_t, 16> ciphertext{};
        for (std::size_t byte = 0; byte < 16; ++byte) {
            const auto decoded = static_cast<std::uint8_t>(input[offset + byte] ^ state.first);
            state = decode_key_stream_byte(state, decoded).state;
            ciphertext[byte] = decoded ^ parameters.input_mask[byte];
        }
        const auto plaintext = ::apple_auth::detail::decrypt_aes128_block(ciphertext, schedule);
        for (std::size_t byte = 0; byte < 16; ++byte) {
            output[offset + byte] = plaintext[byte] ^ previous[byte] ^ parameters.output_mask[byte];
        }
        previous = ciphertext;
    }
    return output;
}

// Decode 1248 bytes before address encoding.
inline std::vector<std::uint8_t> decode_key_material(std::span<const std::uint8_t> input,
                                                     const KeyMaterialParameters& parameters) {
    auto data = unmask_key_material(input);
    auto state = initial_key_stream_state;
    for (auto& byte : data) {
        const auto result = decode_key_stream_byte(state, byte);
        byte = result.output;
        state = result.state;
    }
    return decode_key_material_blocks(data, parameters);
}

struct KeyMaterialFields {
    std::array<std::array<std::uint8_t, 16>, 3> small_fields;
    std::array<std::array<std::uint8_t, 576>, 2> large_fields;
    std::array<std::uint8_t, 16> final_field;
};

// Remove the position mask: six BE32-length-prefixed fields and eight zeros.
inline KeyMaterialFields
parse_key_material_fields(std::span<const std::uint8_t> material,
                          const std::array<std::uint8_t, 16>& position_mask) {
    if (material.size() != 1248) {
        throw std::invalid_argument("Expected a 1248-byte SAP key-material block");
    }
    std::size_t offset = 0;
    auto read_byte = [&]() {
        const auto byte = static_cast<std::uint8_t>(material[offset] ^ position_mask[offset % 16]);
        ++offset;
        return byte;
    };
    auto read_field = [&](auto& field) {
        std::uint32_t length = 0;
        for (unsigned i = 0; i < 4; ++i) {
            length = (length << 8) | read_byte();
        }
        if (length != field.size()) {
            throw std::invalid_argument("Unexpected SAP material field length");
        }
        for (auto& byte : field) {
            byte = read_byte();
        }
    };
    KeyMaterialFields result{};
    for (auto& field : result.small_fields) {
        read_field(field);
    }
    for (auto& field : result.large_fields) {
        read_field(field);
    }
    read_field(result.final_field);
    while (offset < material.size()) {
        if (read_byte() != 0) {
            throw std::invalid_argument("Unexpected SAP material trailer");
        }
    }
    return result;
}

} // namespace apple_auth::detail::sap
