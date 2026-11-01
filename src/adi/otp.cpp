#include "adi/data/tables.hpp"
#include "adi/internal.hpp"
#include "data_mask.hpp"

namespace apple_auth::detail {
AesBlock compute_otp_mac(const OtpHashes& hashes, std::span<const std::uint8_t, 16> device_key) {
    const auto schedule = expand_aes128_key(device_key);
    AesBlock state{};
    for (const auto& hash : hashes) {
        for (std::size_t offset = 0; offset < hash.size(); offset += state.size()) {
            for (std::size_t byte = 0; byte < state.size(); ++byte) {
                state[byte] ^= hash[offset + byte];
            }
            state = encrypt_aes128_block(state, schedule);
        }
    }
    return state;
}

std::vector<std::uint8_t> decode_store_secondary(std::span<const std::uint8_t> input,
                                                 const SecondaryCipherParameters& parameters) {
    if (input.size() % 16 != 0) {
        throw std::invalid_argument("Secondary cipher input must contain complete AES blocks");
    }
    const auto schedule = expand_aes128_key(parameters.key);
    auto previous = parameters.iv;
    std::vector<std::uint8_t> output(input.size());
    for (std::size_t offset = 0; offset < input.size(); offset += 16) {
        AesBlock ciphertext{};
        for (std::size_t index = 0; index < ciphertext.size(); ++index) {
            ciphertext[index] = input[offset + index];
        }
        const auto plaintext = decrypt_aes128_block(ciphertext, schedule);
        for (std::size_t index = 0; index < plaintext.size(); ++index) {
            const auto decoded = static_cast<std::uint8_t>(plaintext[index] ^ previous[index] ^
                                                           parameters.whitening[index]);
            output[offset + (index ^ 3U)] = parameters.output_maps[index % 4].apply(decoded);
        }
        previous = ciphertext;
    }
    return output;
}

std::array<AffineByteMap, 8> decode_store_byte_maps(std::span<const std::uint8_t, 64> parameters) {
    std::array<AffineByteMap, 8> result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        const auto& codec = matrix_codecs[index];
        auto& decoded = result[index];
        decoded.offset = codec.offset;
        decoded.linear.basis = codec.basis_offset;
        for (const auto& column : codec.columns) {
            const auto image = column.column_map.apply(parameters[column.source_byte]);
            for (std::size_t bit = 0; bit < 8; ++bit) {
                if ((column.row_mask & (1U << bit)) != 0) {
                    decoded.linear.basis[bit] ^= image;
                }
            }
        }
    }
    return result;
}

AesBlock decode_store_device_key(std::span<const std::uint8_t, 272> secondary) {
    const auto maps =
        decode_store_byte_maps(std::span<const std::uint8_t, 64>(secondary.data() + 208, 64));
    static const auto word_mask =
        data_mask::decode(std::array<std::uint8_t, 4>{0x7E, 0x20, 0xB9, 0x8B}, 0xC84575C4U);
    AesBlock final_round_key{};
    for (std::size_t byte = 0; byte < final_round_key.size(); ++byte) {
        const auto position = 160 + byte;
        const auto encoded =
            static_cast<std::uint8_t>(secondary[position] ^ secondary[176 + position % 32] ^
                                      word_mask[byte % 4] ^ encoded_key_offsets[byte]);
        const auto intermediate = maps[byte % 4].linear.apply(encoded);
        final_round_key[byte ^ 3] =
            key_output_maps[byte % 4].apply(intermediate) ^ decoded_key_offsets[byte];
    }
    return recover_aes128_key(final_round_key);
}

ArithmeticHashState arithmetic_hash_round(const ArithmeticHashState& state,
                                          std::uint32_t message_word,
                                          std::uint32_t round_constant) {
    const auto [a, b, c, d, e, f, g, h] = state;
    const std::uint32_t first = h + std::rotr(e, 25) + (std::rotr(e, 6) ^ std::rotr(e, 11)) +
                                2U * g + e + (f ^ e) + message_word + round_constant;
    const std::uint32_t second =
        c - a - (a ^ c) + 2U * b + std::rotr(a, 2) - std::rotr(a, 13) - std::rotr(a, 22);
    return {first + second, a, b, c, d + first, e, f, g};
}

std::uint32_t arithmetic_hash_schedule_word(std::uint32_t oldest,
                                            std::uint32_t previous_fifteen,
                                            std::uint32_t previous_seven,
                                            std::uint32_t previous_two) {
    const std::uint32_t first =
        std::rotr(previous_fifteen, 7) + std::rotr(previous_fifteen, 18) - (previous_fifteen >> 3);
    const std::uint32_t second =
        std::rotr(previous_two, 17) - std::rotr(previous_two, 19) - (previous_two >> 10);
    return previous_seven - oldest + (first ^ second);
}

ArithmeticHashState arithmetic_hash_compress(const ArithmeticHashState& initial,
                                             std::span<const std::uint8_t, 64> block) {
    std::array<std::uint32_t, 64> schedule{};
    for (std::size_t index = 0; index < 16; ++index) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            schedule[index] = (schedule[index] << 8) | block[index * 4 + byte];
        }
    }
    for (std::size_t index = 16; index < schedule.size(); ++index) {
        schedule[index] = arithmetic_hash_schedule_word(
            schedule[index - 16], schedule[index - 15], schedule[index - 7], schedule[index - 2]);
    }
    auto state = initial;
    for (std::size_t index = 0; index < schedule.size(); ++index) {
        state =
            arithmetic_hash_round(state, schedule[index], arithmetic_hash_round_constants[index]);
    }
    return {state[0] - initial[0],
            state[1] - initial[1],
            state[2] - initial[2],
            state[3] + initial[3],
            state[4] - initial[4],
            state[5] + initial[5],
            state[6] ^ initial[6],
            state[7] ^ initial[7]};
}

std::array<std::uint8_t, 32> arithmetic_hash(std::span<const std::uint8_t> message) {
    auto state = arithmetic_hash_initial_state;
    const std::size_t complete_bytes = message.size() - message.size() % 64;
    for (std::size_t offset = 0; offset < complete_bytes; offset += 64) {
        state = arithmetic_hash_compress(
            state, std::span<const std::uint8_t, 64>(message.data() + offset, 64));
    }
    std::array<std::uint8_t, 128> tail{};
    const std::size_t remaining = message.size() - complete_bytes;
    for (std::size_t index = 0; index < remaining; ++index) {
        tail[index] = message[complete_bytes + index];
    }
    tail[remaining] = 0x80;
    const std::size_t padded_size = remaining < 56 ? 64 : 128;
    const std::uint64_t bit_length = static_cast<std::uint64_t>(message.size()) * 8;
    for (std::size_t byte = 0; byte < 8; ++byte) {
        tail[padded_size - 1 - byte] = static_cast<std::uint8_t>(bit_length >> (byte * 8));
    }
    for (std::size_t offset = 0; offset < padded_size; offset += 64) {
        state = arithmetic_hash_compress(
            state, std::span<const std::uint8_t, 64>(tail.data() + offset, 64));
    }
    std::array<std::uint8_t, 32> digest{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            digest[index * 4 + byte] = static_cast<std::uint8_t>(state[index] >> (24 - byte * 8));
        }
    }
    return digest;
}

std::array<std::uint8_t, 64> expand_arithmetic_digest(std::span<const std::uint8_t, 32> digest) {
    std::array<std::uint8_t, 64> expanded{};
    for (std::size_t index = 0; index < expanded.size(); ++index) {
        const std::size_t left = (5 * index + 7) % digest.size();
        const std::size_t right = (5 * index * index + 9) % digest.size();
        const auto adjusted = static_cast<std::uint8_t>(digest[right] + 42U);
        expanded[index] = digest[left] ^ adjusted;
    }
    return expanded;
}

std::array<std::uint8_t, 55> store_counter_message(std::span<const std::uint8_t, 32> seed,
                                                   std::uint32_t counter) {
    static const auto moduli = data_mask::decode(
        std::array<std::uint32_t, 4>{0xBFD6E222U, 0xAB5D4239U, 0x854D91DAU, 0xBDB8F5EEU},
        0x3C0D2741U);
    std::array<std::uint8_t, 55> message{};
    for (std::size_t index = 0; index < moduli.size(); ++index) {
        const std::uint32_t remainder = counter % moduli[index];
        message[index * 2] = static_cast<std::uint8_t>(remainder >> 8);
        message[index * 2 + 1] = static_cast<std::uint8_t>(remainder);
    }
    std::uint32_t rolling = 0x6B532D89U;
    for (std::size_t index = 0; index < seed.size() * 3; ++index) {
        const std::size_t destination = (index + 7) % message.size();
        const auto mixed =
            static_cast<std::uint8_t>((rolling ^ 0x1AU) + seed[(index * 2 + 1) % seed.size()]);
        message[destination] ^= mixed;
        rolling ^= static_cast<std::uint32_t>(message[destination]) * 0x5D809044U;
    }
    return message;
}

StoreHashMaterial derive_store_hash_material(std::span<const std::uint8_t, 32> seed,
                                             std::uint32_t counter) {
    const auto seed_hash = arithmetic_hash(seed);
    const auto expanded = expand_arithmetic_digest(seed_hash);
    const auto counter_message = store_counter_message(seed, counter);
    return {seed_hash, arithmetic_hash(expanded), arithmetic_hash(counter_message)};
}

AesBlock generate_store_otp(std::span<const std::uint8_t, 32> seed,
                            std::uint32_t counter,
                            std::span<const std::uint8_t, 16> device_key) {
    const auto material = derive_store_hash_material(seed, counter);
    const std::array<std::array<std::uint8_t, 32>, 3> hashes = {
        material.seed_hash, material.expanded_hash, material.counter_hash};
    return compute_otp_mac(hashes, device_key);
}

GsaKeyState mix_gsa_key_state(std::span<const std::uint8_t, 208> input) {
    GsaKeyState state{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = input[index] ^ 5;
    }
    auto feedback = static_cast<std::uint8_t>(state[207] + state[147] + state[8] + state[123]);
    state[31] = static_cast<std::uint8_t>(state[31] - feedback);
    for (const auto destination : gsa_key_mix_positions) {
        auto& value = state[destination];
        switch (feedback & 7) {
        case 3:
            value = static_cast<std::uint8_t>(value - feedback);
            break;
        case 5:
            value = static_cast<std::uint8_t>(value + feedback);
            break;
        case 6:
        case 7:
            value ^= feedback;
            break;
        default:
            break;
        }
        feedback = static_cast<std::uint8_t>((feedback ^ value) + 0x6E);
    }
    for (auto& value : state) {
        value ^= 5;
    }
    return state;
}

AesBlock decode_gsa_final_round_key(std::span<const std::uint8_t, 208> mixed_state,
                                    const GsaMixedKeyParameters& parameters) {
    AesBlock round_key{};
    for (std::size_t index = 0; index < round_key.size(); ++index) {
        const auto& sources = parameters.sources[index];
        for (const auto source : sources) {
            if (source >= mixed_state.size()) {
                throw std::invalid_argument("GrandSlam key source exceeds the 208-byte state");
            }
        }
        const auto mapped =
            static_cast<std::uint8_t>(mixed_state[sources[1]] ^ mixed_state[sources[2]]);
        round_key[index] = parameters.offsets[index] ^ mixed_state[sources[0]] ^
                           parameters.mapped_sources.apply(mapped);
    }
    return round_key;
}

AesBlock decode_gsa_device_key_from_mixed_state(std::span<const std::uint8_t, 208> mixed_state,
                                                const GsaMixedKeyParameters& parameters) {
    return recover_aes128_key(decode_gsa_final_round_key(mixed_state, parameters));
}

std::vector<std::uint8_t> decode_gsa_secondary(std::span<const std::uint8_t> ciphertext,
                                               const SecondaryCipherParameters& parameters) {
    if (ciphertext.empty() || ciphertext.size() % 16 != 0) {
        throw std::invalid_argument("GrandSlam secondary input needs complete AES blocks");
    }
    const auto schedule = expand_aes128_key(parameters.key);
    auto previous = parameters.iv;
    std::vector<std::uint8_t> output(ciphertext.size());
    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        AesBlock block{};
        std::copy_n(ciphertext.begin() + offset, block.size(), block.begin());
        const auto plaintext = decrypt_aes128_block(block, schedule);
        for (std::size_t index = 0; index < block.size(); ++index) {
            const auto value = static_cast<std::uint8_t>(plaintext[index] ^ previous[index] ^
                                                         parameters.whitening[index]);
            output[offset + index] = parameters.output_maps[index % 4].apply(value);
        }
        previous = block;
    }
    return output;
}

AesBlock decode_gsa_device_key(std::span<const std::uint8_t, 208> opaque_state,
                               const GsaKeyParameters& parameters) {
    const auto decoded = decode_gsa_secondary(opaque_state, parameters.secondary_cipher);
    const auto mixed = mix_gsa_key_state(std::span<const std::uint8_t, 208>(decoded.data(), 208));
    return decode_gsa_device_key_from_mixed_state(mixed, parameters.mixed_key);
}

GsaHashState
gsa_hash_round(const GsaHashState& state, std::uint32_t message, std::uint32_t constant) {
    const auto [a, b, c, d, e, f, g, h] = state;
    const std::uint32_t sigma_a = std::rotr(a, 2) + std::rotr(a, 13) - std::rotr(a, 22);
    const std::uint32_t mixed_abc = (a ^ b) - (a ^ c) - b - c;
    const std::uint32_t sigma_e = (std::rotr(e, 6) - std::rotr(e, 11)) ^ std::rotr(e, 25);
    const std::uint32_t mixed_efg = ((f + e) ^ e ^ g) + g;
    const std::uint32_t first = (h + sigma_e - mixed_efg + constant) ^ message;
    const std::uint32_t second = sigma_a ^ mixed_abc;
    return {first + second, a, b, c, d + first, e, f, g};
}

std::uint32_t gsa_hash_schedule_word(std::uint32_t oldest,
                                     std::uint32_t previous_fifteen,
                                     std::uint32_t previous_seven,
                                     std::uint32_t previous_two) {
    const std::uint32_t first =
        std::rotr(previous_fifteen, 7) - std::rotr(previous_fifteen, 18) - (previous_fifteen >> 3);
    const std::uint32_t second =
        (std::rotr(previous_two, 17) ^ std::rotr(previous_two, 19)) + (previous_two >> 10);
    return (first - second - previous_seven) ^ oldest;
}

GsaHashState gsa_hash_compress(const GsaHashState& initial,
                               std::span<const std::uint8_t, 64> block) {
    std::array<std::uint32_t, 64> schedule{};
    for (std::size_t index = 0; index < 16; ++index) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            schedule[index] = (schedule[index] << 8) | block[index * 4 + byte];
        }
    }
    for (std::size_t index = 16; index < schedule.size(); ++index) {
        schedule[index] = gsa_hash_schedule_word(
            schedule[index - 16], schedule[index - 15], schedule[index - 7], schedule[index - 2]);
    }
    auto state = initial;
    for (std::size_t index = 0; index < schedule.size(); ++index) {
        state = gsa_hash_round(state, schedule[index], gsa_hash_round_constants[index]);
    }
    return {state[0] - initial[0],
            state[1] + initial[1],
            state[2] ^ initial[2],
            state[3] ^ initial[3],
            state[4] - initial[4],
            state[5] - initial[5],
            state[6] - initial[6],
            state[7] + initial[7]};
}

GsaHashDigest gsa_hash(std::span<const std::uint8_t> message) {
    auto state = gsa_hash_initial_state;
    const std::size_t complete_bytes = message.size() - message.size() % 64;
    for (std::size_t offset = 0; offset < complete_bytes; offset += 64) {
        state = gsa_hash_compress(state,
                                  std::span<const std::uint8_t, 64>(message.data() + offset, 64));
    }
    std::array<std::uint8_t, 128> tail{};
    const std::size_t remaining = message.size() - complete_bytes;
    for (std::size_t index = 0; index < remaining; ++index) {
        tail[index] = message[complete_bytes + index];
    }
    tail[remaining] = 0x80;
    const std::size_t padded_size = remaining < 56 ? 64 : 128;
    const std::uint64_t bit_length = static_cast<std::uint64_t>(message.size()) * 8;
    for (std::size_t byte = 0; byte < 8; ++byte) {
        tail[padded_size - 1 - byte] = static_cast<std::uint8_t>(bit_length >> (8 * byte));
    }
    for (std::size_t offset = 0; offset < padded_size; offset += 64) {
        state =
            gsa_hash_compress(state, std::span<const std::uint8_t, 64>(tail.data() + offset, 64));
    }
    GsaHashDigest digest{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            digest[index * 4 + byte] = static_cast<std::uint8_t>(state[index] >> (24 - 8 * byte));
        }
    }
    return digest;
}

GsaHashMaterial derive_gsa_hash_material(std::span<const std::uint8_t, 32> seed,
                                         std::uint32_t counter) {
    const auto seed_hash = gsa_hash(seed);
    const auto expanded = expand_arithmetic_digest(seed_hash);
    const auto counter_message = store_counter_message(seed, counter);
    return {seed_hash, gsa_hash(expanded), gsa_hash(counter_message)};
}

AesBlock generate_gsa_otp(std::span<const std::uint8_t, 32> seed,
                          std::uint32_t counter,
                          std::span<const std::uint8_t, 16> device_key) {
    const auto material = derive_gsa_hash_material(seed, counter);
    return compute_otp_mac({material.seed_hash, material.expanded_hash, material.counter_hash},
                           device_key);
}

} // namespace apple_auth::detail
