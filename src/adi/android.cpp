#include "adi/data/android_hash_data.hpp"
#include "adi/data/android_profile_data.hpp"
#include "adi/internal.hpp"

namespace apple_auth::detail {

SecondaryCipherParameters android_secondary_cipher_parameters() {
    const auto& data = android_profile_data::secondary_cipher;
    SecondaryCipherParameters parameters{};
    std::copy_n(data.begin(), 16, parameters.key.begin());
    std::copy_n(data.begin() + 16, 16, parameters.iv.begin());
    std::copy_n(data.begin() + 32, 16, parameters.whitening.begin());
    for (std::size_t map = 0; map < 4; ++map) {
        std::copy_n(data.begin() + 48 + map * 8, 8, parameters.output_maps[map].basis.begin());
    }
    return parameters;
}

std::array<std::uint8_t, 384> mix_android_key_state(std::span<const std::uint8_t, 384> input) {
    std::array<std::uint8_t, 384> state{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = input[index] ^ 0x46;
    }
    auto feedback = static_cast<std::uint8_t>(state[378] + state[286] + state[106] + state[93]);
    state[74] = static_cast<std::uint8_t>(state[74] - feedback);
    for (const auto destination : android_profile_data::mixing_positions) {
        auto& value = state[destination];
        switch (feedback & 3) {
        case 0:
            value = static_cast<std::uint8_t>(value + feedback);
            break;
        case 1:
            value = static_cast<std::uint8_t>(value - feedback);
            break;
        case 2:
            value ^= feedback;
            break;
        default:
            break;
        }
        feedback = static_cast<std::uint8_t>((feedback ^ value) + 0x1B);
    }
    for (auto& value : state) {
        value ^= 0x46;
    }
    return state;
}

AesBlock decode_android_final_round_key(std::span<const std::uint8_t, 384> mixed_state) {
    const LinearByteMap map{android_profile_data::key_map};
    auto key = android_profile_data::key_offsets;
    for (std::size_t index = 0; index < key.size(); ++index) {
        const auto& sources = android_profile_data::key_sources[index];
        key[index] ^=
            mixed_state[sources[0]] ^ map.apply(mixed_state[sources[1]] ^ mixed_state[sources[2]]);
    }
    return key;
}

AesBlock decode_android_device_key(std::span<const std::uint8_t, 384> opaque_state) {
    const auto decoded = decode_gsa_secondary(opaque_state, android_secondary_cipher_parameters());
    const auto mixed =
        mix_android_key_state(std::span<const std::uint8_t, 384>(decoded.data(), 384));
    return recover_aes128_key(decode_android_final_round_key(mixed));
}

using AndroidHashState = std::array<std::uint32_t, 8>;
using AndroidHashDigest = std::array<std::uint8_t, 32>;

AndroidHashState
android_hash_round(const AndroidHashState& state, std::uint32_t message, std::uint32_t constant) {
    const auto [a, b, c, d, e, f, g, h] = state;
    const auto sigma_e = std::rotr(e, 25) - std::rotr(e, 6) - std::rotr(e, 11);
    const auto mixed_efg = (e + g) ^ (e + f) ^ g;
    const auto first = h + sigma_e + mixed_efg + message + constant;
    const auto sigma_a = (std::rotr(a, 2) - std::rotr(a, 13)) ^ std::rotr(a, 22);
    const auto mixed_abc = (b ^ c) + ((a ^ b) ^ (a + c));
    const auto second = sigma_a ^ mixed_abc;
    return {first + second, a, b, c, d + first, e, f, g};
}

std::uint32_t android_hash_schedule_word(std::uint32_t oldest,
                                         std::uint32_t fifteen,
                                         std::uint32_t seven,
                                         std::uint32_t two) {
    const auto first = (std::rotr(fifteen, 7) ^ std::rotr(fifteen, 18)) + (fifteen >> 3);
    const auto second = (std::rotr(two, 17) - std::rotr(two, 19)) ^ (two >> 10);
    return (first ^ seven ^ second) - oldest;
}

AndroidHashState android_hash_compress(const AndroidHashState& initial,
                                       std::span<const std::uint8_t, 64> block) {
    std::array<std::uint32_t, 64> words{};
    for (std::size_t index = 0; index < 16; ++index) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            words[index] = (words[index] << 8) | block[index * 4 + byte];
        }
    }
    for (std::size_t index = 16; index < words.size(); ++index) {
        words[index] = android_hash_schedule_word(
            words[index - 16], words[index - 15], words[index - 7], words[index - 2]);
    }
    auto state = initial;
    for (std::size_t index = 0; index < words.size(); ++index) {
        state = android_hash_round(state, words[index], android_hash_data::round_constants[index]);
    }
    return {state[0] - initial[0],
            state[1] + initial[1],
            state[2] + initial[2],
            state[3] + initial[3],
            state[4] ^ initial[4],
            state[5] - initial[5],
            state[6] + initial[6],
            state[7] ^ initial[7]};
}

AndroidHashDigest android_hash(std::span<const std::uint8_t> message) {
    auto state = android_hash_data::initial_state;
    const auto complete = message.size() - message.size() % 64;
    for (std::size_t offset = 0; offset < complete; offset += 64) {
        state = android_hash_compress(
            state, std::span<const std::uint8_t, 64>(message.data() + offset, 64));
    }
    std::array<std::uint8_t, 128> tail{};
    const auto remaining = message.size() - complete;
    std::copy_n(message.begin() + complete, remaining, tail.begin());
    tail[remaining] = 0x80;
    const std::size_t padded = remaining < 56 ? 64 : 128;
    const auto bit_length = static_cast<std::uint64_t>(message.size()) * 8;
    for (std::size_t byte = 0; byte < 8; ++byte) {
        tail[padded - 1 - byte] = static_cast<std::uint8_t>(bit_length >> (byte * 8));
    }
    for (std::size_t offset = 0; offset < padded; offset += 64) {
        state = android_hash_compress(state,
                                      std::span<const std::uint8_t, 64>(tail.data() + offset, 64));
    }
    AndroidHashDigest digest{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            digest[index * 4 + byte] = static_cast<std::uint8_t>(state[index] >> (24 - byte * 8));
        }
    }
    return digest;
}

AesBlock generate_android_otp(std::span<const std::uint8_t, 32> seed,
                              std::uint32_t counter,
                              std::span<const std::uint8_t, 16> device_key) {
    const auto seed_hash = android_hash(seed);
    return compute_otp_mac({seed_hash,
                            android_hash(expand_arithmetic_digest(seed_hash)),
                            android_hash(store_counter_message(seed, counter))},
                           device_key);
}

} // namespace apple_auth::detail
