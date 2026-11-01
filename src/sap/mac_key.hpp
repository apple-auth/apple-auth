#pragma once
#include "crypto.hpp"
#include "data_mask.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>

namespace apple_auth::detail::sap {

using MacWord = std::array<std::uint8_t, 4>;
using ByteLinearMap = std::array<std::uint8_t, 8>;

struct MacKeyRoundParameters {
    std::array<ByteLinearMap, 4> word_columns;
    std::array<ByteLinearMap, 4> pair_columns;
    MacWord constant;
};

struct MacKeyParameters {
    MacWord word_bias;
    std::array<MacKeyRoundParameters, 8> rounds;
};

inline std::uint8_t apply_byte_linear_map(const ByteLinearMap& columns, std::uint8_t value) {
    std::uint8_t result = 0;
    for (unsigned bit = 0; bit < 8; ++bit) {
        if ((value >> bit) & 1U) {
            result ^= columns[bit];
        }
    }
    return result;
}

// The 36 stored words precede the per-round share transformation.
inline std::array<std::uint8_t, 144> mac_raw_round_words(std::span<const std::uint8_t> field,
                                                         const MacWord& bias) {
    if (field.size() != 576) {
        throw std::invalid_argument("Expected SAP MAC field576");
    }
    static const auto sources = data_mask::decode(
        std::array<std::array<unsigned, 4>, 9>{
            {{0xCAFBC44FU, 0xF4F990F0U, 0x1E29215FU, 0x7EDC7178U},
             {0xECF1B930U, 0xA9F98C75U, 0x929A4ABAU, 0xA6F42BB2U},
             {0x55BF0692U, 0x102BDAE2U, 0x0193E6C5U, 0xD4A07196U},
             {0x8EABF53EU, 0xF9702976U, 0x759C6DD5U, 0xFC640C78U},
             {0xC6DE539CU, 0x9D754D2FU, 0xACC6CE83U, 0xD76111FEU},
             {0x58C87140U, 0x8E99BD1DU, 0x9C43612CU, 0xFC003D21U},
             {0x87AE3FF8U, 0x4E31C575U, 0xA75509EEU, 0xC9238017U},
             {0x95906D8CU, 0x98463391U, 0x9C178A0DU, 0xC5D71963U},
             {0xF13169A5U, 0x58917173U, 0xA5EEC8C2U, 0xE0537114U}}},
        0xCDB96721U);
    std::array<std::uint8_t, 144> result{};
    for (unsigned round = 0; round < 9; ++round) {
        for (unsigned word = 0; word < 4; ++word) {
            for (unsigned byte = 0; byte < 4; ++byte) {
                result[16 * round + 4 * word + byte] =
                    field[sources[round][word] + byte] ^
                    field[208 + 4 * ((round + word) % 4) + byte] ^ bias[byte];
            }
        }
    }
    return result;
}

// Recover AES-128 from one word per round K9..K2; validate redundant words.
inline ::apple_auth::detail::AesBlock
recover_mac_key_from_second_words(const std::array<MacWord, 8>& observed) {
    static const auto rcon = data_mask::decode(
        std::array<std::uint8_t, 11>{
            0x73, 0xBA, 0xEF, 0x9A, 0x78, 0xA0, 0xE2, 0x02, 0xCF, 0xF1, 0x7F},
        0xAE31BAA1U);
    std::array<MacWord, 10> second{}, first{};
    for (unsigned i = 0; i < observed.size(); ++i) {
        second[9 - i] = observed[i];
    }
    for (unsigned round = 3; round <= 9; ++round) {
        for (unsigned byte = 0; byte < 4; ++byte) {
            first[round][byte] = second[round][byte] ^ second[round - 1][byte];
        }
    }
    auto last = [&](unsigned round) {
        MacWord difference{};
        for (unsigned byte = 0; byte < 4; ++byte) {
            difference[byte] = first[round + 1][byte] ^ first[round][byte];
        }
        return MacWord{aes_inverse_sbox[difference[3]],
                       aes_inverse_sbox[difference[0] ^ rcon[round + 1]],
                       aes_inverse_sbox[difference[1]],
                       aes_inverse_sbox[difference[2]]};
    };
    ::apple_auth::detail::AesBlock current{};
    const auto last3 = last(3), last4 = last(4);
    for (unsigned byte = 0; byte < 4; ++byte) {
        current[byte] = first[4][byte];
        current[4 + byte] = second[4][byte];
        current[8 + byte] = last4[byte] ^ last3[byte];
        current[12 + byte] = last4[byte];
    }
    for (unsigned round = 4; round != 0; --round) {
        ::apple_auth::detail::AesBlock previous{};
        for (unsigned byte = 4; byte < 16; ++byte) {
            previous[byte] = current[byte] ^ current[byte - 4];
        }
        const MacWord transformed{static_cast<std::uint8_t>(aes_sbox[previous[13]] ^ rcon[round]),
                                  aes_sbox[previous[14]],
                                  aes_sbox[previous[15]],
                                  aes_sbox[previous[12]]};
        for (unsigned byte = 0; byte < 4; ++byte) {
            previous[byte] = current[byte] ^ transformed[byte];
        }
        current = previous;
    }
    const auto schedule = ::apple_auth::detail::expand_aes128_key(current);
    for (unsigned i = 0; i < observed.size(); ++i) {
        if (!std::equal(observed[i].begin(), observed[i].end(), schedule[9 - i].begin() + 4)) {
            throw std::invalid_argument(
                "Prepared SAP material does not form an AES-128 key schedule");
        }
    }
    return current;
}

inline ::apple_auth::detail::AesBlock recover_mac_key(std::span<const std::uint8_t> field,
                                                      std::span<const std::uint8_t> prepared_pool,
                                                      const MacKeyParameters& parameters) {
    if (prepared_pool.size() != 576) {
        throw std::invalid_argument("Expected prepared SAP pool576");
    }
    static const auto offsets = data_mask::decode(std::array<unsigned, 8>{0x26726701U,
                                                                          0x3CFC1868U,
                                                                          0x411FB363U,
                                                                          0x5B9686F0U,
                                                                          0xE040B80CU,
                                                                          0x1E233CD9U,
                                                                          0x4EBC2065U,
                                                                          0x9FB45A11U},
                                                  0x1FF97A7AU);
    static const auto pairs = data_mask::decode(
        std::array<unsigned, 4>{0x20245648U, 0xF75DE47AU, 0x3182B3F8U, 0x9860E1A3U}, 0x41C91EC4U);
    static const auto rows = data_mask::decode(
        std::array<unsigned, 4>{0x6FF17F1DU, 0x42493DB5U, 0xDA0A4608U, 0xCBA2A28CU}, 0x15D9BDAAU);
    const auto words = mac_raw_round_words(field, parameters.word_bias);
    std::array<MacWord, 8> observed{};
    for (unsigned round = 0; round < 8; ++round) {
        const auto& item = parameters.rounds[round];
        ::apple_auth::detail::AesBlock transformed{};
        for (unsigned byte = 0; byte < 4; ++byte) {
            transformed[byte] =
                apply_byte_linear_map(item.word_columns[byte], words[16 * (8 - round) + 4 + byte]);
        }
        aes_mix_columns(transformed);
        for (unsigned byte = 0; byte < 4; ++byte) {
            observed[round][byte] = transformed[byte] ^ item.constant[byte];
        }
        for (unsigned j = 0; j < 4; ++j) {
            const auto address = offsets[round] + 2 * pairs[j];
            const auto sum =
                static_cast<std::uint8_t>(prepared_pool[address] + prepared_pool[address + 1]);
            observed[round][rows[j]] ^= apply_byte_linear_map(item.pair_columns[j], sum);
        }
    }
    return recover_mac_key_from_second_words(observed);
}

using MacControlProgram = std::array<std::array<std::uint8_t, 11>, 16>;

inline MacControlProgram mac_control_program(std::span<const std::uint8_t> field) {
    if (field.size() != 576) {
        throw std::invalid_argument("Expected SAP MAC field576");
    }
    MacControlProgram program{};
    static const auto divisors = data_mask::decode(
        std::array<std::array<unsigned, 4>, 3>{
            {{0xE99AE4CCU, 0x15781711U, 0xE4B2C429U, 0x3A7919B2U},
             {0x31985ED5U, 0x723BBC40U, 0xB3B3CE14U, 0x84966891U},
             {0x783C0F1DU, 0xC2310D0EU, 0x91E00733U, 0xB1727C34U}}},
        0x622DDD6BU);
    static const auto widths =
        data_mask::decode(std::array<std::uint8_t, 4>{0x91, 0x45, 0xC1, 0x86}, 0xFBD688B2U);
    for (unsigned index = 0; index < 44; ++index) {
        const auto source = index < 32 ? 224 + index : 192 + index - 32;
        const auto value = field[source] ^ field[48 + index % 16];
        for (unsigned digit = 0; digit < 4; ++digit) {
            program[4 * (index % 4) + digit][index / 4] =
                widths[(value % divisors[index / 16][digit]) & 3];
        }
    }
    const unsigned seed = (field[193] ^ field[49]) & 15;
    for (unsigned column = 0; column < 11; ++column) {
        unsigned cost = 0;
        for (const auto& row : program) {
            cost += row[column];
        }
        for (unsigned row = seed; cost > 32; row = (row + 5) & 15) {
            cost -= program[row][column] - 1;
            program[row][column] = 1;
        }
    }
    return program;
}

// Replace address-encoded shares with (zero, sum).
// Each command folds 1, 3 or 5 source bytes.
inline std::array<std::uint8_t, 576> prepare_mac_pair_sums(std::span<const std::uint8_t> field,
                                                           std::span<const std::uint8_t> masks) {
    if (masks.size() != 2304) {
        throw std::invalid_argument("Expected SAP pair masks2304");
    }
    const auto program = mac_control_program(field);
    static const auto sources = data_mask::decode(std::array<unsigned, 9>{0xCF9469F4U,
                                                                          0x1567CB6BU,
                                                                          0x651136EEU,
                                                                          0x3BDA3AAEU,
                                                                          0xED775809U,
                                                                          0xCF81261EU,
                                                                          0x87F6C0FCU,
                                                                          0xA578B146U,
                                                                          0xDCBB19F9U},
                                                  0x5D79C17FU);
    static const auto outputs = data_mask::decode(std::array<unsigned, 9>{0xD082073FU,
                                                                          0x9490094DU,
                                                                          0x25BDAB2DU,
                                                                          0x88C8322DU,
                                                                          0x5F37785BU,
                                                                          0xB6FE4290U,
                                                                          0xA933D42EU,
                                                                          0xA7EDD68FU,
                                                                          0xBA7D3D62U},
                                                  0x1219AD03U);
    static const auto permutation = data_mask::decode(std::array<unsigned, 16>{0x4C013F00U,
                                                                               0x17C474D7U,
                                                                               0xB29D17BDU,
                                                                               0x1D312EE3U,
                                                                               0x2566013DU,
                                                                               0x4D7BA039U,
                                                                               0x16FF8CE8U,
                                                                               0x0B10751CU,
                                                                               0xB3F4CEA9U,
                                                                               0x6E16CCD6U,
                                                                               0x463314B4U,
                                                                               0xB0307B0AU,
                                                                               0x5569504DU,
                                                                               0x93507118U,
                                                                               0x33292A62U,
                                                                               0xDAF8CADBU},
                                                      0xB07AA984U);
    std::array<std::uint8_t, 576> pool{};
    for (unsigned stage = 0; stage < 9; ++stage) {
        unsigned cursor = 0;
        for (unsigned row = 0; row < 16; ++row) {
            const unsigned width = program[row][stage + 1];
            std::uint8_t value = 0x66;
            for (unsigned byte = 0; byte < width; ++byte) {
                value ^= field[sources[stage] + cursor + byte] ^
                         masks[256 * stage + 16 * row + ((cursor + byte) & 15)];
            }
            pool[outputs[stage] + 2 * permutation[row] + 1] = value;
            cursor += width;
        }
    }
    return pool;
}

inline ::apple_auth::detail::AesBlock
recover_mac_key_from_field(std::span<const std::uint8_t> field,
                           const MacKeyParameters& parameters,
                           std::span<const std::uint8_t> masks) {
    const auto pool = prepare_mac_pair_sums(field, masks);
    return recover_mac_key(field, pool, parameters);
}

} // namespace apple_auth::detail::sap
