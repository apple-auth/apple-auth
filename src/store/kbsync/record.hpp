#pragma once
#include "entropy.hpp"
#include "store/data/arithmetic.hpp"
#include "store/data/record.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace apple_auth::detail::kbsync {

struct RecordFields {
    std::array<std::uint32_t, 22> words;
};

inline std::array<std::uint8_t, 16>
select_record_trailer(std::span<const std::uint8_t, 144> state) {
    const std::size_t offset = state[0] % 111u;
    std::array<std::uint8_t, 16> result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = state[offset + index];
    }
    return result;
}

inline std::array<std::uint8_t, 176>
assemble_record(const RecordFields& fields,
                std::span<const std::uint8_t, 48> payload,
                std::span<const std::uint8_t, 144> random_state) {
    std::array<std::uint8_t, 176> logical{};
    logical[3] = 156;
    for (std::size_t index = 0; index < fields.words.size(); ++index) {
        const auto word = fields.words[index];
        const auto offset = record_word_offsets[index];
        for (std::size_t byte = 0; byte < 4; ++byte) {
            logical[offset + byte] = static_cast<std::uint8_t>(word >> (24 - 8 * byte));
        }
    }
    logical[28] = 1;
    logical[41] = 2;
    logical[110] = 1;
    logical[119] = 1;
    for (std::size_t index = 0; index < payload.size(); ++index) {
        logical[54 + index] = payload[index];
    }
    const auto trailer = select_record_trailer(random_state);
    for (std::size_t index = 0; index < trailer.size(); ++index) {
        logical[144 + index] = trailer[index];
    }
    for (auto& byte : logical) {
        byte ^= record_values[0];
    }
    return logical;
}

struct RecordSample {
    std::array<std::uint8_t, 176> source;
    std::size_t entropy_consumed;
};

inline std::optional<RecordSample> sample_record(const RecordFields& fields,
                                                 std::span<const std::uint8_t> entropy) {
    const auto state = sample_nonzero<144>(entropy);
    if (!state) {
        return std::nullopt;
    }
    const auto payload = sample_nonzero<48>(entropy.subspan(state->consumed));
    if (!payload) {
        return std::nullopt;
    }
    return RecordSample{assemble_record(fields, payload->bytes, state->bytes),
                        state->consumed + payload->consumed};
}

} // namespace apple_auth::detail::kbsync
