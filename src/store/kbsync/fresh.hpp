#pragma once
#include "packet.hpp"
#include "store/data/arithmetic.hpp"
#include "store/data/record.hpp"
#include <bit>
#include <stdexcept>

namespace apple_auth::detail::kbsync {

inline std::uint32_t padded_integer(std::uint32_t value, std::uint32_t random) {
    const auto width = value == 0 ? 1u : static_cast<unsigned>(std::bit_width(value));
    if (width > 27) {
        throw std::invalid_argument("Record integer exceeds27-bit profile");
    }
    return ((random << width) & fresh_values[0]) | (width << 27) | value;
}

inline std::uint32_t load_big32(std::span<const std::uint8_t, 4> source) {
    std::uint32_t word = 0;
    for (const auto byte : source) {
        word = (word << 8) | byte;
    }
    return word;
}

inline RecordFields fresh_record_fields(std::span<const std::uint8_t, 32> randomness) {
    RecordFields fields{};
    for (std::size_t index = 0; index < record_word_offsets.size(); ++index) {
        const auto offset = record_word_offsets[index];
        for (std::size_t fixed = 0; fixed < fixed_record_offsets.size(); ++fixed) {
            if (fixed_record_offsets[fixed] == offset) {
                fields.words[index] = fixed_record_words[fixed];
            }
        }
        for (std::size_t padded = 0; padded < padded_record_offsets.size(); ++padded) {
            if (padded_record_offsets[padded] == offset) {
                fields.words[index] = padded_integer(padded_record_values[padded],
                                                     load_big32(std::span<const std::uint8_t, 4>(
                                                         randomness.data() + 4 * padded, 4)));
            }
        }
        if (offset == 50) {
            fields.words[index] = load_big32(randomness.template subspan<28, 4>());
        }
    }
    return fields;
}

inline std::optional<PacketSample> generate_packet(std::uint64_t dsid,
                                                   std::span<const std::uint8_t> hardware,
                                                   std::span<const std::uint8_t> entropy) {
    if (dsid == 0) {
        throw std::invalid_argument("Expected nonzero account DSID");
    }
    const auto state = sample_nonzero<144>(entropy);
    if (!state) {
        return std::nullopt;
    }
    const auto payload = sample_nonzero<48>(entropy.subspan(state->consumed));
    if (!payload) {
        return std::nullopt;
    }
    const auto random_offset = state->consumed + payload->consumed;
    if (entropy.size() - random_offset < 32) {
        return std::nullopt;
    }
    const auto fields =
        fresh_record_fields(std::span<const std::uint8_t, 32>(entropy.data() + random_offset, 32));
    const auto source = assemble_record(fields, payload->bytes, state->bytes);
    auto packet =
        assemble_packet_with_entropy(dsid, hardware, source, entropy.subspan(random_offset + 32));
    if (!packet) {
        return std::nullopt;
    }
    packet->entropy_consumed += random_offset + 32;
    return packet;
}

} // namespace apple_auth::detail::kbsync
