#pragma once
#include "context.hpp"
#include "inner_cipher.hpp"
#include "mac.hpp"
#include "prehash.hpp"
#include "record.hpp"
#include "store/data/arithmetic.hpp"
#include "store/data/packet.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace apple_auth::detail::kbsync {

struct PacketInputs {
    std::array<std::uint8_t, 176> source;
    AesBlock iv;
    AesBlock input_whitening;
    AesBlock output_whitening;
};

inline std::array<std::uint8_t, 212> assemble_packet(std::uint64_t dsid,
                                                     std::span<const std::uint8_t> hardware,
                                                     std::span<const std::uint8_t, 12> context,
                                                     const PacketInputs& inputs) {
    const auto key = derive_inner_key(dsid, hardware, context);
    const auto cipher = encrypt_inner176(
        inputs.source, {key, inputs.iv, inputs.input_whitening, inputs.output_whitening});
    std::array<std::uint8_t, 212> packet{};
    packet[1] = 4;
    packet[3] = 3;
    for (std::size_t index = 0; index < context.size(); ++index) {
        packet[4 + index] = context[index];
    }
    for (std::size_t index = 0; index < cipher.size(); ++index) {
        packet[16 + index] = static_cast<std::uint8_t>(cipher[index] ^ packet_values[0]);
    }
    const auto mac = compute_mac192(std::span<const std::uint8_t, 192>(packet.data(), 192), key);
    for (std::size_t index = 0; index < mac.size(); ++index) {
        packet[192 + index] = mac[index];
    }
    return packet;
}

inline std::array<std::uint8_t, 212> assemble_packet(std::uint64_t dsid,
                                                     std::span<const std::uint8_t> hardware,
                                                     std::span<const std::uint8_t, 12> context,
                                                     std::span<const std::uint8_t, 176> source) {
    PacketInputs inputs{};
    for (std::size_t index = 0; index < source.size(); ++index) {
        inputs.source[index] = source[index];
    }
    inputs.iv = packet_iv;
    inputs.input_whitening = packet_input_whitening;
    inputs.output_whitening = packet_output_whitening;
    return assemble_packet(dsid, hardware, context, inputs);
}

struct PacketSample {
    std::array<std::uint8_t, 212> bytes;
    std::size_t entropy_consumed;
};

inline std::optional<PacketSample>
assemble_packet_with_entropy(std::uint64_t dsid,
                             std::span<const std::uint8_t> hardware,
                             std::span<const std::uint8_t, 176> source,
                             std::span<const std::uint8_t> entropy) {
    const auto context = sample_context(entropy);
    if (!context) {
        return std::nullopt;
    }
    return PacketSample{assemble_packet(dsid, hardware, context->bytes, source), context->consumed};
}

inline std::optional<PacketSample>
assemble_packet_with_fields(std::uint64_t dsid,
                            std::span<const std::uint8_t> hardware,
                            const RecordFields& fields,
                            std::span<const std::uint8_t> entropy) {
    const auto record = sample_record(fields, entropy);
    if (!record) {
        return std::nullopt;
    }
    auto packet = assemble_packet_with_entropy(
        dsid, hardware, record->source, entropy.subspan(record->entropy_consumed));
    if (!packet) {
        return std::nullopt;
    }
    packet->entropy_consumed += record->entropy_consumed;
    return packet;
}

} // namespace apple_auth::detail::kbsync
