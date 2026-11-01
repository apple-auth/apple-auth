#include "adi/data/tables.hpp"
#include "adi/internal.hpp"

namespace apple_auth::detail {

FileKeyPreparedBuffer prepare_file_key_buffer(std::span<const std::uint8_t, 20> hardware_digest,
                                              std::span<const std::uint8_t> prefix,
                                              std::optional<std::uint32_t> binding_word) {
    if (prefix.size() > 227) {
        throw std::invalid_argument("File-key prefix exceeds the prepared buffer capacity");
    }
    auto prepared = file_key_preparation_base;
    for (std::size_t index = 0; index < hardware_digest.size(); ++index) {
        prepared[index] ^= hardware_digest[index];
    }
    for (std::size_t index = 0; index < prefix.size(); ++index) {
        prepared[hardware_digest.size() + index] ^= prefix[index];
    }
    if (binding_word) {
        const std::uint32_t binding = *binding_word * 0x01000193U + 0x5FD5F5E1U;
        for (std::size_t index = 0; index < 4; ++index) {
            prepared[index] ^= static_cast<std::uint8_t>(binding >> (24 - 8 * index));
        }
    }
    return prepared;
}

std::vector<std::uint8_t> prepare_file_key_input(std::span<const std::uint8_t, 20> hardware_digest,
                                                 std::span<const std::uint8_t> prefix,
                                                 std::optional<std::uint32_t> binding_word) {
    const auto prepared = prepare_file_key_buffer(hardware_digest, prefix, binding_word);
    // Hardware (20), prefix, and eight further bytes of the fixed template.
    return {prepared.begin(), prepared.begin() + 28 + prefix.size()};
}

FileKeyPreparedBuffer
assemble_file_key_md5_message(std::span<const std::uint8_t, 20> hardware_digest,
                              std::span<const std::uint8_t> prefix,
                              std::span<const std::uint8_t, 16> reduced,
                              std::optional<std::uint32_t> binding_word) {
    auto message = prepare_file_key_buffer(hardware_digest, prefix, binding_word);
    for (std::size_t index = 0; index < message.size(); ++index) {
        message[index] ^= file_key_input_to_hash_mask[index % 16];
    }
    for (std::size_t index = 0; index < reduced.size(); ++index) {
        message[index] = reduced[index] ^ file_key_reduction_to_hash_mask[index];
    }
    return message;
}

FileKeyDiffusionState mix_file_key_state(FileKeyDiffusionState state, std::uint32_t steps) {
    constexpr std::uint32_t state_size = 319;
    if (steps > 4 * state_size) {
        throw std::invalid_argument("File-key diffusion step count exceeds four passes");
    }
    for (std::uint32_t step = 0; step < steps; ++step) {
        const auto first =
            state[step % state_size] ^ std::rotl(state[(step - 13U) % state_size], 3);
        const auto second = std::rotl(state[(step - 57U) % state_size], 5);
        const auto third = std::rotl(state[(step - 155U) % state_size], 7);
        state[step % state_size] = static_cast<std::uint8_t>(first + second - third);
    }
    return state;
}

FileKeyDiffusionState diffuse_file_key_input(std::span<const std::uint8_t> input) {
    if (input.empty()) {
        throw std::invalid_argument("File-key diffusion needs a nonempty input");
    }
    FileKeyDiffusionState state{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = input[index % input.size()];
    }
    return mix_file_key_state(state);
}

void fold_file_key_bytes(std::span<std::uint8_t> input, std::span<const std::uint8_t> values) {
    if (input.empty()) {
        throw std::invalid_argument("File-key folding needs a nonempty input");
    }
    for (std::size_t index = 0; index < values.size(); ++index) {
        input[index % input.size()] ^= values[index];
    }
}

void mix_file_key_input(std::span<std::uint8_t> input, std::uint32_t steps) {
    if (input.empty() || input.size() > UINT32_MAX || steps > 256) {
        throw std::invalid_argument("Invalid file-key input size or mixing step count");
    }
    const auto size = static_cast<std::uint32_t>(input.size());
    for (std::uint32_t step = 0; step < steps; ++step) {
        const auto first = std::rotl(input[(step - 7U) % size], 1);
        const auto second = std::rotl(input[(step - 37U) % size], 6);
        const auto third = std::rotl(input[(step - 177U) % size], 5);
        input[step % size] ^= static_cast<std::uint8_t>(first ^ second ^ third);
    }
}

void reduce_file_key_state(std::span<std::uint8_t> input,
                           std::span<const std::uint8_t, 319> state,
                           std::span<const std::uint8_t, 128> tables) {
    fold_file_key_bytes(input, tables.first<64>());
    fold_file_key_bytes(input, tables.last<64>());
    fold_file_key_bytes(input, state);
    mix_file_key_input(input);
}

Md5Digest derive_state_file_tag_key(std::span<const std::uint8_t, 16> first_stage_digest) {
    auto message = state_file_tag_key_base_message;
    for (std::size_t index = 0; index < first_stage_digest.size(); ++index) {
        message[16 + index] ^= first_stage_digest[index];
    }
    return md5(message);
}

Md5Digest derive_file_key_digest(std::span<const std::uint8_t, 20> hardware_digest,
                                 std::span<const std::uint8_t> prefix,
                                 std::optional<std::uint32_t> binding_word) {
    const auto prepared = prepare_file_key_input(hardware_digest, prefix, binding_word);
    auto nonlinear =
        mutate_file_key_state(diffuse_file_key_input(prepared), file_key_initial_tables);
    reduce_file_key_state(nonlinear.input, nonlinear.state, nonlinear.tables);
    const auto message =
        assemble_file_key_md5_message(hardware_digest, prefix, nonlinear.input, binding_word);
    return md5(message);
}

AesBlock derive_state_file_body_key(std::span<const std::uint8_t, 16> first_stage_digest,
                                    const StateBodyKeyParameters& parameters) {
    AesBlock input{};
    for (std::size_t index = 0; index < input.size(); ++index) {
        input[index] = first_stage_digest[index] ^ parameters.input_whitening[index];
    }
    auto key = encrypt_aes128_block(input, expand_aes128_key(parameters.program_key));
    for (std::size_t index = 0; index < key.size(); ++index) {
        key[index] ^= parameters.output_whitening[index];
    }
    return key;
}
} // namespace apple_auth::detail
