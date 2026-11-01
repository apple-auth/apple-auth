#include "adi/data/tables.hpp"
#include "adi/internal.hpp"

namespace apple_auth::detail {
LinearByteMap invert_provisioning_byte_map(const LinearByteMap& map) {
    // Gaussian elimination on [matrix | identity], one byte per vector.
    std::array<std::uint16_t, 8> rows{};
    for (std::size_t row = 0; row < rows.size(); ++row) {
        rows[row] = static_cast<std::uint16_t>(1U << (8 + row));
        for (std::size_t column = 0; column < rows.size(); ++column) {
            if ((map.basis[column] & (1U << row)) != 0) {
                rows[row] |= static_cast<std::uint16_t>(1U << column);
            }
        }
    }
    for (std::size_t column = 0; column < rows.size(); ++column) {
        auto pivot = column;
        while (pivot < rows.size() && (rows[pivot] & (1U << column)) == 0) {
            ++pivot;
        }
        if (pivot == rows.size()) {
            throw std::invalid_argument("SPIM response input matrix is singular");
        }
        std::swap(rows[column], rows[pivot]);
        for (std::size_t row = 0; row < rows.size(); ++row) {
            if (row != column && (rows[row] & (1U << column)) != 0) {
                rows[row] ^= rows[column];
            }
        }
    }
    LinearByteMap inverse{};
    for (std::size_t column = 0; column < rows.size(); ++column) {
        for (std::size_t row = 0; row < rows.size(); ++row) {
            if ((rows[row] & (1U << (8 + column))) != 0) {
                inverse.basis[column] |= static_cast<std::uint8_t>(1U << row);
            }
        }
    }
    return inverse;
}

std::array<LinearByteMap, 4>
decode_provisioning_response_input_matrices(std::span<const std::uint8_t, 64> encoded,
                                            const ProvisioningResponseKeyParameters& parameters) {
    std::array<LinearByteMap, 4> result{};
    for (std::size_t matrix = 0; matrix < result.size(); ++matrix) {
        const auto& codec = parameters.input_matrix_codecs[matrix];
        auto& basis = result[matrix].basis;
        basis = codec.basis_offset;
        for (const auto& column : codec.columns) {
            if (column.source_byte >= encoded.size()) {
                throw std::invalid_argument("SPIM matrix codec has an invalid source byte");
            }
            const auto image = column.column_map.apply(encoded[column.source_byte]);
            for (std::size_t bit = 0; bit < basis.size(); ++bit) {
                if ((column.row_mask & (1U << bit)) != 0) {
                    basis[bit] ^= image;
                }
            }
        }
    }
    return result;
}

Aes128Schedule
decode_provisioning_response_round_keys(std::span<const std::uint8_t, 240> material,
                                        const ProvisioningResponseKeyParameters& parameters) {
    const auto matrices = decode_provisioning_response_input_matrices(
        std::span<const std::uint8_t, 64>(material.data() + 176, 64), parameters);
    std::array<LinearByteMap, 4> inverse_matrices{};
    for (std::size_t matrix = 0; matrix < matrices.size(); ++matrix) {
        inverse_matrices[matrix] = invert_provisioning_byte_map(matrices[matrix]);
    }
    Aes128Schedule schedule{};
    for (std::size_t position = 0; position < parameters.round_key_masks.size(); ++position) {
        const auto row = position % 4;
        const auto encoded = parameters.encoded_key_maps[row].apply(material[position]) ^
                             parameters.round_key_masks[position];
        schedule[position / 16][position % 16] = parameters.decoded_key_maps[row].apply(
            inverse_matrices[row].apply(static_cast<std::uint8_t>(encoded)));
    }
    if (schedule != expand_aes128_key(schedule[0])) {
        throw std::invalid_argument("SPIM response round keys do not form an AES-128 schedule");
    }
    return schedule;
}

AesBlock decode_provisioning_response_key(std::span<const std::uint8_t, 240> material,
                                          const ProvisioningResponseKeyParameters& parameters) {
    return decode_provisioning_response_round_keys(material, parameters)[0];
}

std::array<std::uint8_t, 240>
decode_provisioning_spim_material(std::span<const std::uint8_t, 240> ciphertext,
                                  const ProvisioningSpimParameters& parameters) {
    const auto schedule = expand_aes128_key(parameters.key);
    auto previous = parameters.iv;
    std::array<std::uint8_t, 240> output{};
    for (std::size_t offset = 0; offset < output.size(); offset += 16) {
        AesBlock block{};
        std::copy_n(ciphertext.begin() + offset, block.size(), block.begin());
        const auto decrypted = decrypt_aes128_block(block, schedule);
        for (std::size_t index = 0; index < block.size(); ++index) {
            output[offset + index] = decrypted[index] ^ previous[index];
        }
        previous = block;
    }
    return output;
}

AesBlock derive_provisioning_end_payload_key(std::span<const std::uint8_t, 240> spim_ciphertext,
                                             std::span<const std::uint8_t, 16> trust_key,
                                             const ProvisioningEndParameters& parameters) {
    const auto material = decode_provisioning_spim_material(spim_ciphertext, parameters.spim);
    const auto response_key = decode_provisioning_response_key(material, parameters.response_key);
    AesBlock trust_key_block{};
    std::copy(trust_key.begin(), trust_key.end(), trust_key_block.begin());
    const auto intermediate =
        encrypt_aes128_block(trust_key_block, expand_aes128_key(response_key));
    return encrypt_aes128_block(intermediate, expand_aes128_key(parameters.key_derivation_key));
}

std::array<std::uint8_t, 256>
decrypt_provisioning_end_payload(std::span<const std::uint8_t, 256> ciphertext,
                                 std::span<const std::uint8_t, 16> key,
                                 std::span<const std::uint8_t, 16> iv) {
    const auto schedule = expand_aes128_key(key);
    AesBlock previous{};
    std::copy(iv.begin(), iv.end(), previous.begin());
    std::array<std::uint8_t, 256> plaintext{};
    for (std::size_t offset = 0; offset < plaintext.size(); offset += previous.size()) {
        AesBlock block{};
        std::copy_n(ciphertext.begin() + offset, block.size(), block.begin());
        const auto decoded = decrypt_aes128_block(block, schedule);
        for (std::size_t index = 0; index < block.size(); ++index) {
            plaintext[offset + index] = decoded[index] ^ previous[index];
        }
        previous = block;
    }
    return plaintext;
}

std::array<std::uint8_t, 256>
decrypt_provisioning_end_payload_from_spim(std::span<const std::uint8_t, 240> spim_ciphertext,
                                           std::span<const std::uint8_t, 256> ciphertext,
                                           std::span<const std::uint8_t, 16> trust_key,
                                           std::span<const std::uint8_t, 16> iv,
                                           const ProvisioningEndParameters& parameters) {
    const auto key = derive_provisioning_end_payload_key(spim_ciphertext, trust_key, parameters);
    return decrypt_provisioning_end_payload(ciphertext, key, iv);
}

std::uint32_t read_provisioning_end_word(std::span<const std::uint8_t, 4> bytes) {
    std::uint32_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | byte;
    }
    return value;
}

Sha1Digest transform_provisioning_end_digest(Sha1Digest digest, const AesBlock& key) {
    AesBlock block{};
    std::copy_n(digest.begin(), block.size(), block.begin());
    const auto encrypted = encrypt_aes128_block(block, expand_aes128_key(key));
    std::copy(encrypted.begin(), encrypted.end(), digest.begin());
    return digest;
}

bool has_provisioning_end_packet_format(std::span<const std::uint8_t> packet) {
    if (packet.size() != 311 && packet.size() != 375 && packet.size() != 487 &&
        packet.size() != 503) {
        return false;
    }
    const auto version =
        read_provisioning_end_word(std::span<const std::uint8_t, 4>(packet.data(), 4));
    const auto payload_size =
        read_provisioning_end_word(std::span<const std::uint8_t, 4>(packet.data() + 20, 4));
    const auto marker = read_provisioning_end_word(
        std::span<const std::uint8_t, 4>(packet.data() + packet.size() - 31, 4));
    return version == 4 && payload_size == packet.size() - 55 && marker == 0xED9281D8U;
}

Sha1Digest compute_provisioning_end_packet_tag(std::span<const std::uint8_t> packet,
                                               const AesBlock& key) {
    if (packet.size() != 311 && packet.size() != 375 && packet.size() != 487 &&
        packet.size() != 503) {
        throw std::invalid_argument("Unsupported PTM version-4 packet length");
    }
    return transform_provisioning_end_digest(sha1(packet.subspan(4, packet.size() - 31)), key);
}

bool verify_provisioning_end_packet(std::span<const std::uint8_t> packet, const AesBlock& key) {
    if (!has_provisioning_end_packet_format(packet)) {
        return false;
    }
    const auto expected = compute_provisioning_end_packet_tag(packet, key);
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < expected.size(); ++index) {
        difference |= expected[index] ^ packet[packet.size() - 27 + index];
    }
    return difference == 0;
}

std::vector<std::uint8_t>
decrypt_authenticated_provisioning_end_packet(std::span<const std::uint8_t, 240> spim_ciphertext,
                                              std::span<const std::uint8_t> packet,
                                              std::span<const std::uint8_t, 16> trust_key,
                                              const ProvisioningEndPacketParameters& parameters) {
    if (!verify_provisioning_end_packet(packet, parameters.authentication_key)) {
        throw std::invalid_argument("PTM packet framing or authentication is invalid");
    }
    const auto key =
        derive_provisioning_end_payload_key(spim_ciphertext, trust_key, parameters.payload);
    const auto schedule = expand_aes128_key(key);
    AesBlock previous{};
    std::copy_n(packet.begin() + 4, previous.size(), previous.begin());
    std::vector<std::uint8_t> plaintext(packet.size() - 55);
    for (std::size_t offset = 0; offset < plaintext.size(); offset += 16) {
        AesBlock block{};
        std::copy_n(packet.begin() + 24 + offset, block.size(), block.begin());
        const auto decoded = decrypt_aes128_block(block, schedule);
        for (std::size_t index = 0; index < block.size(); ++index) {
            plaintext[offset + index] = decoded[index] ^ previous[index];
        }
        previous = block;
    }
    return plaintext;
}

std::array<std::uint8_t, 160>
make_provisioning_body(std::span<const std::uint8_t, 32> encrypted_material,
                       std::span<const std::uint8_t, 20> device_tag,
                       const ProvisioningBodyEntropy& entropy,
                       std::int64_t dsid,
                       std::uint32_t unix_seconds,
                       std::uint32_t platform) {
    std::array<std::uint8_t, 160> body{};
    const auto write_word = [&body](std::size_t offset, std::uint32_t value) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            body[offset + byte] = static_cast<std::uint8_t>(value >> ((3 - byte) * 8));
        }
    };
    write_word(0, 32);
    std::copy(encrypted_material.begin(), encrypted_material.end(), body.begin() + 4);
    write_word(36, 32);
    std::copy(entropy.session_random.begin(), entropy.session_random.end(), body.begin() + 40);
    std::copy(device_tag.begin(), device_tag.end(), body.begin() + 72);
    std::copy(entropy.first_nonce.begin(), entropy.first_nonce.end(), body.begin() + 92);
    std::copy(entropy.second_nonce.begin(), entropy.second_nonce.end(), body.begin() + 112);
    const auto dsid_bits = static_cast<std::uint64_t>(dsid);
    for (std::size_t byte = 0; byte < 8; ++byte) {
        body[132 + byte] = static_cast<std::uint8_t>(dsid_bits >> ((7 - byte) * 8));
    }
    write_word(140, unix_seconds);
    write_word(144, platform);
    std::copy(entropy.padding.begin(), entropy.padding.end(), body.begin() + 148);
    return body;
}

std::array<std::uint8_t, 32>
encrypt_provisioning_input(std::span<const std::uint8_t, 32> input,
                           const ProvisioningCipherParameters& parameters) {
    const auto schedule = expand_aes128_key(parameters.key);
    auto previous = parameters.iv;
    std::array<std::uint8_t, 32> output{};
    for (std::size_t offset = 0; offset < input.size(); offset += 16) {
        AesBlock block{};
        for (std::size_t index = 0; index < block.size(); ++index) {
            block[index] = input[offset + index] ^ parameters.input_mask[index] ^ previous[index];
        }
        previous = encrypt_aes128_block(block, schedule);
        std::copy(previous.begin(), previous.end(), output.begin() + offset);
    }
    return output;
}

std::array<std::uint8_t, 276>
assemble_provisioning_cpim(std::span<const std::uint8_t, 16> nonce,
                           std::span<const std::uint8_t, 192> response,
                           std::span<const std::uint8_t, 60> echoed_server_field) {
    std::array<std::uint8_t, 276> packet{};
    packet[3] = 5;
    std::copy(nonce.begin(), nonce.end(), packet.begin() + 4);
    packet[23] = 160;
    std::copy(response.begin(), response.end(), packet.begin() + 24);
    std::copy(echoed_server_field.begin(), echoed_server_field.end(), packet.begin() + 216);
    return packet;
}

AesBlock decrypt_provisioning_digest_parameter(std::span<const std::uint8_t, 16> ciphertext,
                                               std::span<const std::uint8_t, 16> key) {
    AesBlock block{};
    std::copy(ciphertext.begin(), ciphertext.end(), block.begin());
    return decrypt_aes128_block(block, expand_aes128_key(key));
}

std::vector<std::uint8_t>
mix_provisioning_hardware_seed(std::span<const std::uint8_t> input,
                               std::span<const std::uint8_t, 128> parameters) {
    if (input.size() < 80 || input.size() > 256) {
        throw std::invalid_argument("Provisioning hardware seed must contain 80 to 256 bytes");
    }
    std::uint32_t length_sum = 11;
    for (std::size_t index = 0; index < input.size() + 172; ++index) {
        const auto decoded = static_cast<std::uint8_t>(input[index % input.size()] + 0x92);
        length_sum = (length_sum + 34U * (decoded % 41U)) % 41U;
    }
    std::vector<std::uint8_t> output(20 + length_sum, 0x87);
    std::array<std::uint8_t, 384> state{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = static_cast<std::uint8_t>(input[index % input.size()] + 0x92);
    }
    const auto wrapped_index = [](std::uint32_t index, std::uint32_t distance, std::size_t size) {
        return static_cast<std::uint32_t>(index - distance) % size;
    };
    for (std::uint32_t index = 0; index < 1536; ++index) {
        const auto first = state[wrapped_index(index, 13, state.size())];
        const auto second = state[wrapped_index(index, 57, state.size())];
        const auto third = state[wrapped_index(index, 155, state.size())];
        auto& value = state[index % state.size()];
        value = static_cast<std::uint8_t>((value ^ std::rotl(first, 3)) + std::rotl(second, 5) -
                                          std::rotl(third, 7));
    }
    provisioning_mixer_detail::adjust_hardware_mixer(state, output, parameters);
    for (std::size_t index = 0; index < state.size(); ++index) {
        output[index % output.size()] ^= state[index];
    }
    for (std::uint32_t index = 0; index < 256; ++index) {
        const auto first = output[wrapped_index(index, 7, output.size())];
        const auto second = output[wrapped_index(index, 37, output.size())];
        const auto third = output[wrapped_index(index, 177, output.size())];
        output[index % output.size()] ^=
            std::rotl(first, 1) ^ std::rotl(second, 6) ^ std::rotl(third, 5);
    }
    return output;
}

std::vector<std::uint8_t>
make_provisioning_hardware_seed(std::span<const std::uint8_t, 20> hardware_hash,
                                std::span<const std::uint8_t, 128> parameters) {
    std::uint32_t length_sum = 43;
    for (std::size_t index = 0; index < 146; ++index) {
        length_sum =
            (length_sum + 14U * (hardware_hash[index % hardware_hash.size()] % 177U)) % 177U;
    }
    std::vector<std::uint8_t> output(80 + length_sum, 0xE5);
    std::array<std::uint8_t, 384> state{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = hardware_hash[index % hardware_hash.size()];
    }
    const auto previous_index = [](std::size_t index, std::size_t distance, std::size_t size) {
        return (index + size - distance % size) % size;
    };
    for (std::size_t index = 0; index < 1536; ++index) {
        const auto first = state[previous_index(index, 13, state.size())];
        const auto second = state[previous_index(index, 57, state.size())];
        const auto third = state[previous_index(index, 155, state.size())];
        auto& value = state[index % state.size()];
        value = static_cast<std::uint8_t>((value ^ std::rotl(first, 3)) + std::rotl(second, 5) -
                                          std::rotl(third, 7));
    }
    provisioning_seed_detail::adjust_hardware_seed(state, output, parameters);
    for (std::size_t index = 0; index < state.size(); ++index) {
        output[index % output.size()] ^= state[index];
    }
    for (std::size_t index = 0; index < 256; ++index) {
        const auto first = output[previous_index(index, 7, output.size())];
        const auto second = output[previous_index(index, 37, output.size())];
        const auto third = output[previous_index(index, 177, output.size())];
        output[index % output.size()] ^=
            std::rotl(first, 1) ^ std::rotl(second, 6) ^ std::rotl(third, 5);
    }
    for (auto& value : output) {
        value = static_cast<std::uint8_t>(value - 0x92);
    }
    return output;
}

Sha1Digest make_provisioning_hardware_digest(std::span<const std::uint8_t, 20> hardware_hash,
                                             std::span<const std::uint8_t, 256> parameters) {
    const auto seed = make_provisioning_hardware_seed(hardware_hash, parameters.first<128>());
    const auto message = mix_provisioning_hardware_seed(seed, parameters.last<128>());
    return sha1(message);
}

Sha1Digest make_provisioning_hardware_digest(const HardwareInputs& hardware,
                                             std::span<const std::uint8_t, 256> parameters) {
    return make_provisioning_hardware_digest(hash_hardware_inputs(hardware), parameters);
}

Sha1Digest make_provisioning_hardware_tag(std::span<const std::uint8_t, 20> hardware_hash,
                                          std::span<const std::uint8_t, 272> parameters) {
    auto tag = make_provisioning_hardware_digest(hardware_hash, parameters.first<256>());
    AesBlock block{};
    std::copy_n(tag.begin(), block.size(), block.begin());
    const auto encrypted = encrypt_aes128_block(block, expand_aes128_key(parameters.last<16>()));
    std::copy(encrypted.begin(), encrypted.end(), tag.begin());
    return tag;
}

Sha1Digest make_provisioning_hardware_tag(const HardwareInputs& hardware,
                                          std::span<const std::uint8_t, 272> parameters) {
    return make_provisioning_hardware_tag(hash_hardware_inputs(hardware), parameters);
}

Sha256Digest provisioning_payload_digest(std::span<const std::uint8_t, 160> ciphertext,
                                         std::span<const std::uint8_t, 16> parameter,
                                         std::span<const std::uint8_t, 24> suffix) {
    std::array<std::uint8_t, 200> message{};
    std::copy(ciphertext.begin(), ciphertext.end(), message.begin());
    std::copy(parameter.begin(), parameter.end(), message.begin() + 160);
    std::copy(suffix.begin(), suffix.end(), message.begin() + 176);
    return sha256(message);
}

std::array<std::uint8_t, 192>
make_provisioning_payload(std::span<const std::uint8_t, 160> ciphertext,
                          std::span<const std::uint8_t, 16> parameter,
                          std::span<const std::uint8_t, 24> suffix) {
    std::array<std::uint8_t, 192> result{};
    std::copy(ciphertext.begin(), ciphertext.end(), result.begin());
    const auto digest = provisioning_payload_digest(ciphertext, parameter, suffix);
    std::copy(digest.begin(), digest.end(), result.begin() + 160);
    return result;
}

std::array<std::uint8_t, 160>
encrypt_provisioning_response_body(std::span<const std::uint8_t, 160> plaintext,
                                   std::span<const std::uint8_t, 16> key,
                                   std::span<const std::uint8_t, 16> nonce) {
    const auto schedule = expand_aes128_key(key);
    AesBlock previous{};
    std::copy(nonce.begin(), nonce.end(), previous.begin());
    std::array<std::uint8_t, 160> ciphertext{};
    for (std::size_t offset = 0; offset < plaintext.size(); offset += previous.size()) {
        AesBlock block{};
        for (std::size_t index = 0; index < block.size(); ++index) {
            block[index] = plaintext[offset + index] ^ previous[index];
        }
        previous = encrypt_aes128_block(block, schedule);
        std::copy(previous.begin(), previous.end(), ciphertext.begin() + offset);
    }
    return ciphertext;
}

std::array<std::uint8_t, 192>
encrypt_provisioning_response(std::span<const std::uint8_t, 160> plaintext,
                              std::span<const std::uint8_t, 16> key,
                              std::span<const std::uint8_t, 16> nonce,
                              std::span<const std::uint8_t, 16> parameter,
                              std::span<const std::uint8_t, 24> suffix) {
    return make_provisioning_payload(
        encrypt_provisioning_response_body(plaintext, key, nonce), parameter, suffix);
}

std::array<std::uint8_t, 192>
make_provisioning_response_from_spim(std::span<const std::uint8_t, 240> spim_ciphertext,
                                     std::span<const std::uint8_t, 160> plaintext,
                                     std::span<const std::uint8_t, 16> nonce,
                                     std::span<const std::uint8_t, 16> parameter,
                                     const ProvisioningResponseParameters& parameters) {
    const auto material = decode_provisioning_spim_material(spim_ciphertext, parameters.spim);
    const auto key = decode_provisioning_response_key(material, parameters.key);
    return encrypt_provisioning_response(plaintext, key, nonce, parameter, parameters.hash_suffix);
}

ProvisioningSelectorEntropy
take_provisioning_selector_entropy(std::span<const std::uint8_t> random_bytes) {
    ProvisioningSelectorEntropy result{};
    std::size_t accepted{};
    for (const auto value : random_bytes) {
        ++result.consumed;
        if (value != 0) {
            result.bytes[accepted++] = value;
            if (accepted == result.bytes.size()) {
                return result;
            }
        }
    }
    throw std::invalid_argument("Provisioning selector needs 32 nonzero random bytes");
}

std::array<std::uint8_t, 32>
make_provisioning_selector_input(std::span<const std::uint8_t, 32> random_bytes,
                                 const ProvisioningSelectorSourceParameters& parameters,
                                 std::span<const std::uint8_t, 16> selector_input_mask) {
    const ProvisioningCipherParameters cipher{parameters.key, parameters.iv, {}};
    auto output = encrypt_provisioning_input(random_bytes, cipher);
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] ^= selector_input_mask[index % 16];
    }
    return output;
}

ProvisioningChallengeFields read_provisioning_challenge_fields(std::span<const std::uint8_t> spim) {
    if (spim.size() < 324) {
        throw std::invalid_argument("Provisioning challenge is truncated");
    }
    const auto word = [&spim](std::size_t offset) {
        std::uint32_t value{};
        for (std::size_t byte = 0; byte < 4; ++byte) {
            value = (value << 8) | spim[offset + byte];
        }
        return value;
    };
    if (word(0) != 4 || word(4) != 240 || word(264) != 52 || word(268) != 4) {
        throw std::invalid_argument("Unsupported provisioning challenge field layout");
    }
    return {std::span<const std::uint8_t, 240>(spim.data() + 8, 240),
            std::span<const std::uint8_t, 16>(spim.data() + 248, 16),
            std::span<const std::uint8_t, 60>(spim.data() + 264, 60)};
}

std::array<std::uint8_t, 276>
make_provisioning_cpim(std::span<const std::uint8_t> spim,
                       std::span<const std::uint8_t, 160> body,
                       std::span<const std::uint8_t, 16> nonce,
                       const ProvisioningStartParameters& parameters) {
    const auto fields = read_provisioning_challenge_fields(spim);
    const auto digest_parameter = decrypt_provisioning_digest_parameter(
        fields.encrypted_digest_parameter, parameters.digest_key);
    const auto response = make_provisioning_response_from_spim(
        fields.encrypted_material, body, nonce, digest_parameter, parameters.response);
    return assemble_provisioning_cpim(nonce, response, fields.echoed_server_field);
}

std::array<std::uint8_t, 160>
make_provisioning_start_body(std::span<const std::uint8_t, 32> selector_input,
                             std::span<const std::uint8_t, 20> hardware_hash,
                             const ProvisioningBodyEntropy& entropy,
                             std::int64_t dsid,
                             std::uint32_t unix_seconds,
                             const ProvisioningRequestParameters& parameters,
                             std::uint32_t platform) {
    const auto encrypted = encrypt_provisioning_input(selector_input, parameters.selector);
    const auto tag = make_provisioning_hardware_tag(hardware_hash, parameters.hardware);
    return make_provisioning_body(encrypted, tag, entropy, dsid, unix_seconds, platform);
}

bool verify_provisioning_profile_challenge(std::span<const std::uint8_t> spim,
                                           const AesBlock& authentication_key) {
    if (spim.size() != 347) {
        return false;
    }
    const auto word = [&spim](std::size_t offset) {
        return read_provisioning_end_word(
            std::span<const std::uint8_t, 4>(spim.data() + offset, 4));
    };
    if (word(0) != 4 || word(4) != 240 || word(264) != 52 || word(268) != 4 ||
        word(320) != 0xED9281D8U) {
        return false;
    }
    const auto tag =
        transform_provisioning_end_digest(sha1(spim.subspan(4, 320)), authentication_key);
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < tag.size(); ++index) {
        difference |= tag[index] ^ spim[324 + index];
    }
    return difference == 0;
}

ProvisioningProfileStart
begin_provisioning_profile(std::span<const std::uint8_t> spim,
                           std::span<const std::uint8_t> selector_random,
                           std::span<const std::uint8_t, 20> hardware_hash,
                           const ProvisioningBodyEntropy& entropy,
                           std::uint32_t unix_seconds,
                           std::span<const std::uint8_t, 16> nonce,
                           const ProvisioningSelectorSourceParameters& source_parameters,
                           const ProvisioningRequestParameters& request_parameters,
                           const AesBlock& authentication_key,
                           std::uint32_t platform) {
    if (platform != 1 && platform != 2 && platform != 4) {
        throw std::invalid_argument("Unsupported ADI provisioning platform");
    }
    if (!verify_provisioning_profile_challenge(spim, authentication_key)) {
        throw std::invalid_argument("SPIM challenge framing or authentication is invalid");
    }
    const auto random = take_provisioning_selector_entropy(selector_random);
    const auto selector_input = make_provisioning_selector_input(
        random.bytes, source_parameters, request_parameters.selector.input_mask);
    ProvisioningProfileStart start{};
    start.body = make_provisioning_start_body(
        selector_input, hardware_hash, entropy, -2, unix_seconds, request_parameters, platform);
    start.packet = make_provisioning_cpim(spim, start.body, nonce, request_parameters.response);
    return start;
}

StateBody make_provisioned_profile(std::span<const std::uint8_t, 160> start_body,
                                   std::span<const std::uint8_t> payload) {
    const auto word = [](const auto& bytes, std::size_t offset) {
        return read_provisioning_end_word(
            std::span<const std::uint8_t, 4>(bytes.data() + offset, 4));
    };
    const auto platform = word(start_body, 144);
    const std::size_t secondary_size = platform == 1 ? 400 : platform == 4 ? 384 : 208;
    if ((platform != 1 && platform != 2 && platform != 4) ||
        payload.size() != secondary_size + 48 || word(start_body, 0) != 32 ||
        word(start_body, 36) != 32 ||
        read_state_body_integer(start_body.subspan(132, 8)) != UINT64_MAX - 1 ||
        word(payload, 0) != secondary_size || word(payload, secondary_size + 4) != 32) {
        throw std::invalid_argument("Unsupported fresh GrandSlam profile fields");
    }
    std::uint8_t nonce_difference = 0;
    for (std::size_t index = 0; index < 32; ++index) {
        nonce_difference |= start_body[40 + index] ^ payload[secondary_size + 8 + index];
    }
    if (nonce_difference != 0) {
        throw std::invalid_argument("Provisioning response belongs to a different start session");
    }
    StateBody profile{};
    profile.profile = UINT64_MAX - 1;
    std::copy_n(start_body.begin() + 72, profile.profile_data.size(), profile.profile_data.begin());
    std::copy_n(
        start_body.begin() + 4, profile.encrypted_seed.size(), profile.encrypted_seed.begin());
    profile.secondary.assign(payload.begin() + 4, payload.begin() + 4 + secondary_size);
    return profile;
}

StateBody finish_provisioning_profile(std::span<const std::uint8_t> spim,
                                      std::span<const std::uint8_t, 160> start_body,
                                      std::span<const std::uint8_t> ptm,
                                      std::span<const std::uint8_t, 16> trust_key,
                                      const ProvisioningEndPacketParameters& parameters) {
    if (!verify_provisioning_profile_challenge(spim, parameters.authentication_key)) {
        throw std::invalid_argument("SPIM challenge framing or authentication is invalid");
    }
    const auto payload = decrypt_authenticated_provisioning_end_packet(
        std::span<const std::uint8_t, 240>(spim.data() + 8, 240), ptm, trust_key, parameters);
    if (read_state_body_integer(start_body.subspan(132, 8)) == UINT64_MAX) {
        const auto word = [&](std::size_t offset) {
            return read_provisioning_end_word(
                std::span<const std::uint8_t, 4>(payload.data() + offset, 4));
        };
        if (payload.size() != 320 || word(0) != 272 || word(276) != 32) {
            throw std::invalid_argument("Unsupported Store provisioning fields");
        }
        std::uint8_t difference = 0;
        for (std::size_t i = 0; i < 32; ++i) {
            difference |= start_body[40 + i] ^ payload[280 + i];
        }
        if (difference) {
            throw std::invalid_argument("Store response belongs to a different start session");
        }
        StateBody profile{};
        profile.profile = UINT64_MAX;
        std::copy_n(start_body.begin() + 72, 60, profile.profile_data.begin());
        std::copy_n(start_body.begin() + 4, 32, profile.encrypted_seed.begin());
        profile.secondary.assign(payload.begin() + 4, payload.begin() + 276);
        return profile;
    }
    return make_provisioned_profile(start_body, payload);
}
} // namespace apple_auth::detail
