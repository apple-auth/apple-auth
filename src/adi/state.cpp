#include "adi/data/tables.hpp"
#include "adi/internal.hpp"

namespace apple_auth::detail {
std::uint32_t read_state_file_word(std::span<const std::uint8_t, 4> bytes) {
    std::uint32_t result = 0;
    for (const auto byte : bytes) {
        result = (result << 8) | byte;
    }
    return result;
}

StateFileView parse_state_file(std::span<const std::uint8_t> bytes) {
    constexpr std::size_t header_size = 8;
    constexpr std::size_t iv_size = 16;
    constexpr std::size_t tag_size = 20;
    constexpr std::size_t minimum_ciphertext_size = 16;
    constexpr std::size_t minimum_size = header_size + iv_size + minimum_ciphertext_size + tag_size;
    if (bytes.size() < minimum_size) {
        throw std::invalid_argument("Truncated ADI state file");
    }
    const auto version = read_state_file_word(std::span<const std::uint8_t, 4>(bytes.data(), 4));
    if (version != 1 && version != 3) {
        throw std::invalid_argument("Unsupported ADI state file version");
    }
    const auto prefix_size =
        read_state_file_word(std::span<const std::uint8_t, 4>(bytes.data() + 4, 4));
    if (prefix_size > bytes.size() - minimum_size) {
        throw std::invalid_argument("ADI state prefix exceeds the file boundary");
    }
    const auto iv_offset = header_size + static_cast<std::size_t>(prefix_size);
    const auto ciphertext_offset = iv_offset + iv_size;
    const auto tag_offset = bytes.size() - tag_size;
    const auto ciphertext_size = tag_offset - ciphertext_offset;
    if (ciphertext_size % iv_size != 0) {
        throw std::invalid_argument("ADI ciphertext is not a complete sequence of blocks");
    }
    return {version,
            bytes.subspan(header_size, prefix_size),
            std::span<const std::uint8_t, 16>(bytes.data() + iv_offset, iv_size),
            bytes.subspan(ciphertext_offset, ciphertext_size),
            std::span<const std::uint8_t, 20>(bytes.data() + tag_offset, tag_size)};
}

std::vector<std::uint8_t> serialize_state_body(const StateBody& state,
                                               const StateBodySchemaParameters& parameters,
                                               std::span<const std::uint8_t> padding) {
    const std::size_t secondary_size = state.secondary.size();
    if (!((state.profile == UINT64_MAX && secondary_size == 272) ||
          (state.profile == UINT64_MAX - 1 &&
           (secondary_size == 208 || secondary_size == 384 || secondary_size == 400)))) {
        throw std::invalid_argument("Unsupported ADI profile or secondary size");
    }
    const std::size_t area_size =
        8 + 60 + secondary_size + 32 + 8 + 5 * 8 + (state.option.has_value() ? 12 : 0);
    const std::size_t unpadded_size = 12 + area_size;
    if (padding.size() != (16 - unpadded_size % 16) % 16) {
        throw std::invalid_argument("Incorrect ADI body padding length");
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(unpadded_size + padding.size());
    const auto append_integer = [&bytes](std::uint64_t value, std::size_t size) {
        for (std::size_t index = 0; index < size; ++index) {
            bytes.push_back(static_cast<std::uint8_t>(value >> (8 * (size - index - 1))));
        }
    };
    const auto append_record = [&](std::size_t index, std::span<const std::uint8_t> value) {
        append_integer(parameters.record_tags[index], 4);
        append_integer(value.size(), 4);
        bytes.insert(bytes.end(), value.begin(), value.end());
    };
    append_integer(1, 4);
    append_integer(parameters.outer_tag, 4);
    append_integer(area_size, 4);
    append_integer(parameters.record_tags[0], 4);
    append_integer(8, 4);
    append_integer(state.profile, 8);
    append_record(1, state.profile_data);
    append_record(2, state.secondary);
    append_record(3, state.encrypted_seed);
    if (state.option.has_value()) {
        append_integer(parameters.record_tags[4], 4);
        append_integer(4, 4);
        append_integer(*state.option, 4);
    }
    append_record(5, state.extra_data);
    bytes.insert(bytes.end(), padding.begin(), padding.end());
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] ^= parameters.field_mask[index % 16];
    }
    return bytes;
}

std::uint64_t read_state_body_integer(std::span<const std::uint8_t> bytes) {
    std::uint64_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | byte;
    }
    return value;
}

StateBody parse_state_body(std::span<const std::uint8_t> encoded,
                           const StateBodySchemaParameters& parameters) {
    if (encoded.size() < 16 || encoded.size() % 16 != 0) {
        throw std::invalid_argument("Invalid ADI body alignment");
    }
    std::vector<std::uint8_t> bytes(encoded.size());
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = encoded[index] ^ parameters.field_mask[index % 16];
    }
    const auto number = [&bytes](std::size_t offset) {
        return read_state_file_word(std::span<const std::uint8_t, 4>(bytes.data() + offset, 4));
    };
    if (number(0) != 1 || number(4) != parameters.outer_tag) {
        throw std::invalid_argument("Unsupported ADI body header");
    }
    const auto area_size = static_cast<std::size_t>(number(8));
    if (area_size > bytes.size() - 12 || bytes.size() - 12 - area_size > 15) {
        throw std::invalid_argument("Invalid ADI body record area");
    }
    const std::size_t end = 12 + area_size;
    std::size_t cursor = 12;
    std::array<std::span<const std::uint8_t>, 6> fields{};
    for (std::size_t index = 0; index < fields.size(); ++index) {
        if (index == 4 && end - cursor >= 8 && number(cursor) == parameters.record_tags[5]) {
            continue;
        }
        if (end - cursor < 8 || number(cursor) != parameters.record_tags[index]) {
            throw std::invalid_argument("Missing or unsupported ADI body record");
        }
        const auto size = static_cast<std::size_t>(number(cursor + 4));
        if (index == 4 && size != 4) {
            throw std::invalid_argument("Invalid ADI option record length");
        }
        cursor += 8;
        if (size > end - cursor) {
            throw std::invalid_argument("ADI body record exceeds its container");
        }
        fields[index] = std::span<const std::uint8_t>(bytes.data() + cursor, size);
        cursor += size;
    }
    if (cursor != end || fields[0].size() != 8 || fields[1].size() != 60 ||
        fields[3].size() != 32 || fields[5].size() != 8) {
        throw std::invalid_argument("Invalid ADI body record lengths");
    }
    const auto profile = read_state_body_integer(fields[0]);
    const std::size_t secondary_size = fields[2].size();
    if (!((profile == UINT64_MAX && secondary_size == 272) ||
          (profile == UINT64_MAX - 1 &&
           (secondary_size == 208 || secondary_size == 384 || secondary_size == 400)))) {
        throw std::invalid_argument("Unsupported ADI profile or secondary size");
    }
    StateBody result{};
    result.profile = profile;
    std::copy(fields[1].begin(), fields[1].end(), result.profile_data.begin());
    result.secondary.assign(fields[2].begin(), fields[2].end());
    std::copy(fields[3].begin(), fields[3].end(), result.encrypted_seed.begin());
    if (!fields[4].empty()) {
        result.option = static_cast<std::uint32_t>(read_state_body_integer(fields[4]));
    }
    std::copy(fields[5].begin(), fields[5].end(), result.extra_data.begin());
    return result;
}

Sha1Digest compute_state_file_tag(std::span<const std::uint8_t> file, const AesBlock& key) {
    parse_state_file(file);
    constexpr std::size_t version_size = 4;
    constexpr std::size_t tag_size = 20;
    auto digest = sha1(file.subspan(version_size, file.size() - version_size - tag_size));
    AesBlock block{};
    std::copy_n(digest.begin(), block.size(), block.begin());
    const auto encrypted = encrypt_aes128_block(block, expand_aes128_key(key));
    std::copy(encrypted.begin(), encrypted.end(), digest.begin());
    return digest;
}

bool verify_state_file_tag(std::span<const std::uint8_t> file, const AesBlock& key) {
    const auto envelope = parse_state_file(file);
    const auto expected = compute_state_file_tag(file, key);
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < expected.size(); ++index) {
        difference |= expected[index] ^ envelope.authentication_tag[index];
    }
    return difference == 0;
}

std::vector<std::uint8_t> decode_state_file_body(std::span<const std::uint8_t> ciphertext,
                                                 std::span<const std::uint8_t, 16> key,
                                                 std::span<const std::uint8_t, 16> iv) {
    if (ciphertext.empty() || ciphertext.size() % 16 != 0) {
        throw std::invalid_argument("State-file body must contain complete AES blocks");
    }
    const auto schedule = expand_aes128_key(key);
    AesBlock previous{};
    std::copy(iv.begin(), iv.end(), previous.begin());
    std::vector<std::uint8_t> output(ciphertext.size());
    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        AesBlock block{};
        std::copy_n(ciphertext.begin() + offset, block.size(), block.begin());
        const auto decrypted = decrypt_aes128_block(block, schedule);
        for (std::size_t index = 0; index < block.size(); ++index) {
            output[offset + index] = static_cast<std::uint8_t>(decrypted[index] ^ previous[index] ^
                                                               state_body_output_mask[index]);
        }
        previous = block;
    }
    return output;
}

std::vector<std::uint8_t> encode_state_file_body(std::span<const std::uint8_t> body,
                                                 std::span<const std::uint8_t, 16> key,
                                                 std::span<const std::uint8_t, 16> iv) {
    if (body.empty() || body.size() % 16 != 0) {
        throw std::invalid_argument("State-file body must contain complete AES blocks");
    }
    const auto schedule = expand_aes128_key(key);
    AesBlock previous{};
    std::copy(iv.begin(), iv.end(), previous.begin());
    std::vector<std::uint8_t> ciphertext(body.size());
    for (std::size_t offset = 0; offset < body.size(); offset += 16) {
        AesBlock block{};
        for (std::size_t index = 0; index < block.size(); ++index) {
            block[index] = body[offset + index] ^ state_body_output_mask[index] ^ previous[index];
        }
        previous = encrypt_aes128_block(block, schedule);
        std::copy(previous.begin(), previous.end(), ciphertext.begin() + offset);
    }
    return ciphertext;
}

std::vector<std::uint8_t> encode_bound_state_file(std::uint32_t version,
                                                  std::span<const std::uint8_t> body,
                                                  std::span<const std::uint8_t, 20> hardware_digest,
                                                  std::span<const std::uint8_t> prefix,
                                                  std::span<const std::uint8_t, 16> iv,
                                                  const StateBodyKeyParameters& body_key_parameters,
                                                  std::optional<std::uint32_t> binding_word) {
    if (version != 1 && version != 3) {
        throw std::invalid_argument("Unsupported ADI state file version");
    }
    const auto digest = derive_file_key_digest(hardware_digest, prefix, binding_word);
    const auto body_key = derive_state_file_body_key(digest, body_key_parameters);
    const auto ciphertext = encode_state_file_body(body, body_key, iv);
    std::vector<std::uint8_t> file;
    file.reserve(44 + prefix.size() + ciphertext.size());
    const auto append_word = [&file](std::uint32_t value) {
        for (std::size_t index = 0; index < 4; ++index) {
            file.push_back(static_cast<std::uint8_t>(value >> (24 - 8 * index)));
        }
    };
    append_word(version);
    append_word(static_cast<std::uint32_t>(prefix.size()));
    file.insert(file.end(), prefix.begin(), prefix.end());
    file.insert(file.end(), iv.begin(), iv.end());
    file.insert(file.end(), ciphertext.begin(), ciphertext.end());
    file.resize(file.size() + 20);
    const auto authentication_key = derive_state_file_tag_key(digest);
    const auto tag = compute_state_file_tag(file, authentication_key);
    std::copy(tag.begin(), tag.end(), file.end() - tag.size());
    return file;
}

std::vector<std::uint8_t> decode_bound_state_file(std::span<const std::uint8_t> file,
                                                  std::span<const std::uint8_t, 20> hardware_digest,
                                                  const StateBodyKeyParameters& body_key_parameters,
                                                  std::optional<std::uint32_t> binding_word) {
    const auto envelope = parse_state_file(file);
    const auto digest = derive_file_key_digest(hardware_digest, envelope.prefix, binding_word);
    const auto authentication_key = derive_state_file_tag_key(digest);
    if (!verify_state_file_tag(file, authentication_key)) {
        throw std::invalid_argument("ADI state-file authentication failed");
    }
    const auto body_key = derive_state_file_body_key(digest, body_key_parameters);
    return decode_state_file_body(envelope.ciphertext, body_key, envelope.iv);
}

std::array<std::uint8_t, 32> decode_state_seed(std::span<const std::uint8_t, 32> ciphertext,
                                               const StateSeedCipherParameters& parameters) {
    const auto schedule = expand_aes128_key(parameters.key);
    auto previous = parameters.iv;
    std::array<std::uint8_t, 32> seed{};
    for (std::size_t offset = 0; offset < seed.size(); offset += 16) {
        AesBlock block{};
        std::copy_n(ciphertext.begin() + offset, block.size(), block.begin());
        const auto plaintext = decrypt_aes128_block(block, schedule);
        for (std::size_t index = 0; index < block.size(); ++index) {
            seed[offset + index] = plaintext[index] ^ previous[index];
        }
        previous = block;
    }
    return seed;
}

std::optional<std::uint32_t> state_file_profile_hash(std::string_view name) {
    if (name == "adi.pb") {
        return std::nullopt;
    }
    if (name.size() != 15 || !name.starts_with("adi-") || !name.ends_with(".pb")) {
        throw std::invalid_argument("Invalid ADI state-file name");
    }
    std::uint32_t hash = 0;
    const auto* begin = name.data() + 4;
    const auto* end = begin + 8;
    const auto parsed = std::from_chars(begin, end, hash, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != end) {
        throw std::invalid_argument("Invalid ADI profile hash in state-file name");
    }
    return hash;
}

Sha1Digest hash_hardware_inputs(const HardwareInputs& inputs) {
    constexpr std::string_view preamble = "cache-controlEthernet";
    std::vector<std::uint8_t> message(preamble.begin(), preamble.end());
    message.reserve(preamble.size() + 3 * 7);
    const auto append_checksum = [&message](std::span<const std::uint8_t> value) {
        const auto checksum = md5(value);
        message.insert(message.end(), checksum.begin(), checksum.begin() + 7);
    };

    if (inputs.volume_serial.has_value()) {
        std::array<std::uint8_t, 4> serialized_volume{};
        for (std::size_t index = 0; index < serialized_volume.size(); ++index) {
            serialized_volume[index] =
                static_cast<std::uint8_t>(*inputs.volume_serial >> (index * 8));
        }
        append_checksum(serialized_volume);
    }
    if (inputs.bios.has_value()) {
        append_checksum(*inputs.bios);
    }
    if (inputs.processor.has_value()) {
        append_checksum(*inputs.processor);
    }
    return sha1(message);
}
} // namespace apple_auth::detail
