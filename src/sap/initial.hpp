#pragma once
#include "crypto.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace apple_auth::detail::sap {

inline std::array<std::uint8_t, 48>
encrypt_initial_payload(std::span<const std::uint8_t> loader_key,
                        std::span<const std::uint8_t> payload_nonce,
                        std::span<const std::uint8_t> padding,
                        std::span<const std::uint8_t> transport_key,
                        std::span<const std::uint8_t> iv,
                        std::uint32_t device_type = 66) {
    if (loader_key.size() != 16 || payload_nonce.size() != 16 || padding.size() != 11 ||
        transport_key.size() != 16 || iv.size() != 16) {
        throw std::invalid_argument(
            "Expected initial payload key16/nonce16/padding11/AES-key16/IV16");
    }
    std::array<std::uint8_t, 48> plaintext{}, ciphertext{};
    plaintext[0] = 2;
    for (unsigned byte = 0; byte < 4; ++byte) {
        plaintext[1 + byte] = static_cast<std::uint8_t>(device_type >> (24 - 8 * byte));
    }
    std::copy(loader_key.begin(), loader_key.end(), plaintext.begin() + 5);
    std::copy(payload_nonce.begin(), payload_nonce.end(), plaintext.begin() + 21);
    std::copy(padding.begin(), padding.end(), plaintext.begin() + 37);
    const auto schedule = ::apple_auth::detail::expand_aes128_key(
        std::span<const std::uint8_t, 16>(transport_key.data(), 16));
    ::apple_auth::detail::AesBlock previous{};
    std::copy(iv.begin(), iv.end(), previous.begin());
    for (unsigned offset = 0; offset < 48; offset += 16) {
        ::apple_auth::detail::AesBlock block{};
        for (unsigned byte = 0; byte < 16; ++byte) {
            block[byte] = plaintext[offset + byte] ^ previous[byte];
        }
        previous = ::apple_auth::detail::encrypt_aes128_block(block, schedule);
        std::copy(previous.begin(), previous.end(), ciphertext.begin() + offset);
    }
    return ciphertext;
}

// RSA-2048 OAEP with SHA-1 and an empty label.
inline std::vector<std::uint8_t> initial_mgf1_sha1(std::span<const std::uint8_t> seed,
                                                   std::size_t length) {
    std::vector<std::uint8_t> output;
    for (std::uint32_t counter = 0; output.size() < length; ++counter) {
        std::vector<std::uint8_t> input(seed.begin(), seed.end());
        for (unsigned byte = 0; byte < 4; ++byte) {
            input.push_back(static_cast<std::uint8_t>(counter >> (24 - 8 * byte)));
        }
        const auto digest = ::apple_auth::detail::sha1(input);
        const auto count = std::min(digest.size(), length - output.size());
        output.insert(output.end(), digest.begin(), digest.begin() + count);
    }
    return output;
}

inline std::array<std::uint8_t, 256> encode_initial_oaep(std::span<const std::uint8_t> message,
                                                         std::span<const std::uint8_t> seed) {
    if (message.size() > 214 || seed.size() != 20) {
        throw std::invalid_argument("Expected an OAEP-SHA1 message up to214 and seed20");
    }
    std::array<std::uint8_t, 256> encoded{};
    auto masked_seed = std::span<std::uint8_t>(encoded).subspan(1, 20);
    auto database = std::span<std::uint8_t>(encoded).subspan(21);
    const auto label_hash = ::apple_auth::detail::sha1(std::span<const std::uint8_t>{});
    std::copy(label_hash.begin(), label_hash.end(), database.begin());
    database[database.size() - message.size() - 1] = 1;
    std::copy(message.begin(), message.end(), database.end() - message.size());
    const auto db_mask = initial_mgf1_sha1(seed, database.size());
    for (std::size_t byte = 0; byte < database.size(); ++byte) {
        database[byte] ^= db_mask[byte];
    }
    const auto seed_mask = initial_mgf1_sha1(database, seed.size());
    for (std::size_t byte = 0; byte < seed.size(); ++byte) {
        masked_seed[byte] = seed[byte] ^ seed_mask[byte];
    }
    return encoded;
}

inline ::apple_auth::detail::Sha1Digest initial_hmac_sha1(std::span<const std::uint8_t> key,
                                                          std::span<const std::uint8_t> message) {
    std::array<std::uint8_t, 64> block{};
    if (key.size() > block.size()) {
        const auto digest = ::apple_auth::detail::sha1(key);
        std::copy(digest.begin(), digest.end(), block.begin());
    } else {
        std::copy(key.begin(), key.end(), block.begin());
    }
    std::vector<std::uint8_t> inner(block.size()), outer(block.size());
    for (std::size_t byte = 0; byte < block.size(); ++byte) {
        inner[byte] = block[byte] ^ 0x36;
        outer[byte] = block[byte] ^ 0x5c;
    }
    inner.insert(inner.end(), message.begin(), message.end());
    const auto digest = ::apple_auth::detail::sha1(inner);
    outer.insert(outer.end(), digest.begin(), digest.end());
    return ::apple_auth::detail::sha1(outer);
}

// The MAC covers only the 48-byte encrypted payload.
inline std::array<std::uint8_t, 354>
assemble_initial_request(std::span<const std::uint8_t> key_identifier,
                         std::span<const std::uint8_t> rsa_block,
                         std::span<const std::uint8_t> iv,
                         std::span<const std::uint8_t> encrypted,
                         std::span<const std::uint8_t> authentication_key) {
    if (key_identifier.size() != 8 || rsa_block.size() != 256 || iv.size() != 16 ||
        encrypted.size() != 48 || authentication_key.size() != 20) {
        throw std::invalid_argument("Expected initial SAP key-ID8/RSA256/IV16/cipher48/MAC-key20");
    }
    std::array<std::uint8_t, 354> packet{};
    packet[0] = 1;
    packet[1] = 8;
    std::copy(key_identifier.begin(), key_identifier.end(), packet.begin() + 2);
    std::copy(rsa_block.begin(), rsa_block.end(), packet.begin() + 10);
    std::copy(iv.begin(), iv.end(), packet.begin() + 266);
    packet[285] = 48;
    std::copy(encrypted.begin(), encrypted.end(), packet.begin() + 286);
    const auto mac = initial_hmac_sha1(authentication_key, encrypted);
    std::copy(mac.begin(), mac.end(), packet.begin() + 334);
    return packet;
}

} // namespace apple_auth::detail::sap
