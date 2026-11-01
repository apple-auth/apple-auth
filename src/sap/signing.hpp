#pragma once
#include "crypto.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace apple_auth::detail::sap {
using Bytes = std::vector<std::uint8_t>;
using Block = std::array<std::uint8_t, 16>;
using View = std::span<const std::uint8_t>;

// SAP 200 signs SHA1(session_blob || HTTP_body).
inline ::apple_auth::detail::Sha1Digest request_digest(View session_blob, View body) {
    if ((session_blob.size() != 448 && session_blob.size() != 464) || body.size() > 1024 * 1024) {
        throw std::invalid_argument("Unsupported SAP session blob or request length");
    }
    Bytes message(session_blob.begin(), session_blob.end());
    message.insert(message.end(), body.begin(), body.end());
    return ::apple_auth::detail::sha1(message);
}

// Zero-pad the 20-byte digest to two AES blocks.
inline std::array<std::uint8_t, 32> authenticator_message(View session_blob, View body) {
    const auto digest = request_digest(session_blob, body);
    std::array<std::uint8_t, 32> result{};
    std::copy(digest.begin(), digest.end(), result.begin());
    return result;
}

inline Bytes assemble_signature(const Block& nonce, const Block& authenticator, View session_blob) {
    if (session_blob.size() != 448 && session_blob.size() != 464) {
        throw std::invalid_argument("Unsupported SAP session blob length");
    }
    Bytes result(37 + session_blob.size());
    result[0] = 2;
    std::copy(nonce.begin(), nonce.end(), result.begin() + 1);
    std::copy(authenticator.begin(), authenticator.end(), result.begin() + 17);
    for (unsigned byte = 0; byte < 4; ++byte) {
        result[33 + byte] = static_cast<std::uint8_t>(session_blob.size() >> (24 - 8 * byte));
    }
    std::copy(session_blob.begin(), session_blob.end(), result.begin() + 37);
    return result;
}

// Inverse AES CBC-MAC:
// previous = AES_decrypt(key, message_block XOR previous), starting with nonce.
inline Block
request_authenticator(const Block& session_key, const Block& nonce, View session_blob, View body) {
    const auto message = authenticator_message(session_blob, body);
    const auto schedule = ::apple_auth::detail::expand_aes128_key(session_key);
    Block previous = nonce;
    for (std::size_t offset = 0; offset < message.size(); offset += 16) {
        for (std::size_t byte = 0; byte < 16; ++byte) {
            previous[byte] ^= message[offset + byte];
        }
        previous = ::apple_auth::detail::decrypt_aes128_block(previous, schedule);
    }
    return previous;
}

inline Bytes
sign_request(const Block& session_key, const Block& nonce, View session_blob, View body) {
    return assemble_signature(
        nonce, request_authenticator(session_key, nonce, session_blob, body), session_blob);
}
} // namespace apple_auth::detail::sap
