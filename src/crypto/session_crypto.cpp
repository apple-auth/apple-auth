// AES-GCM storage envelopes, independent of Apple authentication protocols.
#include <apple_auth/session_crypto.hpp>
#include "crypto/backend.hpp"
#include <mbedtls/gcm.h>
#include <limits>

namespace apple_auth {
namespace {
constexpr std::array<std::uint8_t, 9> header{'A', 'A', 'U', 'T', 'H', 'E', 'N', 'C', 1};
constexpr std::size_t nonce_size = 12, tag_size = 16;
constexpr std::size_t prefix_size = header.size() + nonce_size;

void check_key(ByteView key) {
    if (key.size() != session_key_size) {
        throw Error(ErrorCode::invalid_argument, "Session encryption requires a 32-byte key");
    }
}
} // namespace

Bytes generate_session_key() {
    Bytes key(session_key_size);
    crypto::random(key);
    return key;
}

Bytes encrypt_session(ByteView plaintext, ByteView key) {
    check_key(key);
    if (plaintext.size() > std::numeric_limits<std::size_t>::max() - session_encryption_overhead) {
        throw Error(ErrorCode::invalid_argument, "Session is too large to encrypt");
    }
    Bytes result(plaintext.size() + session_encryption_overhead);
    std::copy(header.begin(), header.end(), result.begin());
    crypto::random(std::span(result).subspan(header.size(), nonce_size));
    crypto::Context<mbedtls_gcm_context, mbedtls_gcm_init, mbedtls_gcm_free> cipher;
    crypto::check(mbedtls_gcm_setkey(cipher.get(), MBEDTLS_CIPHER_ID_AES, key.data(), 256),
                  "Cannot initialize session encryption");
    crypto::check(mbedtls_gcm_crypt_and_tag(
                      cipher.get(), MBEDTLS_GCM_ENCRYPT, plaintext.size(),
                      result.data() + header.size(), nonce_size, result.data(), prefix_size,
                      plaintext.data(), result.data() + prefix_size, tag_size,
                      result.data() + result.size() - tag_size),
                  "Session encryption failed");
    return result;
}

Bytes decrypt_session(ByteView encrypted, ByteView key) {
    check_key(key);
    if (encrypted.size() < session_encryption_overhead ||
        !std::equal(header.begin(), header.end(), encrypted.begin())) {
        throw Error(ErrorCode::invalid_data, "Invalid or unsupported encrypted session format");
    }
    crypto::Context<mbedtls_gcm_context, mbedtls_gcm_init, mbedtls_gcm_free> cipher;
    crypto::check(mbedtls_gcm_setkey(cipher.get(), MBEDTLS_CIPHER_ID_AES, key.data(), 256),
                  "Cannot initialize session decryption");
    Bytes plaintext(encrypted.size() - session_encryption_overhead);
    const auto status = mbedtls_gcm_auth_decrypt(
        cipher.get(), plaintext.size(), encrypted.data() + header.size(), nonce_size,
        encrypted.data(), prefix_size, encrypted.data() + encrypted.size() - tag_size,
        tag_size, encrypted.data() + prefix_size, plaintext.data());
    if (status != 0) {
        crypto::wipe(plaintext.data(), plaintext.size());
        if (status == MBEDTLS_ERR_GCM_AUTH_FAILED) {
            throw Error(ErrorCode::authentication, "Session authentication failed: wrong key or modified data");
        }
        throw Error(ErrorCode::internal, "Session decryption failed");
    }
    return plaintext;
}
} // namespace apple_auth
