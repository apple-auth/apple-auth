#pragma once

#include "crypto/backend.hpp"
#include <climits>

namespace apple_auth::crypto {

inline void require(bool valid, const std::string& message) {
    if (!valid) {
        throw Error(ErrorCode::invalid_data, message);
    }
}

inline Bytes bytes(const std::string& value) { return {value.begin(), value.end()}; }

inline Bytes random_bytes(std::size_t size) {
    require(size <= INT_MAX, "Random buffer exceeds limit");
    Bytes output(size);
    crypto::random(output);
    return output;
}

inline Bytes unhex(const std::string& s) {
    require(s.size() % 2 == 0, "Invalid hexadecimal length");
    Bytes out;
    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    };
    for (std::size_t i = 0; i < s.size(); i += 2) {
        int a = digit(s[i]), b = digit(s[i + 1]);
        require(a >= 0 && b >= 0, "Invalid hexadecimal data");
        out.push_back(std::uint8_t(a * 16 + b));
    }
    return out;
}

inline std::string hex(ByteView v) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (auto c : v) {
        out += digits[c >> 4];
        out += digits[c & 15];
    }
    return out;
}


inline Bytes digest(const std::string& name, ByteView input) {
    const auto* info = mbedtls_md_info_from_string(name.c_str());
    require(info != nullptr, "Unknown digest");
    return crypto::digest(mbedtls_md_get_type(info), input);
}

inline Bytes hmac_sha256(ByteView key, ByteView input) {
    Bytes output(32);
    crypto::check(mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                                  key.data(),
                                  key.size(),
                                  input.data(),
                                  input.size(),
                                  output.data()),
                  "HMAC failed");
    return output;
}

inline Bytes aes_cbc(ByteView input, ByteView key, ByteView iv, bool decrypt, bool padding) {
    require((key.size() == 16 || key.size() == 32) && iv.size() == 16 && input.size() <= INT_MAX,
            "Invalid AES dimensions");
    const auto type = key.size() == 16 ? MBEDTLS_CIPHER_AES_128_CBC : MBEDTLS_CIPHER_AES_256_CBC;
    crypto::Context<mbedtls_cipher_context_t, mbedtls_cipher_init, mbedtls_cipher_free> context;
    crypto::check(mbedtls_cipher_setup(context.get(), mbedtls_cipher_info_from_type(type)),
                  "AES initialization failed");
    crypto::check(mbedtls_cipher_setkey(context.get(),
                                        key.data(),
                                        static_cast<int>(key.size() * 8),
                                        decrypt ? MBEDTLS_DECRYPT : MBEDTLS_ENCRYPT),
                  "AES key setup failed");
    crypto::check(mbedtls_cipher_set_padding_mode(
                      context.get(), padding ? MBEDTLS_PADDING_PKCS7 : MBEDTLS_PADDING_NONE),
                  "AES padding setup failed");
    Bytes output(input.size() + 16);
    std::size_t written = 0;
    require(mbedtls_cipher_crypt(context.get(),
                                 iv.data(),
                                 iv.size(),
                                 input.data(),
                                 input.size(),
                                 output.data(),
                                 &written) == 0,
            "AES decryption or padding failed");
    output.resize(written);
    return output;
}

inline Bytes password_key(const std::string& password, ByteView salt, int iterations, bool hex_password) {
    require(password.size() <= 4096 && !salt.empty() && salt.size() <= 1024 && iterations > 0 &&
                iterations <= 1000000,
            "Invalid password derivation input");
    auto hashed = digest("SHA256", bytes(password));

    struct Cleanup {
        Bytes& value;

        ~Cleanup() {
            crypto::wipe(value.data(), value.size());
        }
    } cleanup{hashed};

    if (hex_password) {
        auto encoded = bytes(hex(hashed));
        crypto::wipe(hashed.data(), hashed.size());
        hashed = std::move(encoded);
    }
    crypto::Context<mbedtls_md_context_t, mbedtls_md_init, mbedtls_md_free> context;
    crypto::check(mbedtls_md_setup(context.get(), mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1),
                  "Password derivation initialization failed");
    Bytes output(32);
    crypto::check(mbedtls_pkcs5_pbkdf2_hmac(context.get(),
                                            hashed.data(),
                                            hashed.size(),
                                            salt.data(),
                                            salt.size(),
                                            static_cast<unsigned>(iterations),
                                            static_cast<std::uint32_t>(output.size()),
                                            output.data()),
                  "Password derivation failed");
    return output;
}

} // namespace apple_auth::crypto
