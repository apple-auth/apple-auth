#include "adi/internal.hpp"
#include "crypto/backend.hpp"
#include <climits>
#include <memory>

namespace apple_auth::detail {
constexpr std::uint8_t aes_multiply(std::uint8_t left, std::uint8_t right) {
    std::uint8_t result{};
    while (right != 0) {
        if ((right & 1U) != 0) {
            result ^= left;
        }
        const bool high_bit = (left & 0x80U) != 0;
        left = static_cast<std::uint8_t>(left << 1);
        if (high_bit) {
            left ^= 0x1BU;
        }
        right >>= 1;
    }
    return result;
}

constexpr std::uint8_t invert_aes_field_byte(std::uint8_t value) {
    std::uint8_t inverse = value == 0 ? 0 : 1;
    std::uint8_t power = value;
    for (unsigned int exponent = 254; exponent != 0; exponent >>= 1) {
        if ((exponent & 1U) != 0) {
            inverse = aes_multiply(inverse, power);
        }
        power = aes_multiply(power, power);
    }
    return inverse;
}

constexpr std::uint8_t aes_substitute(std::uint8_t value) {
    const auto inverse = invert_aes_field_byte(value);
    std::uint8_t result = inverse ^ 0x63U;
    for (unsigned int rotation = 1; rotation < 5; ++rotation) {
        result ^= static_cast<std::uint8_t>((inverse << rotation) | (inverse >> (8 - rotation)));
    }
    return result;
}

constexpr auto aes_sbox = [] {
    std::array<std::uint8_t, 256> result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = aes_substitute(static_cast<std::uint8_t>(index));
    }
    return result;
}();

Aes128Schedule expand_aes128_key(std::span<const std::uint8_t, 16> key) {
    Aes128Schedule schedule{};
    for (std::size_t index = 0; index < key.size(); ++index) {
        schedule[0][index] = key[index];
    }
    std::uint8_t round_constant = 1;
    for (std::size_t round = 1; round < schedule.size(); ++round) {
        const auto& previous = schedule[round - 1];
        const std::array<std::uint8_t, 4> transformed = {
            static_cast<std::uint8_t>(aes_sbox[previous[13]] ^ round_constant),
            aes_sbox[previous[14]],
            aes_sbox[previous[15]],
            aes_sbox[previous[12]]};
        for (std::size_t index = 0; index < 16; ++index) {
            const auto word = index < 4 ? transformed[index] : schedule[round][index - 4];
            schedule[round][index] = previous[index] ^ word;
        }
        round_constant = aes_multiply(round_constant, 2);
    }
    return schedule;
}

void aes_add_round_key(AesBlock& state, const AesBlock& key) {
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] ^= key[index];
    }
}

AesBlock recover_aes128_key(AesBlock current) {
    constexpr std::array<std::uint8_t, 10> round_constants = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    for (std::size_t round = round_constants.size(); round != 0; --round) {
        AesBlock previous{};
        for (std::size_t byte = 4; byte < previous.size(); ++byte) {
            previous[byte] = current[byte] ^ current[byte - 4];
        }
        const std::array<std::uint8_t, 4> transformed = {
            static_cast<std::uint8_t>(aes_sbox[previous[13]] ^ round_constants[round - 1]),
            aes_sbox[previous[14]],
            aes_sbox[previous[15]],
            aes_sbox[previous[12]]};
        for (std::size_t byte = 0; byte < transformed.size(); ++byte) {
            previous[byte] = current[byte] ^ transformed[byte];
        }
        current = previous;
    }
    return current;
}

namespace {
template <std::size_t Size>
std::array<std::uint8_t, Size> hash(ByteView input, mbedtls_md_type_t algorithm) {
    const auto value = crypto::digest(algorithm, input);
    std::array<std::uint8_t, Size> output{};
    std::copy_n(value.begin(), Size, output.begin());
    return output;
}

AesBlock aes_block(AesBlock input, const Aes128Schedule& schedule, bool encrypt) {
    crypto::Context<mbedtls_cipher_context_t, mbedtls_cipher_init, mbedtls_cipher_free> context;
    crypto::check(mbedtls_cipher_setup(context.get(),
                                       mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB)),
                  "AES initialization failed");
    crypto::check(
        mbedtls_cipher_setkey(
            context.get(), schedule[0].data(), 128, encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT),
        "AES key setup failed");
    AesBlock output{};
    std::size_t written = 0;
    crypto::check(
        mbedtls_cipher_crypt(
            context.get(), nullptr, 0, input.data(), input.size(), output.data(), &written),
        "AES block operation failed");
    if (written != output.size()) {
        throw Error(ErrorCode::internal, "Invalid AES output size");
    }
    return output;
}
} // namespace

Sha1Digest sha1(std::span<const std::uint8_t> input) {
    return hash<20>(input, MBEDTLS_MD_SHA1);
}

Sha256Digest sha256(std::span<const std::uint8_t> input) {
    return hash<32>(input, MBEDTLS_MD_SHA256);
}

Md5Digest md5(std::span<const std::uint8_t> input) {
    return hash<16>(input, MBEDTLS_MD_MD5);
}

AesBlock encrypt_aes128_block(AesBlock input, const Aes128Schedule& schedule) {
    return aes_block(input, schedule, true);
}

AesBlock decrypt_aes128_block(AesBlock input, const Aes128Schedule& schedule) {
    return aes_block(input, schedule, false);
}

} // namespace apple_auth::detail
