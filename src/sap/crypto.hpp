#pragma once
#include "adi/internal.hpp"
#include "sap/data/aes.hpp"

namespace apple_auth::detail::sap {
constexpr std::uint8_t multiply(std::uint8_t a, std::uint8_t b) {
    std::uint8_t result = 0;
    while (b) {
        if (b & 1) {
            result ^= a;
        }
        a = static_cast<std::uint8_t>((a << 1) ^ ((a & 128) ? 0x1b : 0));
        b >>= 1;
    }
    return result;
}

inline void aes_mix_columns(AesBlock& block) {
    for (unsigned i = 0; i < 16; i += 4) {
        const std::array<std::uint8_t, 4> c{block[i], block[i + 1], block[i + 2], block[i + 3]};
        for (unsigned row = 0; row < 4; ++row) {
            block[i + row] = multiply(c[row], 2) ^ multiply(c[(row + 1) % 4], 3) ^
                             c[(row + 2) % 4] ^ c[(row + 3) % 4];
        }
    }
}
} // namespace apple_auth::detail::sap
