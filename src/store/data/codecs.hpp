#pragma once
#include "adi/internal.hpp"
#include "data_mask.hpp"
#include <array>
#include <cstdint>

namespace apple_auth::detail::kbsync {
inline const auto input_mask = data_mask::decode(std::array<std::uint8_t, 16>{0xA4,
                                                                              0xD3,
                                                                              0x13,
                                                                              0x75,
                                                                              0x68,
                                                                              0x2C,
                                                                              0x0D,
                                                                              0x0F,
                                                                              0x71,
                                                                              0xB6,
                                                                              0x96,
                                                                              0x25,
                                                                              0x65,
                                                                              0x28,
                                                                              0x50,
                                                                              0xA0},
                                                 0x21AF49B7U);
inline const auto output_mask = data_mask::decode(std::array<std::uint8_t, 16>{0xD9,
                                                                               0x2F,
                                                                               0x8C,
                                                                               0x9A,
                                                                               0x28,
                                                                               0xAB,
                                                                               0x98,
                                                                               0xF1,
                                                                               0x2B,
                                                                               0x3A,
                                                                               0x47,
                                                                               0xCC,
                                                                               0xC3,
                                                                               0x06,
                                                                               0xEE,
                                                                               0xD6},
                                                  0xCAA64602U);
} // namespace apple_auth::detail::kbsync
