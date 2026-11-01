#pragma once
#include "adi/internal.hpp"
#include "data_mask.hpp"
#include <array>
#include <cstdint>

namespace apple_auth::detail::kbsync {
inline const auto mac_key_mask = data_mask::decode(AesBlock{0xA0,
                                                            0xB0,
                                                            0xCF,
                                                            0xA2,
                                                            0x17,
                                                            0x21,
                                                            0x6C,
                                                            0xBC,
                                                            0xB3,
                                                            0x05,
                                                            0x6A,
                                                            0x85,
                                                            0x89,
                                                            0xBD,
                                                            0xF3,
                                                            0x55},
                                                   0x970D8CAEU);
} // namespace apple_auth::detail::kbsync

namespace apple_auth::detail::kbsync::detail {
inline const auto posthash_key = data_mask::decode(AesBlock{0x17,
                                                            0xED,
                                                            0x5D,
                                                            0x2F,
                                                            0xFC,
                                                            0xA0,
                                                            0xA3,
                                                            0xDE,
                                                            0x94,
                                                            0x86,
                                                            0x4A,
                                                            0xA3,
                                                            0xE6,
                                                            0xA4,
                                                            0x2C,
                                                            0x4D},
                                                   0x7F473DD4U);
inline const auto posthash_input_mask = data_mask::decode(AesBlock{0x1E,
                                                                   0x16,
                                                                   0x31,
                                                                   0x28,
                                                                   0x76,
                                                                   0x19,
                                                                   0x65,
                                                                   0x3D,
                                                                   0x78,
                                                                   0xC8,
                                                                   0x9E,
                                                                   0x0A,
                                                                   0xB2,
                                                                   0xC4,
                                                                   0xDD,
                                                                   0x4D},
                                                          0x91BC03F1U);
inline const auto posthash_output_mask = data_mask::decode(AesBlock{0xC7,
                                                                    0x2E,
                                                                    0x0B,
                                                                    0xEE,
                                                                    0x11,
                                                                    0x75,
                                                                    0x1D,
                                                                    0x04,
                                                                    0xF3,
                                                                    0x69,
                                                                    0x2E,
                                                                    0x9A,
                                                                    0xE4,
                                                                    0x91,
                                                                    0xC3,
                                                                    0x65},
                                                           0xBE6DB767U);
} // namespace apple_auth::detail::kbsync::detail
