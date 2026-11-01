#pragma once
#include "data_mask.hpp"
#include <array>
#include <cstdint>

namespace apple_auth::detail::sap {
struct KeyStreamState {
    std::uint32_t first;
    std::uint32_t second;
    std::uint32_t third;
    std::uint32_t fourth;
};

inline const auto initial_key_stream_state =
    data_mask::decode(KeyStreamState{0x510DBE2CU, 0x855F5DC5U, 0x49FCAECAU, 0x1F5C6486U},
                      0x567B82FFU,
                      [](auto& stream, auto& value) {
                          stream.apply(value.first);
                          stream.apply(value.second);
                          stream.apply(value.third);
                          stream.apply(value.fourth);
                      });

inline const auto key_material_mask = data_mask::decode(std::array<std::uint8_t, 16>{0x8B,
                                                                                     0x6E,
                                                                                     0xEF,
                                                                                     0x25,
                                                                                     0xC8,
                                                                                     0xA7,
                                                                                     0xED,
                                                                                     0xDF,
                                                                                     0x66,
                                                                                     0x80,
                                                                                     0xB9,
                                                                                     0xD4,
                                                                                     0xB6,
                                                                                     0x19,
                                                                                     0x39,
                                                                                     0x31},
                                                        0x29820AAFU);

inline const auto key_stream_coefficients = data_mask::decode(
    std::array<std::uint32_t, 4>{0x14545646U, 0x26E2A97BU, 0x04761370U, 0x1708B75BU}, 0xEA20AF5CU);
} // namespace apple_auth::detail::sap
