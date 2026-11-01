#pragma once
#include "data_mask.hpp"
#include <array>
#include <cstdint>

namespace apple_auth::detail::kbsync {

inline const auto fixed_record_offsets =
    data_mask::decode(std::array<std::uint32_t, 14>{0x670419E7U,
                                                    0x63397417U,
                                                    0xFAECEA8EU,
                                                    0x902FB2CCU,
                                                    0xA8F43D32U,
                                                    0xC54DBB56U,
                                                    0x36AC09FDU,
                                                    0x456D90DDU,
                                                    0x191262E8U,
                                                    0xFD328DA0U,
                                                    0x3DEC4AB2U,
                                                    0x221F4210U,
                                                    0x83E9D1F2U,
                                                    0x812EFFB9U},
                      0x6A234813U);
inline const auto fixed_record_words = data_mask::decode(std::array<std::uint32_t, 14>{0x29C3D54DU,
                                                                                       0xFD09836CU,
                                                                                       0x61E8DE1FU,
                                                                                       0x3F4F426BU,
                                                                                       0x374B74ABU,
                                                                                       0x621D1091U,
                                                                                       0xD8702855U,
                                                                                       0x1D0F3340U,
                                                                                       0x46F4A5C6U,
                                                                                       0xA033B5F2U,
                                                                                       0xD88F24DAU,
                                                                                       0x9F1BA3DEU,
                                                                                       0xCF44C428U,
                                                                                       0x5AF1C706U},
                                                         0xC0FA6F66U);
inline const auto padded_record_offsets = data_mask::decode(
    std::array<std::uint32_t, 7>{
        0xEAC8E6FDU, 0x3487208FU, 0xC2D314ADU, 0xA827B088U, 0x9940206CU, 0x35325902U, 0xBDA968F8U},
    0x42B07C7FU);
inline const auto padded_record_values = data_mask::decode(
    std::array<std::uint32_t, 7>{
        0x3684C95BU, 0x5A48EFCBU, 0xB1800E66U, 0xB908D896U, 0xE1575ADBU, 0x4B8FE458U, 0x5783C41AU},
    0x4B7DA9DEU);

} // namespace apple_auth::detail::kbsync

namespace apple_auth::detail::kbsync {
inline const auto record_word_offsets = data_mask::decode(
    std::array<std::uint32_t, 22>{0x3064FBA1U, 0x4D118985U, 0xF822E431U, 0x3007DB9FU, 0xA5BD98A0U,
                                  0xC3C96FD9U, 0x281623E4U, 0x6147CC4CU, 0x818E212DU, 0xF04F7815U,
                                  0xF65A64D5U, 0xE26E6A8BU, 0xC812F9E3U, 0x736050FEU, 0x572F69E2U,
                                  0xF9CC04B1U, 0x53DB7510U, 0x93BB11CFU, 0xC02C2755U, 0xDE0212FAU,
                                  0x15FE17D0U, 0x35BAE61EU},
    0xAFDE6A4EU);
} // namespace apple_auth::detail::kbsync
