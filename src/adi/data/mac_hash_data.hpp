#pragma once

#include "data_mask.hpp"
#include <array>
#include <cstdint>

namespace apple_auth::detail::mac_hash_data {

// Mac hash IV and round constants.
inline const auto initial_state = data_mask::decode(
    std::array<std::uint32_t, 8>{
        0x05426513U,
        0xA49C8066U,
        0x989B5FC2U,
        0xF89D4DB0U,
        0x17B8FF77U,
        0xB288E623U,
        0xA5E3EDCFU,
        0xEE62FFEAU,
    },
    0x419D7AD1U);

inline const auto round_constants = data_mask::decode(
    std::array<std::uint32_t, 64>{
        0x3950428BU, 0xB602EEC8U, 0xD92A39BDU, 0xC11E7E73U, 0x1534B36EU, 0x367911E5U, 0xBEA8AE55U,
        0x69925D7EU, 0x7D8E9D97U, 0x1E1F8D4CU, 0x88C90232U, 0x5A6A158BU, 0x187C47B8U, 0x1AC0CE88U,
        0xE2D54C2CU, 0x6BA33B24U, 0x94C93410U, 0x247CA7EBU, 0x3629290EU, 0x7ED98E5CU, 0x6C7F140DU,
        0x494C1A9BU, 0x0DE6FAC2U, 0xA2B24CF3U, 0xA48BD534U, 0xCE28CCB0U, 0xB796B776U, 0x3E9CB24AU,
        0x6377F500U, 0x786D67D9U, 0xC070180AU, 0xA303F645U, 0x1D27C921U, 0x51BE6DF3U, 0x80ECA465U,
        0xFD9E0C14U, 0xEDEF696EU, 0x4D317E11U, 0xAE8DB6D0U, 0xA6B8FF16U, 0x79674AC3U, 0xF7328747U,
        0x08FA6114U, 0x25CF623CU, 0xE5E6EC29U, 0x43EB7716U, 0xFED9C0ACU, 0xF54136B1U, 0x68F9D7D4U,
        0x313DECB1U, 0xBCB51932U, 0xFF87A3D9U, 0xCBFF4667U, 0x1EAF23DDU, 0xDFFC10E6U, 0xDCF8A072U,
        0xF71E82B4U, 0xAFDA9C0EU, 0xC73EA67CU, 0x237AD02BU, 0x384B4E74U, 0x00477785U, 0x823D3244U,
        0x4DAAADFAU,
    },
    0x455AE9ACU);

} // namespace apple_auth::detail::mac_hash_data
