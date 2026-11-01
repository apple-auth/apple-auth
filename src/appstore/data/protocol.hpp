#pragma once
#include "data_mask.hpp"
#include <array>
#include <cstdint>

namespace apple_auth::appstoredetail {
inline const auto serial_prefix = detail::data_mask::decode(
    std::array<std::uint8_t, 5>{0x5F, 0xB0, 0x0D, 0x3F, 0xF0}, 0x1FC166E5U);
} // namespace apple_auth::appstoredetail
