#pragma once
#include "data_mask.hpp"
#include <array>
#include <cstdint>

namespace apple_auth::detail::sap {
inline const auto certificate_marker = data_mask::decode(
    std::array<std::uint8_t, 10>{0xB2, 0xB2, 0x92, 0xDE, 0x16, 0x46, 0x68, 0xEF, 0xF1, 0xA5},
    0x66D36789U);
} // namespace apple_auth::detail::sap
