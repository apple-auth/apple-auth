#pragma once
#include "adi/internal.hpp"
#include "data_mask.hpp"
#include "store/data/codecs.hpp"

namespace apple_auth::detail::kbsync {

inline const auto packet_iv = data_mask::decode(AesBlock{0x61,
                                                         0x18,
                                                         0x5E,
                                                         0xF8,
                                                         0x4C,
                                                         0x1A,
                                                         0x88,
                                                         0x7E,
                                                         0x1F,
                                                         0x81,
                                                         0xD7,
                                                         0x5A,
                                                         0x93,
                                                         0x02,
                                                         0x71,
                                                         0xBF},
                                                0xD2A9BA42U);

inline const auto packet_input_whitening = [] {
    AesBlock mask{};
    for (std::size_t index = 0; index < mask.size(); ++index) {
        mask[index] = input_mask[index] ^ 0xedu;
    }
    return mask;
}();
inline const auto packet_output_whitening = [] {
    AesBlock mask{};
    for (std::size_t index = 0; index < mask.size(); ++index) {
        mask[index] = output_mask[index] ^ 0xedu;
    }
    return mask;
}();

} // namespace apple_auth::detail::kbsync
