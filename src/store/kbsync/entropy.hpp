#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace apple_auth::detail::kbsync {

template <std::size_t Size> struct NonzeroSample {
    static_assert(Size > 0);
    std::array<std::uint8_t, Size> bytes{};
    std::size_t consumed = 0;
};

template <std::size_t Size>
inline std::optional<NonzeroSample<Size>> sample_nonzero(std::span<const std::uint8_t> entropy) {
    NonzeroSample<Size> result{};
    std::size_t filled = 0;
    for (const auto byte : entropy) {
        ++result.consumed;
        if (byte == 0) {
            continue;
        }
        result.bytes[filled++] = byte;
        if (filled == result.bytes.size()) {
            return result;
        }
    }
    return std::nullopt;
}

} // namespace apple_auth::detail::kbsync
